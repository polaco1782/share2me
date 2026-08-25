use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ops::Deref,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use str0m::{
    Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcError,
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::{ChannelData, ChannelId},
    crypto::CryptoProvider,
    media::{Direction, KeyframeRequest, KeyframeRequestKind, MediaData, MediaKind, Mid, Rid},
    net::{Protocol, Receive},
};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

const COMMAND_QUEUE: usize = 64;
const MAX_FORWARD_CLIENTS: usize = 256;
const MAX_TRACKS_PER_PUBLISHER: usize = 2;
const IO_BUFFER_BYTES: usize = 2048;
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);
const CLIENT_CLOSE_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaRole {
    Publisher,
    Viewer,
}

#[derive(Clone, Debug)]
pub enum ForwardEvent {
    Disconnected {
        session_id: String,
        role: MediaRole,
        connection_id: u128,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ForwardJoinError {
    #[error("media forwarding is busy")]
    Busy,
    #[error("media forwarding is unavailable")]
    Unavailable,
    #[error("invalid WebRTC offer: {0}")]
    InvalidOffer(String),
    #[error("timed out creating the forwarded media connection")]
    Timeout,
}

#[derive(Clone, Debug)]
pub struct MediaForwarder {
    commands: SyncSender<Command>,
}

#[derive(Debug)]
pub struct MediaRuntime {
    commands: SyncSender<Command>,
    thread: Option<thread::JoinHandle<()>>,
}

enum Command {
    Join {
        session_id: String,
        role: MediaRole,
        connection_id: u128,
        offer: SdpOffer,
        response: oneshot::Sender<Result<SdpAnswer, ForwardJoinError>>,
    },
    Stop {
        session_id: String,
        response: oneshot::Sender<()>,
    },
    Shutdown,
}

pub fn start(
    advertised_address: SocketAddr,
) -> Result<(
    MediaForwarder,
    MediaRuntime,
    tokio_mpsc::UnboundedReceiver<ForwardEvent>,
)> {
    let bind_address = match advertised_address.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, advertised_address.port())),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, advertised_address.port())),
    };
    let socket = UdpSocket::bind(bind_address)
        .with_context(|| format!("binding forwarded media UDP port {bind_address}"))?;
    let candidate = Candidate::host(advertised_address, "udp")
        .map_err(|error| anyhow!("invalid forwarded media address: {error}"))?;
    let crypto = Arc::new(str0m::crypto::from_feature_flags());
    let (command_tx, command_rx) = mpsc::sync_channel(COMMAND_QUEUE);
    let (event_tx, event_rx) = tokio_mpsc::unbounded_channel();
    let thread = thread::Builder::new()
        .name("share2me-media".to_owned())
        .spawn(move || {
            if let Err(error) = run(
                &socket,
                advertised_address,
                &candidate,
                &crypto,
                &command_rx,
                &event_tx,
            ) {
                tracing::error!(%error, "forwarded media runtime stopped");
            }
        })
        .context("starting forwarded media runtime")?;
    let forwarder = MediaForwarder {
        commands: command_tx.clone(),
    };
    let runtime = MediaRuntime {
        commands: command_tx,
        thread: Some(thread),
    };
    Ok((forwarder, runtime, event_rx))
}

impl MediaForwarder {
    pub async fn join(
        &self,
        session_id: String,
        role: MediaRole,
        connection_id: u128,
        offer: SdpOffer,
    ) -> Result<SdpAnswer, ForwardJoinError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.commands
            .try_send(Command::Join {
                session_id,
                role,
                connection_id,
                offer,
                response: response_tx,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => ForwardJoinError::Busy,
                TrySendError::Disconnected(_) => ForwardJoinError::Unavailable,
            })?;
        tokio::time::timeout(Duration::from_secs(5), response_rx)
            .await
            .map_err(|_| ForwardJoinError::Timeout)?
            .map_err(|_| ForwardJoinError::Unavailable)?
    }

    pub async fn stop(&self, session_id: String) -> Result<(), ForwardJoinError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.commands
            .try_send(Command::Stop {
                session_id,
                response: response_tx,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => ForwardJoinError::Busy,
                TrySendError::Disconnected(_) => ForwardJoinError::Unavailable,
            })?;
        tokio::time::timeout(Duration::from_secs(5), response_rx)
            .await
            .map_err(|_| ForwardJoinError::Timeout)?
            .map_err(|_| ForwardJoinError::Unavailable)
    }
}

impl MediaRuntime {
    pub async fn shutdown(mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let commands = self.commands.clone();
        match tokio::task::spawn_blocking(move || {
            let _ = commands.send(Command::Shutdown);
            thread.join()
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => tracing::warn!("forwarded media runtime panicked"),
            Err(error) => tracing::warn!(%error, "failed to join forwarded media runtime"),
        }
    }
}

impl Drop for MediaRuntime {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Shutdown);
    }
}

fn run(
    socket: &UdpSocket,
    advertised_address: SocketAddr,
    candidate: &Candidate,
    crypto: &Arc<CryptoProvider>,
    commands: &Receiver<Command>,
    events: &tokio_mpsc::UnboundedSender<ForwardEvent>,
) -> Result<(), RtcError> {
    let mut clients = Vec::new();
    let mut propagated = VecDeque::new();
    let mut buffer = vec![0; IO_BUFFER_BYTES];

    loop {
        match drain_commands(commands, &mut clients, candidate, crypto, events) {
            CommandState::Running => {}
            CommandState::Shutdown => return Ok(()),
        }
        report_disconnected(&mut clients, events);
        clients.retain(|client| client.rtc.is_alive());

        let mut timeout = Instant::now() + COMMAND_POLL_INTERVAL;
        for client in &mut clients {
            timeout = timeout.min(poll_until_timeout(client, &mut propagated, socket));
        }
        if let Some(event) = propagated.pop_front() {
            propagate(event, &mut clients, events);
            continue;
        }

        let duration = timeout
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        socket.set_read_timeout(Some(duration))?;
        if let Some(input) = read_socket_input(socket, advertised_address, &mut buffer)?
            && let Some(client) = clients.iter_mut().find(|client| client.rtc.accepts(&input))
        {
            client.handle_input(input);
        }
        let now = Instant::now();
        for client in &mut clients {
            if client
                .disconnect_after
                .is_some_and(|deadline| now >= deadline)
            {
                client.rtc.disconnect();
            } else {
                client.handle_input(Input::Timeout(now));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandState {
    Running,
    Shutdown,
}

fn drain_commands(
    commands: &Receiver<Command>,
    clients: &mut Vec<Client>,
    candidate: &Candidate,
    crypto: &Arc<CryptoProvider>,
    events: &tokio_mpsc::UnboundedSender<ForwardEvent>,
) -> CommandState {
    loop {
        match commands.try_recv() {
            Ok(Command::Join {
                session_id,
                role,
                connection_id,
                offer,
                response,
            }) => {
                let result = add_client(
                    clients,
                    &session_id,
                    role,
                    connection_id,
                    offer,
                    candidate,
                    crypto,
                );
                let _ = response.send(result);
            }
            Ok(Command::Stop {
                session_id,
                response,
            }) => {
                if let Some((publisher, connection_id)) = clients
                    .iter()
                    .find(|client| {
                        client.session_id == session_id && client.role == MediaRole::Publisher
                    })
                    .map(|client| (client.id, client.connection_id))
                {
                    end_session(&session_id, publisher, connection_id, clients, events);
                }
                let _ = response.send(());
            }
            Ok(Command::Shutdown) | Err(TryRecvError::Disconnected) => {
                return CommandState::Shutdown;
            }
            Err(TryRecvError::Empty) => return CommandState::Running,
        }
    }
}

fn add_client(
    clients: &mut Vec<Client>,
    session_id: &str,
    role: MediaRole,
    connection_id: u128,
    offer: SdpOffer,
    candidate: &Candidate,
    crypto: &Arc<CryptoProvider>,
) -> Result<SdpAnswer, ForwardJoinError> {
    if clients.len() >= MAX_FORWARD_CLIENTS {
        return Err(ForwardJoinError::Busy);
    }
    if role == MediaRole::Publisher
        && clients
            .iter()
            .any(|client| client.session_id == session_id && client.role == MediaRole::Publisher)
    {
        return Err(ForwardJoinError::Unavailable);
    }
    if role == MediaRole::Viewer
        && !clients
            .iter()
            .any(|client| client.session_id == session_id && client.role == MediaRole::Publisher)
    {
        return Err(ForwardJoinError::Unavailable);
    }

    let mut rtc = Rtc::builder()
        .set_crypto_provider(crypto.clone())
        .set_ice_lite(true)
        .build(Instant::now());
    rtc.add_local_candidate(candidate.clone()).ok_or_else(|| {
        ForwardJoinError::InvalidOffer("forwarded media candidate was rejected".to_owned())
    })?;
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .map_err(|error| ForwardJoinError::InvalidOffer(error.to_string()))?;
    let mut client = Client::new(session_id.to_owned(), role, connection_id, rtc);
    if role == MediaRole::Viewer {
        for track in clients
            .iter()
            .filter(|client| client.session_id == session_id && client.role == MediaRole::Publisher)
            .flat_map(|client| &client.tracks_in)
        {
            client.handle_track_open(Arc::downgrade(&track.id));
        }
    }
    clients.push(client);
    Ok(answer)
}

fn report_disconnected(clients: &mut [Client], events: &tokio_mpsc::UnboundedSender<ForwardEvent>) {
    let ended_publishers = clients
        .iter()
        .filter(|client| {
            !client.rtc.is_alive()
                && !client.disconnect_reported
                && client.role == MediaRole::Publisher
        })
        .map(|client| (client.session_id.clone(), client.id, client.connection_id))
        .collect::<Vec<_>>();
    for (session_id, publisher_id, connection_id) in ended_publishers {
        end_session(&session_id, publisher_id, connection_id, clients, events);
    }
    for client in clients.iter_mut().filter(|client| {
        !client.rtc.is_alive() && !client.disconnect_reported && client.role == MediaRole::Viewer
    }) {
        client.disconnect_reported = true;
        let _ = events.send(ForwardEvent::Disconnected {
            session_id: client.session_id.clone(),
            role: client.role,
            connection_id: client.connection_id,
        });
    }
}

fn poll_until_timeout(
    client: &mut Client,
    queue: &mut VecDeque<Propagated>,
    socket: &UdpSocket,
) -> Instant {
    loop {
        if !client.rtc.is_alive() {
            return Instant::now() + COMMAND_POLL_INTERVAL;
        }
        let output = client.poll_output(socket);
        if let Propagated::Timeout(timeout) = output {
            return timeout;
        }
        queue.push_back(output);
    }
}

fn propagate(
    propagated: Propagated,
    clients: &mut [Client],
    events: &tokio_mpsc::UnboundedSender<ForwardEvent>,
) {
    match propagated {
        Propagated::TrackOpen {
            session_id,
            origin,
            track,
        } => {
            for client in clients.iter_mut().filter(|client| {
                client.session_id == session_id
                    && client.id != origin
                    && client.role == MediaRole::Viewer
            }) {
                client.handle_track_open(track.clone());
            }
        }
        Propagated::MediaData {
            session_id,
            origin,
            data,
        } => {
            for client in clients.iter_mut().filter(|client| {
                client.session_id == session_id
                    && client.id != origin
                    && client.role == MediaRole::Viewer
            }) {
                client.handle_media_data_out(origin, &data);
            }
        }
        Propagated::KeyframeRequest {
            session_id,
            request,
            publisher,
            mid,
        } => {
            if let Some(client) = clients
                .iter_mut()
                .find(|client| client.session_id == session_id && client.id == publisher)
            {
                client.handle_keyframe_request(request, mid);
            }
        }
        Propagated::SessionEnded {
            session_id,
            publisher,
            connection_id,
        } => end_session(&session_id, publisher, connection_id, clients, events),
        Propagated::Noop | Propagated::Timeout(_) => {}
    }
}

fn end_session(
    session_id: &str,
    publisher: ClientId,
    connection_id: u128,
    clients: &mut [Client],
    events: &tokio_mpsc::UnboundedSender<ForwardEvent>,
) {
    for client in clients
        .iter_mut()
        .filter(|client| client.session_id == session_id)
    {
        if client.id == publisher {
            client.disconnect_reported = true;
            client.rtc.disconnect();
        } else if client.role == MediaRole::Viewer {
            client.send_control("ended");
            client.disconnect_after = Some(Instant::now() + CLIENT_CLOSE_DELAY);
        }
    }
    let _ = events.send(ForwardEvent::Disconnected {
        session_id: session_id.to_owned(),
        role: MediaRole::Publisher,
        connection_id,
    });
}

fn read_socket_input<'a>(
    socket: &UdpSocket,
    advertised_address: SocketAddr,
    buffer: &'a mut Vec<u8>,
) -> Result<Option<Input<'a>>, RtcError> {
    buffer.resize(IO_BUFFER_BYTES, 0);
    match socket.recv_from(buffer) {
        Ok((length, source)) => {
            buffer.truncate(length);
            let Ok(contents) = buffer.as_slice().try_into() else {
                return Ok(None);
            };
            Ok(Some(Input::Receive(
                Instant::now(),
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: advertised_address,
                    contents,
                },
            )))
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientId(u64);

impl Deref for ClientId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
struct TrackIn {
    origin: ClientId,
    mid: Mid,
    kind: MediaKind,
}

#[derive(Debug)]
struct TrackInEntry {
    id: Arc<TrackIn>,
    last_keyframe_request: Option<Instant>,
}

#[derive(Debug)]
struct TrackOut {
    track_in: Weak<TrackIn>,
    state: TrackOutState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackOutState {
    ToOpen,
    Negotiating(Mid),
    Open(Mid),
    ToStop(Mid),
    NegotiatingStop(Mid),
}

impl TrackOut {
    fn mid(&self) -> Option<Mid> {
        match self.state {
            TrackOutState::ToOpen => None,
            TrackOutState::Negotiating(mid)
            | TrackOutState::Open(mid)
            | TrackOutState::ToStop(mid)
            | TrackOutState::NegotiatingStop(mid) => Some(mid),
        }
    }
}

#[derive(Debug)]
struct Client {
    id: ClientId,
    session_id: String,
    role: MediaRole,
    connection_id: u128,
    rtc: Rtc,
    pending: Option<SdpPendingOffer>,
    channel_id: Option<ChannelId>,
    tracks_in: Vec<TrackInEntry>,
    tracks_out: Vec<TrackOut>,
    chosen_rid: Option<Rid>,
    disconnect_after: Option<Instant>,
    disconnect_reported: bool,
}

impl Client {
    fn new(session_id: String, role: MediaRole, connection_id: u128, rtc: Rtc) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: ClientId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            session_id,
            role,
            connection_id,
            rtc,
            pending: None,
            channel_id: None,
            tracks_in: Vec::new(),
            tracks_out: Vec::new(),
            chosen_rid: None,
            disconnect_after: None,
            disconnect_reported: false,
        }
    }

    fn handle_input(&mut self, input: Input<'_>) {
        if let Err(error) = self.rtc.handle_input(input) {
            tracing::warn!(client = *self.id, %error, "forwarded media client input failed");
            self.rtc.disconnect();
        }
    }

    fn poll_output(&mut self, socket: &UdpSocket) -> Propagated {
        if self.negotiate_if_needed() {
            return Propagated::Noop;
        }
        match self.rtc.poll_output() {
            Ok(output) => self.handle_output(output, socket),
            Err(error) => {
                tracing::warn!(client = *self.id, %error, "forwarded media client failed");
                self.rtc.disconnect();
                Propagated::Noop
            }
        }
    }

    fn handle_output(&mut self, output: Output, socket: &UdpSocket) -> Propagated {
        match output {
            Output::Transmit(transmit) => {
                if let Err(error) = socket.send_to(&transmit.contents, transmit.destination) {
                    tracing::warn!(client = *self.id, %error, "forwarded media send failed");
                    self.rtc.disconnect();
                }
                Propagated::Noop
            }
            Output::Timeout(timeout) => Propagated::Timeout(timeout),
            Output::Event(event) => match event {
                Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                    self.rtc.disconnect();
                    Propagated::Noop
                }
                Event::MediaAdded(media) => {
                    if self.role != MediaRole::Publisher
                        || !media.direction.is_receiving()
                        || self.tracks_in.len() >= MAX_TRACKS_PER_PUBLISHER
                    {
                        self.rtc.disconnect();
                        Propagated::Noop
                    } else {
                        self.handle_media_added(media.mid, media.kind)
                    }
                }
                Event::MediaData(data) => self.handle_media_data_in(data),
                Event::KeyframeRequest(request) => self.handle_incoming_keyframe_request(request),
                Event::ChannelOpen(channel_id, _) => {
                    self.channel_id = Some(channel_id);
                    Propagated::Noop
                }
                Event::ChannelData(data) => self.handle_channel_data(&data),
                _ => Propagated::Noop,
            },
        }
    }

    fn handle_media_added(&mut self, mid: Mid, kind: MediaKind) -> Propagated {
        let track = TrackInEntry {
            id: Arc::new(TrackIn {
                origin: self.id,
                mid,
                kind,
            }),
            last_keyframe_request: None,
        };
        let weak = Arc::downgrade(&track.id);
        self.tracks_in.push(track);
        Propagated::TrackOpen {
            session_id: self.session_id.clone(),
            origin: self.id,
            track: weak,
        }
    }

    fn handle_media_data_in(&mut self, data: MediaData) -> Propagated {
        if self.role != MediaRole::Publisher {
            self.rtc.disconnect();
            return Propagated::Noop;
        }
        if !data.contiguous {
            self.request_keyframe_throttled(data.mid, data.rid, KeyframeRequestKind::Fir);
        }
        Propagated::MediaData {
            session_id: self.session_id.clone(),
            origin: self.id,
            data,
        }
    }

    fn request_keyframe_throttled(
        &mut self,
        mid: Mid,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) {
        let Some(track) = self.tracks_in.iter_mut().find(|track| track.id.mid == mid) else {
            return;
        };
        if track
            .last_keyframe_request
            .is_some_and(|instant| instant.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        if let Some(mut writer) = self.rtc.writer(mid) {
            let _ = writer.request_keyframe(rid, kind);
            track.last_keyframe_request = Some(Instant::now());
        }
    }

    fn handle_incoming_keyframe_request(&self, mut request: KeyframeRequest) -> Propagated {
        let Some(track) = self
            .tracks_out
            .iter()
            .find(|track| track.mid() == Some(request.mid))
            .and_then(|track| track.track_in.upgrade())
        else {
            return Propagated::Noop;
        };
        request.rid = self.chosen_rid;
        Propagated::KeyframeRequest {
            session_id: self.session_id.clone(),
            request,
            publisher: track.origin,
            mid: track.mid,
        }
    }

    fn negotiate_if_needed(&mut self) -> bool {
        if self.role != MediaRole::Viewer || self.channel_id.is_none() || self.pending.is_some() {
            return false;
        }
        for track in &mut self.tracks_out {
            if let TrackOutState::Open(mid) = track.state
                && track.track_in.upgrade().is_none()
            {
                track.state = TrackOutState::ToStop(mid);
            }
        }
        let mut changes = self.rtc.sdp_api();
        for track in &mut self.tracks_out {
            match track.state {
                TrackOutState::ToOpen => {
                    if let Some(track_in) = track.track_in.upgrade() {
                        let mid = changes.add_media(
                            track_in.kind,
                            Direction::SendOnly,
                            Some(track_in.origin.to_string()),
                            None,
                            None,
                        );
                        track.state = TrackOutState::Negotiating(mid);
                    }
                }
                TrackOutState::ToStop(mid) => {
                    changes.stop_media(mid);
                    track.state = TrackOutState::NegotiatingStop(mid);
                }
                _ => {}
            }
        }
        if !changes.has_changes() {
            return false;
        }
        let Some((offer, pending)) = changes.apply() else {
            return false;
        };
        let Ok(json) = serde_json::to_vec(&offer) else {
            self.rtc.disconnect();
            return true;
        };
        if !self.write_channel(&json) {
            self.rtc.disconnect();
            return true;
        }
        self.pending = Some(pending);
        true
    }

    fn handle_channel_data(&mut self, data: &ChannelData) -> Propagated {
        if let Ok(offer) = serde_json::from_slice::<SdpOffer>(&data.data) {
            self.handle_offer(offer);
            return Propagated::Noop;
        }
        if let Ok(answer) = serde_json::from_slice::<SdpAnswer>(&data.data) {
            self.handle_answer(answer);
            return Propagated::Noop;
        }
        if self.role == MediaRole::Publisher
            && serde_json::from_slice::<serde_json::Value>(&data.data)
                .ok()
                .and_then(|value| {
                    value
                        .get("type")
                        .and_then(|value| value.as_str())
                        .map(str::to_owned)
                })
                .as_deref()
                == Some("stop")
        {
            self.rtc.disconnect();
            return Propagated::SessionEnded {
                session_id: self.session_id.clone(),
                publisher: self.id,
                connection_id: self.connection_id,
            };
        }
        Propagated::Noop
    }

    fn handle_offer(&mut self, offer: SdpOffer) {
        match self.rtc.sdp_api().accept_offer(offer) {
            Ok(answer) => {
                for track in &mut self.tracks_out {
                    match track.state {
                        TrackOutState::Negotiating(_) => track.state = TrackOutState::ToOpen,
                        TrackOutState::NegotiatingStop(mid) => {
                            track.state = TrackOutState::ToStop(mid);
                        }
                        _ => {}
                    }
                }
                self.pending = None;
                match serde_json::to_vec(&answer) {
                    Ok(json) if self.write_channel(&json) => {}
                    _ => self.rtc.disconnect(),
                }
            }
            Err(error) => {
                tracing::warn!(client = *self.id, %error, "forwarded renegotiation failed");
                self.rtc.disconnect();
            }
        }
    }

    fn handle_answer(&mut self, answer: SdpAnswer) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if let Err(error) = self.rtc.sdp_api().accept_answer(pending, answer) {
            tracing::warn!(client = *self.id, %error, "forwarded answer was rejected");
            self.rtc.disconnect();
            return;
        }
        for track in &mut self.tracks_out {
            if let TrackOutState::Negotiating(mid) = track.state {
                track.state = TrackOutState::Open(mid);
            }
        }
        self.tracks_out
            .retain(|track| !matches!(track.state, TrackOutState::NegotiatingStop(_)));
    }

    fn handle_track_open(&mut self, track_in: Weak<TrackIn>) {
        self.tracks_out.push(TrackOut {
            track_in,
            state: TrackOutState::ToOpen,
        });
    }

    fn handle_media_data_out(&mut self, origin: ClientId, data: &MediaData) {
        let Some(mid) = self
            .tracks_out
            .iter()
            .find(|track| {
                track
                    .track_in
                    .upgrade()
                    .is_some_and(|input| input.origin == origin && input.mid == data.mid)
            })
            .and_then(TrackOut::mid)
        else {
            return;
        };
        if data.rid.is_some() && data.rid != Some("h".into()) {
            return;
        }
        self.chosen_rid = data.rid;
        let Some(writer) = self.rtc.writer(mid) else {
            return;
        };
        let Some(payload_type) = writer.match_params(data.params) else {
            return;
        };
        if let Err(error) = writer.write(
            payload_type,
            data.network_time,
            data.time,
            data.data.clone(),
        ) {
            tracing::warn!(client = *self.id, %error, "forwarding media frame failed");
            self.rtc.disconnect();
        }
    }

    fn handle_keyframe_request(&mut self, request: KeyframeRequest, input_mid: Mid) {
        if !self.tracks_in.iter().any(|track| track.id.mid == input_mid) {
            return;
        }
        if let Some(mut writer) = self.rtc.writer(input_mid) {
            let _ = writer.request_keyframe(request.rid, request.kind);
        }
    }

    fn write_channel(&mut self, data: &[u8]) -> bool {
        self.channel_id
            .and_then(|id| self.rtc.channel(id))
            .is_some_and(|mut channel| channel.write(false, data).is_ok())
    }

    fn send_control(&mut self, kind: &str) {
        if let Ok(message) = serde_json::to_vec(&serde_json::json!({"control":kind})) {
            let _ = self.write_channel(&message);
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Propagated {
    Noop,
    Timeout(Instant),
    TrackOpen {
        session_id: String,
        origin: ClientId,
        track: Weak<TrackIn>,
    },
    MediaData {
        session_id: String,
        origin: ClientId,
        data: MediaData,
    },
    KeyframeRequest {
        session_id: String,
        request: KeyframeRequest,
        publisher: ClientId,
        mid: Mid,
    },
    SessionEnded {
        session_id: String,
        publisher: ClientId,
        connection_id: u128,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(crypto: Arc<CryptoProvider>) -> SdpOffer {
        let mut rtc = Rtc::builder()
            .set_crypto_provider(crypto)
            .build(Instant::now());
        let mut changes = rtc.sdp_api();
        changes.add_channel("share2me-control".to_owned());
        changes.apply().unwrap().0
    }

    #[test]
    fn accepts_one_publisher_and_requires_it_before_viewers() {
        let crypto = Arc::new(str0m::crypto::from_feature_flags());
        let candidate = Candidate::host("127.0.0.1:7882".parse().unwrap(), "udp").unwrap();
        let mut clients = Vec::new();
        assert!(matches!(
            add_client(
                &mut clients,
                "session",
                MediaRole::Viewer,
                1,
                offer(crypto.clone()),
                &candidate,
                &crypto,
            ),
            Err(ForwardJoinError::Unavailable)
        ));
        assert!(
            add_client(
                &mut clients,
                "session",
                MediaRole::Publisher,
                2,
                offer(crypto.clone()),
                &candidate,
                &crypto,
            )
            .is_ok()
        );
        assert!(
            add_client(
                &mut clients,
                "session",
                MediaRole::Viewer,
                3,
                offer(crypto.clone()),
                &candidate,
                &crypto,
            )
            .is_ok()
        );
        assert!(matches!(
            add_client(
                &mut clients,
                "session",
                MediaRole::Publisher,
                4,
                offer(crypto.clone()),
                &candidate,
                &crypto,
            ),
            Err(ForwardJoinError::Unavailable)
        ));
    }
}
