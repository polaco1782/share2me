use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};

use crate::media::MediaRole;

const MAX_ROOMS: usize = 128;
pub const MAX_VIEWERS: usize = 8;
pub const MAX_SIGNAL_BYTES: usize = 128 * 1024;
pub const MAX_SDP_BYTES: usize = 96 * 1024;
const MAX_CANDIDATE_BYTES: usize = 8 * 1024;
const MAX_ROOM_NAME_BYTES: usize = 48;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_USERNAME_CHARS: usize = 32;
const SIGNAL_QUEUE: usize = 64;
const REACTION_INTERVAL: Duration = Duration::from_millis(350);
const REACTIONS: &[&str] = &["👍", "❤️", "😂", "😮", "👏", "🎉", "creeper"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Host,
    Viewer,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoomDeparture {
    pub host_left: bool,
    pub forward_viewer: Option<u128>,
}

#[derive(Clone, Debug, Default)]
pub struct LiveHub {
    rooms: Arc<Mutex<HashMap<String, LiveRoom>>>,
}

#[derive(Debug, Default)]
struct LiveRoom {
    host: Option<Peer>,
    viewers: HashMap<String, Peer>,
    forward_host: Option<u128>,
    forward_viewers: HashMap<String, u128>,
    stream_active: bool,
}

#[derive(Clone, Debug)]
struct Peer {
    id: String,
    connection_id: u128,
    username: String,
    media_key: String,
    sender: mpsc::Sender<Outbound>,
}

#[derive(Clone, Debug)]
enum Outbound {
    Text(String),
    Close,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientSignal {
    Offer {
        viewer: String,
        sdp: String,
    },
    Answer {
        sdp: String,
    },
    Ice {
        #[serde(default)]
        viewer: Option<String>,
        candidate: Value,
    },
    StreamState {
        active: bool,
    },
    MicrophoneState {
        enabled: bool,
    },
    Reaction {
        reaction: String,
    },
}

#[derive(Debug)]
struct RegisteredPeer {
    role: PeerRole,
    connection_id: u128,
    participant_id: String,
    username: String,
    media_key: String,
}

impl LiveHub {
    pub async fn handle_socket(
        self,
        mut socket: WebSocket,
        room_name: String,
        username: String,
    ) -> RoomDeparture {
        let (outbound_tx, mut outbound_rx) = mpsc::channel(SIGNAL_QUEUE);
        let Ok(registration) = self
            .register_peer(&room_name, username, outbound_tx.clone())
            .await
        else {
            send_socket_error(&mut socket, "Room is full or unavailable").await;
            return RoomDeparture::default();
        };

        let (mut writer, mut reader) = socket.split();
        let writer_task = tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                match message {
                    Outbound::Text(text) => {
                        if writer.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Outbound::Close => {
                        let _ = writer.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        });

        let mut last_reaction = None;
        while let Some(message) = reader.next().await {
            let Ok(Message::Text(text)) = message else {
                if matches!(message, Ok(Message::Close(_)) | Err(_)) {
                    break;
                }
                continue;
            };
            let Ok(signal) = serde_json::from_str::<ClientSignal>(&text) else {
                send_json(
                    &outbound_tx,
                    &json!({"type":"error","message":"Invalid room message"}),
                );
                continue;
            };
            self.relay(
                &room_name,
                &registration,
                signal,
                &outbound_tx,
                &mut last_reaction,
            )
            .await;
        }

        let departure = self.unregister(&room_name, &registration).await;
        writer_task.abort();
        departure
    }

    pub async fn claim_forward_peer(
        &self,
        room_name: &str,
        media_key: &str,
        connection_id: u128,
    ) -> Option<MediaRole> {
        let mut rooms = self.rooms.lock().await;
        let room = rooms.get_mut(room_name)?;
        if room.host.as_ref().is_some_and(|host| {
            secret_matches(&host.media_key, media_key) && room.forward_host.is_none()
        }) {
            room.forward_host = Some(connection_id);
            return Some(MediaRole::Publisher);
        }
        room.forward_host?;
        let participant_id = room
            .viewers
            .values()
            .find(|viewer| secret_matches(&viewer.media_key, media_key))?
            .id
            .clone();
        if room.forward_viewers.contains_key(&participant_id) {
            return None;
        }
        room.forward_viewers.insert(participant_id, connection_id);
        Some(MediaRole::Viewer)
    }

    pub async fn release_forward_peer(
        &self,
        room_name: &str,
        role: MediaRole,
        connection_id: u128,
    ) {
        let viewers = {
            let mut rooms = self.rooms.lock().await;
            let Some(room) = rooms.get_mut(room_name) else {
                return;
            };
            match role {
                MediaRole::Publisher if room.forward_host == Some(connection_id) => {
                    room.forward_host = None;
                    room.forward_viewers.clear();
                    room.stream_active = false;
                    room.viewers
                        .values()
                        .map(|viewer| viewer.sender.clone())
                        .collect::<Vec<_>>()
                }
                MediaRole::Viewer => {
                    room.forward_viewers
                        .retain(|_, current| *current != connection_id);
                    Vec::new()
                }
                MediaRole::Publisher => Vec::new(),
            }
        };
        for viewer in viewers {
            send_json(&viewer, &json!({"type":"stream_state","active":false}));
        }
    }

    pub async fn stop_forward_stream(&self, room_name: &str, media_key: &str) -> bool {
        let viewers = {
            let mut rooms = self.rooms.lock().await;
            let Some(room) = rooms.get_mut(room_name) else {
                return false;
            };
            if room.forward_host.is_none()
                || !room
                    .host
                    .as_ref()
                    .is_some_and(|host| secret_matches(&host.media_key, media_key))
            {
                return false;
            }
            room.forward_host = None;
            room.forward_viewers.clear();
            room.stream_active = false;
            room.viewers
                .values()
                .map(|viewer| viewer.sender.clone())
                .collect::<Vec<_>>()
        };
        for viewer in viewers {
            send_json(&viewer, &json!({"type":"stream_state","active":false}));
        }
        true
    }

    async fn register_peer(
        &self,
        room_name: &str,
        username: String,
        sender: mpsc::Sender<Outbound>,
    ) -> Result<RegisteredPeer, ()> {
        let connection_id = rand::random::<u128>();
        let (role, participant_id, media_key, stream_active, participants, recipients, host_sender) = {
            let mut rooms = self.rooms.lock().await;
            if !rooms.contains_key(room_name) && rooms.len() >= MAX_ROOMS {
                return Err(());
            }
            let room = rooms.entry(room_name.to_owned()).or_default();
            let participant_id = unique_participant_id(room).ok_or(())?;
            let media_key = random_secret();
            let peer = Peer {
                id: participant_id.clone(),
                connection_id,
                username: username.clone(),
                media_key: media_key.clone(),
                sender: sender.clone(),
            };
            let (role, host_sender) = if room.host.is_none() {
                room.host = Some(peer);
                (PeerRole::Host, None)
            } else {
                if room.viewers.len() >= MAX_VIEWERS {
                    return Err(());
                }
                let host_sender = room.host.as_ref().map(|host| host.sender.clone());
                room.viewers.insert(participant_id.clone(), peer);
                (PeerRole::Viewer, host_sender)
            };
            (
                role,
                participant_id,
                media_key,
                room.stream_active,
                participants(room),
                room_senders(room),
                host_sender,
            )
        };
        send_json(
            &sender,
            &json!({
                "type":"ready",
                "role":role,
                "participant_id":participant_id,
                "peer_key":media_key,
                "stream_active":stream_active,
                "participants":participants,
            }),
        );
        if let Some(host) = host_sender {
            send_json(
                &host,
                &json!({"type":"viewer_joined","viewer":participant_id}),
            );
        }
        broadcast_presence(&recipients, &participants);
        Ok(RegisteredPeer {
            role,
            connection_id,
            participant_id,
            username,
            media_key,
        })
    }

    async fn relay(
        &self,
        room_name: &str,
        peer: &RegisteredPeer,
        signal: ClientSignal,
        own_sender: &mpsc::Sender<Outbound>,
        last_reaction: &mut Option<Instant>,
    ) {
        match (peer.role, signal) {
            (PeerRole::Host, ClientSignal::Offer { viewer, sdp })
                if valid_participant_id(&viewer) && sdp.len() <= MAX_SDP_BYTES =>
            {
                let recipient = self.viewer_sender(room_name, &viewer).await;
                relay_or_report(recipient, own_sender, &json!({"type":"offer","sdp":sdp})).await;
            }
            (PeerRole::Viewer, ClientSignal::Answer { sdp }) if sdp.len() <= MAX_SDP_BYTES => {
                let recipient = self.host_sender(room_name).await;
                relay_or_report(
                    recipient,
                    own_sender,
                    &json!({"type":"answer","viewer":peer.participant_id,"sdp":sdp}),
                )
                .await;
            }
            (
                PeerRole::Host,
                ClientSignal::Ice {
                    viewer: Some(viewer),
                    candidate,
                },
            ) if valid_participant_id(&viewer) && valid_candidate(&candidate) => {
                let recipient = self.viewer_sender(room_name, &viewer).await;
                relay_or_report(
                    recipient,
                    own_sender,
                    &json!({"type":"ice","candidate":candidate}),
                )
                .await;
            }
            (
                PeerRole::Viewer,
                ClientSignal::Ice {
                    viewer: None,
                    candidate,
                },
            ) if valid_candidate(&candidate) => {
                let recipient = self.host_sender(room_name).await;
                relay_or_report(
                    recipient,
                    own_sender,
                    &json!({"type":"ice","viewer":peer.participant_id,"candidate":candidate}),
                )
                .await;
            }
            (PeerRole::Host, ClientSignal::StreamState { active }) => {
                self.set_stream_state(room_name, peer, active).await;
            }
            (PeerRole::Viewer, ClientSignal::MicrophoneState { enabled }) => {
                let recipient = self.host_sender(room_name).await;
                relay_or_report(
                    recipient,
                    own_sender,
                    &json!({
                        "type":"viewer_microphone_state",
                        "viewer":peer.participant_id,
                        "enabled":enabled,
                    }),
                )
                .await;
            }
            (PeerRole::Viewer, ClientSignal::Reaction { reaction })
                if valid_reaction(&reaction) =>
            {
                if last_reaction.is_none_or(|sent| sent.elapsed() >= REACTION_INTERVAL) {
                    *last_reaction = Some(Instant::now());
                    self.broadcast_reaction(room_name, peer, &reaction).await;
                }
            }
            _ => send_json(
                own_sender,
                &json!({"type":"error","message":"Room message is not allowed"}),
            ),
        }
    }

    async fn set_stream_state(&self, room_name: &str, peer: &RegisteredPeer, active: bool) {
        let recipients = {
            let mut rooms = self.rooms.lock().await;
            let Some(room) = rooms.get_mut(room_name) else {
                return;
            };
            if !room.host.as_ref().is_some_and(|host| {
                host.connection_id == peer.connection_id
                    && secret_matches(&host.media_key, &peer.media_key)
            }) {
                return;
            }
            room.stream_active = active;
            room_senders(room)
        };
        for recipient in recipients {
            send_json(&recipient, &json!({"type":"stream_state","active":active}));
        }
    }

    async fn broadcast_reaction(&self, room_name: &str, peer: &RegisteredPeer, reaction: &str) {
        let recipients = {
            let rooms = self.rooms.lock().await;
            let Some(room) = rooms.get(room_name) else {
                return;
            };
            if !room
                .viewers
                .get(&peer.participant_id)
                .is_some_and(|viewer| {
                    viewer.connection_id == peer.connection_id && viewer.username == peer.username
                })
            {
                return;
            }
            room_senders(room)
        };
        let message = json!({
            "type":"reaction",
            "participant_id":peer.participant_id,
            "username":peer.username,
            "reaction":reaction,
        });
        for recipient in recipients {
            send_json(&recipient, &message);
        }
    }

    async fn host_sender(&self, room_name: &str) -> Option<mpsc::Sender<Outbound>> {
        self.rooms
            .lock()
            .await
            .get(room_name)?
            .host
            .as_ref()
            .map(|peer| peer.sender.clone())
    }

    async fn viewer_sender(
        &self,
        room_name: &str,
        participant_id: &str,
    ) -> Option<mpsc::Sender<Outbound>> {
        self.rooms
            .lock()
            .await
            .get(room_name)?
            .viewers
            .get(participant_id)
            .map(|peer| peer.sender.clone())
    }

    async fn unregister(&self, room_name: &str, peer: &RegisteredPeer) -> RoomDeparture {
        let (departure, notifications, participants, recipients) = {
            let mut rooms = self.rooms.lock().await;
            let Some(room) = rooms.get_mut(room_name) else {
                return RoomDeparture::default();
            };
            match peer.role {
                PeerRole::Host
                    if room.host.as_ref().is_some_and(|host| {
                        host.connection_id == peer.connection_id && host.id == peer.participant_id
                    }) =>
                {
                    let notifications = room
                        .viewers
                        .values()
                        .map(|viewer| viewer.sender.clone())
                        .collect::<Vec<_>>();
                    rooms.remove(room_name);
                    (
                        RoomDeparture {
                            host_left: true,
                            forward_viewer: None,
                        },
                        notifications,
                        Value::Null,
                        Vec::new(),
                    )
                }
                PeerRole::Viewer
                    if room
                        .viewers
                        .get(&peer.participant_id)
                        .is_some_and(|viewer| viewer.connection_id == peer.connection_id) =>
                {
                    room.viewers.remove(&peer.participant_id);
                    let forward_viewer = room.forward_viewers.remove(&peer.participant_id);
                    let participants = participants(room);
                    let recipients = room_senders(room);
                    let notifications = room
                        .host
                        .as_ref()
                        .map(|host| vec![host.sender.clone()])
                        .unwrap_or_default();
                    (
                        RoomDeparture {
                            host_left: false,
                            forward_viewer,
                        },
                        notifications,
                        participants,
                        recipients,
                    )
                }
                _ => return RoomDeparture::default(),
            }
        };
        if departure.host_left {
            for recipient in notifications {
                send_json(&recipient, &json!({"type":"ended"}));
                let _ = recipient.try_send(Outbound::Close);
            }
        } else {
            for host in notifications {
                send_json(
                    &host,
                    &json!({"type":"viewer_left","viewer":peer.participant_id}),
                );
            }
            broadcast_presence(&recipients, &participants);
        }
        departure
    }
}

pub fn valid_room_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ROOM_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

pub fn normalize_username(username: &str) -> Option<String> {
    let username = username.trim();
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || username.chars().count() > MAX_USERNAME_CHARS
        || username.chars().any(char::is_control)
    {
        return None;
    }
    Some(username.to_owned())
}

fn participants(room: &LiveRoom) -> Value {
    let mut participants =
        Vec::with_capacity(room.viewers.len() + usize::from(room.host.is_some()));
    if let Some(host) = &room.host {
        participants.push(json!({"id":host.id,"username":host.username,"role":PeerRole::Host}));
    }
    let mut viewers = room.viewers.values().collect::<Vec<_>>();
    viewers.sort_by(|left, right| {
        left.username
            .to_lowercase()
            .cmp(&right.username.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    participants.extend(
        viewers.into_iter().map(
            |viewer| json!({"id":viewer.id,"username":viewer.username,"role":PeerRole::Viewer}),
        ),
    );
    Value::Array(participants)
}

fn room_senders(room: &LiveRoom) -> Vec<mpsc::Sender<Outbound>> {
    room.host
        .iter()
        .chain(room.viewers.values())
        .map(|peer| peer.sender.clone())
        .collect()
}

fn broadcast_presence(recipients: &[mpsc::Sender<Outbound>], participants: &Value) {
    let message = json!({"type":"presence","participants":participants});
    for recipient in recipients {
        send_json(recipient, &message);
    }
}

async fn send_socket_error(socket: &mut WebSocket, message: &str) {
    let _ = socket
        .send(Message::Text(
            json!({"type":"error","message":message}).to_string().into(),
        ))
        .await;
    let _ = socket.send(Message::Close(None)).await;
}

async fn relay_or_report(
    recipient: Option<mpsc::Sender<Outbound>>,
    own_sender: &mpsc::Sender<Outbound>,
    message: &Value,
) {
    if let Some(sender) = recipient
        && tokio::time::timeout(
            Duration::from_secs(2),
            sender.send(Outbound::Text(message.to_string())),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    {
        return;
    }
    send_json(
        own_sender,
        &json!({"type":"error","message":"Peer is no longer available"}),
    );
}

fn send_json(sender: &mpsc::Sender<Outbound>, message: &Value) {
    let _ = sender.try_send(Outbound::Text(message.to_string()));
}

fn unique_participant_id(room: &LiveRoom) -> Option<String> {
    (0..32).find_map(|_| {
        let id = format!("{:016x}", rand::random::<u64>());
        let available =
            room.host.as_ref().is_none_or(|host| host.id != id) && !room.viewers.contains_key(&id);
        available.then_some(id)
    })
}

fn random_secret() -> String {
    format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    )
}

fn valid_participant_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_candidate(candidate: &Value) -> bool {
    candidate.is_object() && candidate.to_string().len() <= MAX_CANDIDATE_BYTES
}

fn valid_reaction(reaction: &str) -> bool {
    REACTIONS.contains(&reaction)
}

fn secret_matches(expected: &str, provided: &str) -> bool {
    expected.len() == provided.len()
        && expected
            .bytes()
            .zip(provided.bytes())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn receive_json(receiver: &mut mpsc::Receiver<Outbound>) -> Value {
        let Some(Outbound::Text(text)) = receiver.recv().await else {
            panic!("expected a JSON room message");
        };
        serde_json::from_str(&text).unwrap()
    }

    async fn receive_type(receiver: &mut mpsc::Receiver<Outbound>, kind: &str) -> Value {
        loop {
            let message = receive_json(receiver).await;
            if message["type"] == kind {
                return message;
            }
        }
    }

    #[test]
    fn validates_room_names_and_usernames() {
        assert!(valid_room_name("weekly-demo"));
        assert!(valid_room_name("room2"));
        assert!(!valid_room_name("Weekly Demo"));
        assert!(!valid_room_name("-room"));
        assert!(!valid_room_name(&"a".repeat(MAX_ROOM_NAME_BYTES + 1)));
        assert_eq!(
            normalize_username("  Cassiano  ").as_deref(),
            Some("Cassiano")
        );
        assert!(normalize_username("").is_none());
        assert!(normalize_username("bad\nname").is_none());
        assert!(valid_reaction("creeper"));
        assert!(!valid_reaction("tnt"));
    }

    #[tokio::test]
    async fn first_participant_hosts_and_later_participants_watch() {
        let hub = LiveHub::default();
        let (host_tx, mut host_rx) = mpsc::channel(SIGNAL_QUEUE);
        let host = hub
            .register_peer("weekly-demo", "Alice".to_owned(), host_tx)
            .await
            .unwrap();
        assert_eq!(host.role, PeerRole::Host);
        let ready = receive_type(&mut host_rx, "ready").await;
        assert_eq!(ready["role"], "host");
        receive_type(&mut host_rx, "presence").await;

        let (viewer_tx, mut viewer_rx) = mpsc::channel(SIGNAL_QUEUE);
        let viewer = hub
            .register_peer("weekly-demo", "Bob".to_owned(), viewer_tx)
            .await
            .unwrap();
        assert_eq!(viewer.role, PeerRole::Viewer);
        let ready = receive_type(&mut viewer_rx, "ready").await;
        assert_eq!(ready["role"], "viewer");
        assert_eq!(ready["participants"].as_array().unwrap().len(), 2);
        let presence = receive_type(&mut host_rx, "presence").await;
        assert_eq!(presence["participants"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn room_name_can_be_reused_after_the_host_leaves() {
        let hub = LiveHub::default();
        let (host_tx, _host_rx) = mpsc::channel(SIGNAL_QUEUE);
        let host = hub
            .register_peer("daily", "Alice".to_owned(), host_tx)
            .await
            .unwrap();
        let (viewer_tx, mut viewer_rx) = mpsc::channel(SIGNAL_QUEUE);
        hub.register_peer("daily", "Bob".to_owned(), viewer_tx)
            .await
            .unwrap();

        assert!(hub.unregister("daily", &host).await.host_left);
        receive_type(&mut viewer_rx, "ended").await;
        assert!(matches!(viewer_rx.recv().await, Some(Outbound::Close)));

        let (next_tx, mut next_rx) = mpsc::channel(SIGNAL_QUEUE);
        let next = hub
            .register_peer("daily", "Bob".to_owned(), next_tx)
            .await
            .unwrap();
        assert_eq!(next.role, PeerRole::Host);
        assert_eq!(receive_type(&mut next_rx, "ready").await["role"], "host");
    }

    #[tokio::test]
    async fn relays_signaling_and_viewer_reactions() {
        let hub = LiveHub::default();
        let (host_tx, mut host_rx) = mpsc::channel(SIGNAL_QUEUE);
        let host = hub
            .register_peer("demo", "Alice".to_owned(), host_tx.clone())
            .await
            .unwrap();
        receive_type(&mut host_rx, "ready").await;
        let (viewer_tx, mut viewer_rx) = mpsc::channel(SIGNAL_QUEUE);
        let viewer = hub
            .register_peer("demo", "Bob".to_owned(), viewer_tx.clone())
            .await
            .unwrap();
        receive_type(&mut viewer_rx, "ready").await;
        receive_type(&mut host_rx, "viewer_joined").await;

        hub.relay(
            "demo",
            &host,
            ClientSignal::Offer {
                viewer: viewer.participant_id.clone(),
                sdp: "v=0".to_owned(),
            },
            &host_tx,
            &mut None,
        )
        .await;
        assert_eq!(
            receive_type(&mut viewer_rx, "offer").await,
            json!({"type":"offer","sdp":"v=0"})
        );

        let mut last_reaction = None;
        hub.relay(
            "demo",
            &viewer,
            ClientSignal::Reaction {
                reaction: "👏".to_owned(),
            },
            &viewer_tx,
            &mut last_reaction,
        )
        .await;
        let reaction = receive_type(&mut host_rx, "reaction").await;
        assert_eq!(reaction["username"], "Bob");
        assert_eq!(reaction["reaction"], "👏");

        hub.relay(
            "demo",
            &viewer,
            ClientSignal::MicrophoneState { enabled: true },
            &viewer_tx,
            &mut None,
        )
        .await;
        assert_eq!(
            receive_type(&mut host_rx, "viewer_microphone_state").await,
            json!({
                "type":"viewer_microphone_state",
                "viewer":viewer.participant_id,
                "enabled":true,
            })
        );
    }

    #[tokio::test]
    async fn forward_credentials_cannot_change_assigned_roles() {
        let hub = LiveHub::default();
        let (host_tx, _host_rx) = mpsc::channel(SIGNAL_QUEUE);
        let host = hub
            .register_peer("demo", "Alice".to_owned(), host_tx)
            .await
            .unwrap();
        let (viewer_tx, _viewer_rx) = mpsc::channel(SIGNAL_QUEUE);
        let viewer = hub
            .register_peer("demo", "Bob".to_owned(), viewer_tx)
            .await
            .unwrap();
        assert_eq!(
            hub.claim_forward_peer("demo", &viewer.media_key, 1).await,
            None
        );
        assert_eq!(
            hub.claim_forward_peer("demo", &host.media_key, 2).await,
            Some(MediaRole::Publisher)
        );
        assert_eq!(
            hub.claim_forward_peer("demo", &viewer.media_key, 3).await,
            Some(MediaRole::Viewer)
        );
        assert_eq!(hub.claim_forward_peer("demo", "wrong", 4).await, None);
        let departure = hub.unregister("demo", &viewer).await;
        assert_eq!(departure.forward_viewer, Some(3));
    }
}
