use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};

use crate::media::MediaRole;

const MAX_SESSIONS: usize = 128;
pub const MAX_VIEWERS: usize = 8;
pub const MAX_SIGNAL_BYTES: usize = 128 * 1024;
pub const MAX_SDP_BYTES: usize = 96 * 1024;
const MAX_CANDIDATE_BYTES: usize = 8 * 1024;
const SIGNAL_QUEUE: usize = 64;
const UNCLAIMED_SESSION_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Host,
    Viewer,
}

#[derive(Clone, Debug)]
pub struct CreatedSession {
    pub id: String,
    pub host_key: String,
}

#[derive(Clone, Debug, Default)]
pub struct LiveHub {
    sessions: Arc<Mutex<HashMap<String, LiveSession>>>,
}

#[derive(Debug)]
struct LiveSession {
    host_key: String,
    host: Option<Peer>,
    viewers: HashMap<String, Peer>,
    forward_host: Option<u128>,
    forward_viewers: HashSet<u128>,
    created_at: tokio::time::Instant,
}

#[derive(Clone, Debug)]
struct Peer {
    connection_id: u128,
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
    Authenticate {
        key: String,
    },
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
    Stop,
}

#[derive(Debug)]
struct RegisteredPeer {
    role: PeerRole,
    connection_id: u128,
    viewer_id: Option<String>,
}

impl LiveHub {
    pub async fn create_session(&self) -> Option<CreatedSession> {
        let mut sessions = self.sessions.lock().await;
        if sessions.len() >= MAX_SESSIONS {
            return None;
        }

        for _ in 0..32 {
            let id = random_token();
            if sessions.contains_key(&id) {
                continue;
            }
            let host_key = format!(
                "{:032x}{:032x}",
                rand::random::<u128>(),
                rand::random::<u128>()
            );
            sessions.insert(
                id.clone(),
                LiveSession {
                    host_key: host_key.clone(),
                    host: None,
                    viewers: HashMap::new(),
                    forward_host: None,
                    forward_viewers: HashSet::new(),
                    created_at: tokio::time::Instant::now(),
                },
            );
            let expiry_hub = self.clone();
            let expiry_id = id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(UNCLAIMED_SESSION_LIFETIME).await;
                expiry_hub.expire_unclaimed(&expiry_id).await;
            });
            return Some(CreatedSession { id, host_key });
        }
        None
    }

    pub async fn contains(&self, id: &str) -> bool {
        let sessions = self.sessions.lock().await;
        let is_stale = sessions.get(id).is_some_and(|session| {
            session.host.is_none()
                && session.forward_host.is_none()
                && session.created_at.elapsed() >= UNCLAIMED_SESSION_LIFETIME
        });
        if is_stale {
            return false;
        }
        sessions.contains_key(id)
    }

    pub async fn claim_forward_host(
        &self,
        session_id: &str,
        host_key: &str,
        connection_id: u128,
    ) -> bool {
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return false;
        };
        if session.host.is_some()
            || session.forward_host.is_some()
            || !secret_matches(&session.host_key, host_key)
        {
            return false;
        }
        session.forward_host = Some(connection_id);
        true
    }

    pub async fn claim_forward_viewer(&self, session_id: &str, connection_id: u128) -> bool {
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return false;
        };
        if session.forward_host.is_none() || session.forward_viewers.len() >= MAX_VIEWERS {
            return false;
        }
        session.forward_viewers.insert(connection_id)
    }

    pub async fn release_forward_peer(
        &self,
        session_id: &str,
        role: MediaRole,
        connection_id: u128,
    ) {
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return;
        };
        match role {
            MediaRole::Publisher => {
                if session.forward_host == Some(connection_id) {
                    sessions.remove(session_id);
                }
            }
            MediaRole::Viewer => {
                session.forward_viewers.remove(&connection_id);
            }
        }
    }

    pub async fn stop_forward_session(&self, session_id: &str, host_key: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get(session_id) else {
            return false;
        };
        if session.forward_host.is_none() || !secret_matches(&session.host_key, host_key) {
            return false;
        }
        sessions.remove(session_id);
        true
    }

    pub async fn handle_socket(self, mut socket: WebSocket, session_id: String, role: PeerRole) {
        let (outbound_tx, mut outbound_rx) = mpsc::channel(SIGNAL_QUEUE);
        let registration = match role {
            PeerRole::Host => {
                let authentication =
                    tokio::time::timeout(Duration::from_secs(5), socket.recv()).await;
                let key = match authentication {
                    Ok(Some(Ok(Message::Text(text)))) => {
                        match serde_json::from_str::<ClientSignal>(&text) {
                            Ok(ClientSignal::Authenticate { key }) => key,
                            _ => {
                                return send_socket_error(
                                    &mut socket,
                                    "Host authentication required",
                                )
                                .await;
                            }
                        }
                    }
                    _ => {
                        return send_socket_error(&mut socket, "Host authentication timed out")
                            .await;
                    }
                };
                self.register_host(&session_id, &key, outbound_tx.clone())
                    .await
            }
            PeerRole::Viewer => self.register_viewer(&session_id, outbound_tx.clone()).await,
        };

        let Ok(registration) = registration else {
            return send_socket_error(&mut socket, "Share is unavailable").await;
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
                    &json!({"type":"error","message":"Invalid signaling message"}),
                );
                continue;
            };
            if !self
                .relay(&session_id, &registration, signal, &outbound_tx)
                .await
            {
                break;
            }
        }

        self.unregister(&session_id, &registration).await;
        writer_task.abort();
    }

    async fn register_host(
        &self,
        session_id: &str,
        key: &str,
        sender: mpsc::Sender<Outbound>,
    ) -> Result<RegisteredPeer, ()> {
        let connection_id = rand::random::<u128>();
        let viewers = {
            let mut sessions = self.sessions.lock().await;
            let session = sessions.get_mut(session_id).ok_or(())?;
            if !secret_matches(&session.host_key, key)
                || session.host.is_some()
                || session.forward_host.is_some()
            {
                return Err(());
            }
            session.host = Some(Peer {
                connection_id,
                sender: sender.clone(),
            });
            session.viewers.keys().cloned().collect::<Vec<_>>()
        };
        send_json(&sender, &json!({"type":"ready"}));
        for viewer in viewers {
            send_json(&sender, &json!({"type":"viewer_joined","viewer":viewer}));
        }
        Ok(RegisteredPeer {
            role: PeerRole::Host,
            connection_id,
            viewer_id: None,
        })
    }

    async fn register_viewer(
        &self,
        session_id: &str,
        sender: mpsc::Sender<Outbound>,
    ) -> Result<RegisteredPeer, ()> {
        let connection_id = rand::random::<u128>();
        let (viewer_id, host) = {
            let mut sessions = self.sessions.lock().await;
            let session = sessions.get_mut(session_id).ok_or(())?;
            if session.viewers.len() >= MAX_VIEWERS {
                return Err(());
            }
            let viewer_id = unique_viewer_id(&session.viewers);
            session.viewers.insert(
                viewer_id.clone(),
                Peer {
                    connection_id,
                    sender: sender.clone(),
                },
            );
            (
                viewer_id,
                session.host.as_ref().map(|peer| peer.sender.clone()),
            )
        };
        send_json(&sender, &json!({"type":"ready","viewer":viewer_id}));
        if let Some(host) = host {
            send_json(&host, &json!({"type":"viewer_joined","viewer":viewer_id}));
        }
        Ok(RegisteredPeer {
            role: PeerRole::Viewer,
            connection_id,
            viewer_id: Some(viewer_id),
        })
    }

    async fn relay(
        &self,
        session_id: &str,
        peer: &RegisteredPeer,
        signal: ClientSignal,
        own_sender: &mpsc::Sender<Outbound>,
    ) -> bool {
        match (peer.role, signal) {
            (PeerRole::Host, ClientSignal::Offer { viewer, sdp })
                if valid_viewer_id(&viewer) && sdp.len() <= MAX_SDP_BYTES =>
            {
                let recipient = self.viewer_sender(session_id, &viewer).await;
                relay_or_report(recipient, own_sender, &json!({"type":"offer","sdp":sdp})).await;
            }
            (PeerRole::Viewer, ClientSignal::Answer { sdp }) if sdp.len() <= MAX_SDP_BYTES => {
                let recipient = self.host_sender(session_id).await;
                let viewer = peer.viewer_id.as_deref().unwrap_or_default();
                relay_or_report(
                    recipient,
                    own_sender,
                    &json!({"type":"answer","viewer":viewer,"sdp":sdp}),
                )
                .await;
            }
            (
                PeerRole::Host,
                ClientSignal::Ice {
                    viewer: Some(viewer),
                    candidate,
                },
            ) if valid_viewer_id(&viewer) && valid_candidate(&candidate) => {
                let recipient = self.viewer_sender(session_id, &viewer).await;
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
                let recipient = self.host_sender(session_id).await;
                let viewer = peer.viewer_id.as_deref().unwrap_or_default();
                relay_or_report(
                    recipient,
                    own_sender,
                    &json!({"type":"ice","viewer":viewer,"candidate":candidate}),
                )
                .await;
            }
            (PeerRole::Host, ClientSignal::Stop) => return false,
            _ => send_json(
                own_sender,
                &json!({"type":"error","message":"Signaling message is not allowed"}),
            ),
        }
        true
    }

    async fn host_sender(&self, session_id: &str) -> Option<mpsc::Sender<Outbound>> {
        self.sessions
            .lock()
            .await
            .get(session_id)?
            .host
            .as_ref()
            .map(|peer| peer.sender.clone())
    }

    async fn viewer_sender(
        &self,
        session_id: &str,
        viewer_id: &str,
    ) -> Option<mpsc::Sender<Outbound>> {
        self.sessions
            .lock()
            .await
            .get(session_id)?
            .viewers
            .get(viewer_id)
            .map(|peer| peer.sender.clone())
    }

    async fn unregister(&self, session_id: &str, peer: &RegisteredPeer) {
        let mut notifications = Vec::new();
        {
            let mut sessions = self.sessions.lock().await;
            let Some(session) = sessions.get_mut(session_id) else {
                return;
            };
            match peer.role {
                PeerRole::Host => {
                    if session
                        .host
                        .as_ref()
                        .is_some_and(|host| host.connection_id == peer.connection_id)
                    {
                        notifications
                            .extend(session.viewers.values().map(|viewer| viewer.sender.clone()));
                        sessions.remove(session_id);
                    }
                }
                PeerRole::Viewer => {
                    let Some(viewer_id) = peer.viewer_id.as_deref() else {
                        return;
                    };
                    if session
                        .viewers
                        .get(viewer_id)
                        .is_some_and(|viewer| viewer.connection_id == peer.connection_id)
                    {
                        session.viewers.remove(viewer_id);
                        if let Some(host) = &session.host {
                            notifications.push(host.sender.clone());
                        }
                    }
                }
            }
        }
        for sender in notifications {
            let message = match peer.role {
                PeerRole::Host => json!({"type":"ended"}),
                PeerRole::Viewer => {
                    json!({"type":"viewer_left","viewer":peer.viewer_id.as_deref().unwrap_or_default()})
                }
            };
            send_json(&sender, &message);
            if matches!(peer.role, PeerRole::Host) {
                let _ = sender.try_send(Outbound::Close);
            }
        }
    }

    async fn expire_unclaimed(&self, session_id: &str) {
        let viewers = {
            let mut sessions = self.sessions.lock().await;
            let should_expire = sessions.get(session_id).is_some_and(|session| {
                session.host.is_none()
                    && session.forward_host.is_none()
                    && session.created_at.elapsed() >= UNCLAIMED_SESSION_LIFETIME
            });
            if !should_expire {
                return;
            }
            sessions
                .remove(session_id)
                .map(|session| {
                    session
                        .viewers
                        .into_values()
                        .map(|viewer| viewer.sender)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        for sender in viewers {
            send_json(&sender, &json!({"type":"ended"}));
            let _ = sender.try_send(Outbound::Close);
        }
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

fn random_token() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn unique_viewer_id(viewers: &HashMap<String, Peer>) -> String {
    loop {
        let id = format!("{:016x}", rand::random::<u64>());
        if !viewers.contains_key(&id) {
            return id;
        }
    }
}

fn valid_viewer_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_candidate(candidate: &Value) -> bool {
    candidate.is_object() && candidate.to_string().len() <= MAX_CANDIDATE_BYTES
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
            panic!("expected a JSON signaling message");
        };
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test]
    async fn creates_bounded_bearer_sessions() {
        let hub = LiveHub::default();
        let session = hub.create_session().await.unwrap();
        assert_eq!(session.id.len(), 32);
        assert_eq!(session.host_key.len(), 64);
        assert!(hub.contains(&session.id).await);
        assert!(!secret_matches(&session.host_key, "wrong"));
        assert!(secret_matches(&session.host_key, &session.host_key));
    }

    #[tokio::test]
    async fn authenticates_host_and_relays_only_to_the_selected_viewer() {
        let hub = LiveHub::default();
        let session = hub.create_session().await.unwrap();
        let (viewer_tx, mut viewer_rx) = mpsc::channel(SIGNAL_QUEUE);
        let viewer = hub
            .register_viewer(&session.id, viewer_tx.clone())
            .await
            .unwrap();
        let ready = receive_json(&mut viewer_rx).await;
        assert_eq!(ready["type"], "ready");

        let (host_tx, mut host_rx) = mpsc::channel(SIGNAL_QUEUE);
        assert!(
            hub.register_host(&session.id, "wrong", host_tx.clone())
                .await
                .is_err()
        );
        let host = hub
            .register_host(&session.id, &session.host_key, host_tx.clone())
            .await
            .unwrap();
        assert_eq!(receive_json(&mut host_rx).await["type"], "ready");
        assert_eq!(receive_json(&mut host_rx).await["type"], "viewer_joined");

        let viewer_id = viewer.viewer_id.clone().unwrap();
        assert!(
            hub.relay(
                &session.id,
                &host,
                ClientSignal::Offer {
                    viewer: viewer_id,
                    sdp: "v=0".to_owned(),
                },
                &host_tx,
            )
            .await
        );
        let offer = receive_json(&mut viewer_rx).await;
        assert_eq!(offer, json!({"type":"offer","sdp":"v=0"}));

        hub.unregister(&session.id, &host).await;
        let ended = receive_json(&mut viewer_rx).await;
        assert_eq!(ended["type"], "ended");
        assert!(matches!(viewer_rx.recv().await, Some(Outbound::Close)));
        assert!(!hub.contains(&session.id).await);
    }

    #[test]
    fn validates_only_bounded_candidate_objects() {
        assert!(valid_candidate(&json!({"candidate":"candidate:1"})));
        assert!(!valid_candidate(&json!("candidate:1")));
        assert!(!valid_candidate(
            &json!({"candidate":"x".repeat(MAX_CANDIDATE_BYTES)})
        ));
    }
}
