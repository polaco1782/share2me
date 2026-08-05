use std::time::Duration;

use tokio::sync::watch;

use crate::store::FileStore;

pub async fn run(store: FileStore, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60)) => {
                let sweep_store = store.clone();
                match tokio::task::spawn_blocking(move || sweep_store.sweep_expired()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => tracing::warn!(%error, "housekeeper sweep failed"),
                    Err(error) => tracing::error!(%error, "housekeeper task panicked"),
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}
