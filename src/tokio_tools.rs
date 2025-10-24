use std::future::Future;

use tokio::task::JoinHandle;

/// Spawn a Tokio task with a stable name when supported, and trace span otherwise.
pub fn spawn_named_task<F, S>(name: S, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
    S: Into<String>,
{
    let name_owned = name.into();
    #[cfg(tokio_unstable)]
    {
        tokio::task::Builder::new().name(&name_owned).spawn(future)
    }
    #[cfg(not(tokio_unstable))]
    {
        use tracing::Instrument;
        let span = tracing::info_span!("task", task_name = %name_owned);
        tokio::spawn(future.instrument(span))
    }
}
