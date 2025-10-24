pub mod bootstrap;
pub mod demo;
mod dto;
mod error;
pub mod logging;
pub mod routes;

pub use bootstrap::{run_server, ServerConfig};
pub use dto::{
    DemoCreateRequest, DemoCreateResponse, DemoStartResponse, HandMessagesResponse,
    LatestSnapshotResponse,
};
pub use error::ApiError;
pub use routes::{LegitPokerServer, ServerContext};
