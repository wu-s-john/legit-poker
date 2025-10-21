pub mod bootstrap;
pub mod demo;
mod dto;
mod error;
pub mod routes;

pub use bootstrap::{run_server, ServerConfig};
pub use dto::{
    ActorResponse, DemoCreateRequest, DemoCreateResponse, DemoStartResponse, HandMessageResponse,
    HandMessagesResponse, LatestSnapshotResponse, MessageTypeResponse, SnapshotPhaseResponse,
    SnapshotStatusResponse,
};
pub use error::ApiError;
pub use routes::{LegitPokerServer, ServerContext};
