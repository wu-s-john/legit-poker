use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::engine::nl::types::{HandConfig, PlayerId};
use crate::ledger::store::snapshot::PreparedSnapshot;
use crate::ledger::types::{GameId, HandId, ShufflerId};

use crate::ledger::lobby::error::GameSetupError;

use super::{
    LobbyStorage, LobbyStorageTxn, NewGame, NewGamePlayer, NewGameShuffler, NewHand, NewHandPlayer,
    NewHandShuffler, NewPlayer, NewShuffler, StoredPlayer, StoredShuffler,
};

#[derive(Default)]
struct Inner {
    players: HashMap<PlayerId, StoredPlayer>,
    shufflers: HashMap<ShufflerId, StoredShuffler>,
    games: HashMap<GameId, StoredGame>,
    game_players: Vec<NewGamePlayer>,
    game_shufflers: Vec<NewGameShuffler>,
    hand_configs: HashMap<i64, HandConfig>,
    hands: HashMap<HandId, StoredHand>,
    hand_players: Vec<NewHandPlayer>,
    hand_shufflers: Vec<NewHandShuffler>,
    snapshots: Vec<PreparedSnapshot>,
    next_player_id: PlayerId,
    next_shuffler_id: ShufflerId,
    next_game_id: GameId,
    next_hand_id: HandId,
    next_hand_config_id: i64,
}

#[allow(dead_code)]
#[derive(Clone)]
struct StoredGame {
    host_player_id: PlayerId,
    config: crate::ledger::lobby::types::GameLobbyConfig,
}

#[allow(dead_code)]
#[derive(Clone)]
struct StoredHand {
    record: NewHand,
}

pub struct InMemoryLobbyStorage {
    inner: Arc<RwLock<Inner>>,
}

impl InMemoryLobbyStorage {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                next_player_id: 1,
                next_shuffler_id: 1,
                next_game_id: 1,
                next_hand_id: 1,
                next_hand_config_id: 1,
                ..Inner::default()
            })),
        }
    }
}

pub struct InMemoryLobbyTxn {
    inner: Arc<RwLock<Inner>>,
    next_player_id: PlayerId,
    next_shuffler_id: ShufflerId,
    next_game_id: GameId,
    next_hand_id: HandId,
    next_hand_config_id: i64,
    players: Vec<(PlayerId, StoredPlayer)>,
    shufflers: Vec<(ShufflerId, StoredShuffler)>,
    games: Vec<(GameId, StoredGame)>,
    game_players: Vec<NewGamePlayer>,
    game_shufflers: Vec<NewGameShuffler>,
    hand_configs: Vec<(i64, HandConfig)>,
    hands: Vec<(HandId, StoredHand)>,
    hand_players: Vec<NewHandPlayer>,
    hand_shufflers: Vec<NewHandShuffler>,
    snapshots: Vec<PreparedSnapshot>,
    committed: bool,
}

#[async_trait]
impl LobbyStorage for InMemoryLobbyStorage {
    async fn begin(&self) -> Result<Box<dyn LobbyStorageTxn>, GameSetupError> {
        let inner = self.inner.read();
        Ok(Box::new(InMemoryLobbyTxn {
            inner: Arc::clone(&self.inner),
            next_player_id: inner.next_player_id,
            next_shuffler_id: inner.next_shuffler_id,
            next_game_id: inner.next_game_id,
            next_hand_id: inner.next_hand_id,
            next_hand_config_id: inner.next_hand_config_id,
            players: Vec::new(),
            shufflers: Vec::new(),
            games: Vec::new(),
            game_players: Vec::new(),
            game_shufflers: Vec::new(),
            hand_configs: Vec::new(),
            hands: Vec::new(),
            hand_players: Vec::new(),
            hand_shufflers: Vec::new(),
            snapshots: Vec::new(),
            committed: false,
        }))
    }
}

impl InMemoryLobbyTxn {
    fn next_player_id(&mut self) -> PlayerId {
        let id = self.next_player_id;
        self.next_player_id += 1;
        id
    }

    fn next_shuffler_id(&mut self) -> ShufflerId {
        let id = self.next_shuffler_id;
        self.next_shuffler_id += 1;
        id
    }

    fn next_game_id(&mut self) -> GameId {
        let id = self.next_game_id;
        self.next_game_id += 1;
        id
    }

    fn next_hand_id(&mut self) -> HandId {
        let id = self.next_hand_id;
        self.next_hand_id += 1;
        id
    }

    fn next_hand_config_id(&mut self) -> i64 {
        let id = self.next_hand_config_id;
        self.next_hand_config_id += 1;
        id
    }

    fn lookup_player(&self, id: PlayerId) -> Option<StoredPlayer> {
        if let Some((_, stored)) = self.players.iter().rev().find(|(pid, _)| *pid == id) {
            return Some(stored.clone());
        }
        let inner = self.inner.read();
        inner.players.get(&id).cloned()
    }

    fn lookup_shuffler(&self, id: ShufflerId) -> Option<StoredShuffler> {
        if let Some((_, stored)) = self.shufflers.iter().rev().find(|(sid, _)| *sid == id) {
            return Some(stored.clone());
        }
        let inner = self.inner.read();
        inner.shufflers.get(&id).cloned()
    }
}

#[async_trait]
impl LobbyStorageTxn for InMemoryLobbyTxn {
    async fn load_player(&mut self, id: PlayerId) -> Result<Option<StoredPlayer>, GameSetupError> {
        Ok(self.lookup_player(id))
    }

    async fn insert_player(&mut self, player: NewPlayer) -> Result<PlayerId, GameSetupError> {
        let id = self.next_player_id();
        self.players.push((
            id,
            StoredPlayer {
                display_name: player.display_name,
                public_key: player.public_key,
            },
        ));
        Ok(id)
    }

    async fn load_shuffler(
        &mut self,
        id: ShufflerId,
    ) -> Result<Option<StoredShuffler>, GameSetupError> {
        Ok(self.lookup_shuffler(id))
    }

    async fn insert_shuffler(
        &mut self,
        shuffler: NewShuffler,
    ) -> Result<ShufflerId, GameSetupError> {
        let id = self.next_shuffler_id();
        self.shufflers.push((
            id,
            StoredShuffler {
                display_name: shuffler.display_name,
                public_key: shuffler.public_key,
            },
        ));
        Ok(id)
    }

    async fn insert_game(&mut self, game: NewGame) -> Result<GameId, GameSetupError> {
        let id = self.next_game_id();
        self.games.push((
            id,
            StoredGame {
                host_player_id: game.host_player_id,
                config: game.config,
            },
        ));
        Ok(id)
    }

    async fn insert_game_player(&mut self, row: NewGamePlayer) -> Result<(), GameSetupError> {
        self.game_players.push(row);
        Ok(())
    }

    async fn count_game_shufflers(&mut self, game_id: GameId) -> Result<u16, GameSetupError> {
        let inner = self.inner.read();
        let existing = inner
            .game_shufflers
            .iter()
            .filter(|entry| entry.game_id == game_id)
            .count();
        drop(inner);
        let pending = self
            .game_shufflers
            .iter()
            .filter(|entry| entry.game_id == game_id)
            .count();
        u16::try_from(existing + pending)
            .map_err(|_| GameSetupError::validation("shuffler sequence exceeds supported range"))
    }

    async fn insert_game_shuffler(&mut self, row: NewGameShuffler) -> Result<(), GameSetupError> {
        self.game_shufflers.push(row);
        Ok(())
    }

    async fn insert_hand_config(
        &mut self,
        _game_id: GameId,
        cfg: &HandConfig,
    ) -> Result<i64, GameSetupError> {
        let id = self.next_hand_config_id();
        self.hand_configs.push((id, cfg.clone()));
        Ok(id)
    }

    async fn insert_hand(&mut self, hand: NewHand) -> Result<HandId, GameSetupError> {
        let id = self.next_hand_id();
        self.hands.push((id, StoredHand { record: hand }));
        Ok(id)
    }

    async fn insert_hand_player(&mut self, row: NewHandPlayer) -> Result<(), GameSetupError> {
        self.hand_players.push(row);
        Ok(())
    }

    async fn insert_hand_shuffler(&mut self, row: NewHandShuffler) -> Result<(), GameSetupError> {
        self.hand_shufflers.push(row);
        Ok(())
    }

    async fn persist_snapshot(&mut self, prepared: PreparedSnapshot) -> Result<(), GameSetupError> {
        self.snapshots.push(prepared);
        Ok(())
    }

    async fn commit(mut self: Box<Self>) -> Result<(), GameSetupError> {
        self.committed = true;
        let mut inner = self.inner.write();

        inner.next_player_id = self.next_player_id;
        inner.next_shuffler_id = self.next_shuffler_id;
        inner.next_game_id = self.next_game_id;
        inner.next_hand_id = self.next_hand_id;
        inner.next_hand_config_id = self.next_hand_config_id;

        for (id, player) in self.players {
            inner.players.insert(id, player);
        }
        for (id, shuffler) in self.shufflers {
            inner.shufflers.insert(id, shuffler);
        }
        for (id, game) in self.games {
            inner.games.insert(id, game);
        }
        inner.game_players.extend(self.game_players);
        inner.game_shufflers.extend(self.game_shufflers);
        for (id, cfg) in self.hand_configs {
            inner.hand_configs.insert(id, cfg);
        }
        for (id, hand) in self.hands {
            inner.hands.insert(id, hand);
        }
        inner.hand_players.extend(self.hand_players);
        inner.hand_shufflers.extend(self.hand_shufflers);
        inner.snapshots.extend(self.snapshots);

        Ok(())
    }

    async fn rollback(mut self: Box<Self>) {
        self.committed = true;
    }
}

impl Default for InMemoryLobbyStorage {
    fn default() -> Self {
        Self::new()
    }
}
