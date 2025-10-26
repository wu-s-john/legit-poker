use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use parking_lot::RwLock;

use crate::engine::nl::types::HandConfig;
use crate::ledger::serialization::serialize_curve_bytes;
use crate::ledger::store::snapshot::PreparedSnapshot;
use crate::ledger::types::{GameId, HandId};
use crate::ledger::CanonicalKey;

use crate::ledger::lobby::error::GameSetupError;

use super::{
    LobbyStorage, LobbyStorageTxn, NewGame, NewGamePlayer, NewGameShuffler, NewHand, NewHandPlayer,
    NewHandShuffler, NewPlayer, NewShuffler, StoredPlayer, StoredShuffler,
};

struct Inner<C: CurveGroup> {
    // Use serialized public key bytes as HashMap keys for lookup
    players: HashMap<Vec<u8>, crate::engine::nl::types::PlayerId>,
    players_by_id: HashMap<crate::engine::nl::types::PlayerId, StoredPlayer<C>>,
    shufflers: HashMap<Vec<u8>, crate::ledger::types::ShufflerId>,
    shufflers_by_id: HashMap<crate::ledger::types::ShufflerId, StoredShuffler<C>>,
    games: HashMap<GameId, StoredGame>,
    game_players: Vec<NewGamePlayer>,
    game_shufflers: Vec<NewGameShuffler<C>>,
    hand_configs: HashMap<i64, HandConfig>,
    hands: HashMap<HandId, StoredHand>,
    hand_players: Vec<NewHandPlayer>,
    hand_shufflers: Vec<NewHandShuffler>,
    snapshots: Vec<PreparedSnapshot>,
    next_player_id: crate::engine::nl::types::PlayerId,
    next_shuffler_id: crate::ledger::types::ShufflerId,
    next_game_id: GameId,
    next_hand_id: HandId,
    next_hand_config_id: i64,
}

impl<C: CurveGroup> Default for Inner<C> {
    fn default() -> Self {
        Self {
            players: HashMap::new(),
            players_by_id: HashMap::new(),
            shufflers: HashMap::new(),
            shufflers_by_id: HashMap::new(),
            games: HashMap::new(),
            game_players: Vec::new(),
            game_shufflers: Vec::new(),
            hand_configs: HashMap::new(),
            hands: HashMap::new(),
            hand_players: Vec::new(),
            hand_shufflers: Vec::new(),
            snapshots: Vec::new(),
            next_player_id: 1,
            next_shuffler_id: 1,
            next_game_id: 1,
            next_hand_id: 1,
            next_hand_config_id: 1,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct StoredGame {
    host_player_id: crate::engine::nl::types::PlayerId,
    config: crate::ledger::lobby::types::GameLobbyConfig,
}

#[allow(dead_code)]
#[derive(Clone)]
struct StoredHand {
    record: NewHand,
}

pub struct InMemoryLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    inner: Arc<RwLock<Inner<C>>>,
}

impl<C> InMemoryLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
        }
    }
}

pub struct InMemoryLobbyTxn<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    inner: Arc<RwLock<Inner<C>>>,
    next_player_id: crate::engine::nl::types::PlayerId,
    next_shuffler_id: crate::ledger::types::ShufflerId,
    next_game_id: GameId,
    next_hand_id: HandId,
    next_hand_config_id: i64,
    players: Vec<(Vec<u8>, crate::engine::nl::types::PlayerId, StoredPlayer<C>)>,
    shufflers: Vec<(Vec<u8>, crate::ledger::types::ShufflerId, StoredShuffler<C>)>,
    games: Vec<(GameId, StoredGame)>,
    game_players: Vec<NewGamePlayer>,
    game_shufflers: Vec<NewGameShuffler<C>>,
    hand_configs: Vec<(i64, HandConfig)>,
    hands: Vec<(HandId, StoredHand)>,
    hand_players: Vec<NewHandPlayer>,
    hand_shufflers: Vec<NewHandShuffler>,
    snapshots: Vec<PreparedSnapshot>,
    committed: bool,
}

#[async_trait]
impl<C> LobbyStorage<C> for InMemoryLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    async fn begin(&self) -> Result<Box<dyn LobbyStorageTxn<C> + Send>, GameSetupError> {
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

impl<C> InMemoryLobbyTxn<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    fn next_player_id(&mut self) -> crate::engine::nl::types::PlayerId {
        let id = self.next_player_id;
        self.next_player_id += 1;
        id
    }

    fn next_shuffler_id(&mut self) -> crate::ledger::types::ShufflerId {
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

    fn lookup_player(&self, key_bytes: &[u8]) -> Option<StoredPlayer<C>> {
        if let Some((_, _, stored)) = self.players.iter().rev().find(|(k, _, _)| k.as_slice() == key_bytes) {
            return Some(stored.clone());
        }
        let inner = self.inner.read();
        let player_id = inner.players.get(key_bytes)?;
        inner.players_by_id.get(player_id).cloned()
    }

    fn lookup_player_by_id(&self, id: crate::engine::nl::types::PlayerId) -> Option<StoredPlayer<C>> {
        if let Some((_, pid, stored)) = self.players.iter().rev().find(|(_, pid, _)| *pid == id) {
            return Some(stored.clone());
        }
        let inner = self.inner.read();
        inner.players_by_id.get(&id).cloned()
    }

    fn lookup_shuffler(&self, key_bytes: &[u8]) -> Option<StoredShuffler<C>> {
        if let Some((_, _, stored)) = self.shufflers.iter().rev().find(|(k, _, _)| k.as_slice() == key_bytes) {
            return Some(stored.clone());
        }
        let inner = self.inner.read();
        let shuffler_id = inner.shufflers.get(key_bytes)?;
        inner.shufflers_by_id.get(shuffler_id).cloned()
    }

    fn lookup_shuffler_by_id(&self, id: crate::ledger::types::ShufflerId) -> Option<StoredShuffler<C>> {
        if let Some((_, sid, stored)) = self.shufflers.iter().rev().find(|(_, sid, _)| *sid == id) {
            return Some(stored.clone());
        }
        let inner = self.inner.read();
        inner.shufflers_by_id.get(&id).cloned()
    }
}

#[async_trait]
impl<C> LobbyStorageTxn<C> for InMemoryLobbyTxn<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    async fn load_player(
        &mut self,
        key: &CanonicalKey<C>,
    ) -> Result<Option<StoredPlayer<C>>, GameSetupError> {
        let key_bytes = serialize_curve_bytes(key.value())
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;
        Ok(self.lookup_player(&key_bytes))
    }

    async fn load_player_by_id(
        &mut self,
        id: crate::engine::nl::types::PlayerId,
    ) -> Result<Option<StoredPlayer<C>>, GameSetupError> {
        Ok(self.lookup_player_by_id(id))
    }

    async fn insert_player(&mut self, player: NewPlayer<C>) -> Result<(crate::engine::nl::types::PlayerId, CanonicalKey<C>), GameSetupError> {
        let key_bytes = serialize_curve_bytes(&player.public_key)
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let id = self.next_player_id();
        self.players.push((
            key_bytes,
            id,
            StoredPlayer {
                display_name: player.display_name,
                public_key: player.public_key.clone(),
            },
        ));
        Ok((id, CanonicalKey::new(player.public_key)))
    }

    async fn load_shuffler(
        &mut self,
        key: &CanonicalKey<C>,
    ) -> Result<Option<StoredShuffler<C>>, GameSetupError> {
        let key_bytes = serialize_curve_bytes(key.value())
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;
        Ok(self.lookup_shuffler(&key_bytes))
    }

    async fn load_shuffler_by_id(
        &mut self,
        id: crate::ledger::types::ShufflerId,
    ) -> Result<Option<StoredShuffler<C>>, GameSetupError> {
        Ok(self.lookup_shuffler_by_id(id))
    }

    async fn insert_shuffler(
        &mut self,
        shuffler: NewShuffler<C>,
    ) -> Result<(crate::ledger::types::ShufflerId, CanonicalKey<C>), GameSetupError> {
        let key_bytes = serialize_curve_bytes(&shuffler.public_key)
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let id = self.next_shuffler_id();
        self.shufflers.push((
            key_bytes,
            id,
            StoredShuffler {
                display_name: shuffler.display_name,
                public_key: shuffler.public_key.clone(),
            },
        ));
        Ok((id, CanonicalKey::new(shuffler.public_key)))
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

    async fn insert_game_shuffler(&mut self, row: NewGameShuffler<C>) -> Result<(), GameSetupError> {
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

        for (key_bytes, id, player) in self.players {
            inner.players.insert(key_bytes, id);
            inner.players_by_id.insert(id, player);
        }
        for (key_bytes, id, shuffler) in self.shufflers {
            inner.shufflers.insert(key_bytes, id);
            inner.shufflers_by_id.insert(id, shuffler);
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

impl<C> Default for InMemoryLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}
