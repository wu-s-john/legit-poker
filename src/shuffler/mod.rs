use anyhow::{anyhow, Result};
use ark_crypto_primitives::signature::{schnorr::Schnorr, SignatureScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::Sha256;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::{
    actor::{AnyActor, ShufflerActor},
    messages::{
        sign_enveloped_action, AnyGameMessage, AnyMessageEnvelope, EnvelopedMessage,
        GameBlindingDecryptionMessage, GamePartialUnblindingShareMessage, GameShuffleMessage,
        MetadataEnvelope, SignatureEncoder,
    },
    shuffler_signals::{
        BoardCardShufflerRequest, DealShufflerRequest, DealingPhaseStarted,
        PlayerCardShufflerRequest,
    },
    snapshot::TableAtShuffling,
    types::{GameId, HandId, ShufflerId},
};
use crate::shuffling::data_structures::ShuffleProof;
use crate::shuffling::{
    bayer_groth::decomposition::random_permutation as bg_random_permutation,
    shuffle_and_rerandomize_random, CommunityDecryptionShare, ElGamalCiphertext,
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    DECK_SIZE,
};
use crate::signing::WithSignature;

pub type Deck<C, const N: usize> = [ElGamalCiphertext<C>; N];

pub type ShufflerScheme<C> = Schnorr<C, Sha256>;

const LOG_TARGET: &str = "game::shuffler";

#[derive(Clone, Debug)]
pub struct ShufflerKeypair<C: CurveGroup> {
    pub index: usize,
    pub secret_key: C::ScalarField,
    pub public_key: C,
    pub aggregated_public_key: C,
}

impl<C> ShufflerKeypair<C>
where
    C: CurveGroup,
{
    pub(crate) fn new(
        index: usize,
        secret_key: C::ScalarField,
        public_key: C,
        aggregated_public_key: C,
    ) -> Self {
        Self {
            index,
            secret_key,
            public_key,
            aggregated_public_key,
        }
    }
}

pub trait ShufflerApi<C: CurveGroup> {
    /// Receives an encrypted deck and returns a shuffled, re-encrypted deck with proof
    fn shuffle<const N: usize, R: Rng>(
        &self,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<(Deck<C, N>, ShuffleProof<C>)>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField;

    /// Provides a player-targeted blinding contribution + proof (for later combination)
    fn provide_blinding_player_decryption_share<R: Rng>(
        &self,
        player_public_key: C,
        rng: &mut R,
    ) -> Result<PlayerTargetedBlindingContribution<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>;

    /// Provides a PartialUnblinding share for a player’s ciphertext (n-of-n)
    fn provide_unblinding_decryption_share(
        &self,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
    ) -> Result<PartialUnblindingShare<C>>
    where
        C::ScalarField: PrimeField;

    /// Provides a CommunityDecryptionShare + proof for a community card (n-of-n)
    fn provide_community_decryption_share<R: Rng>(
        &self,
        ciphertext: &ElGamalCiphertext<C>,
        rng: &mut R,
    ) -> Result<CommunityDecryptionShare<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C: CurveAbsorb<C::BaseField>;
}

impl<C> ShufflerApi<C> for ShufflerKeypair<C>
where
    C: CurveGroup,
{
    fn shuffle<const N: usize, R: Rng>(
        &self,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<(Deck<C, N>, ShuffleProof<C>)>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField,
    {
        // Draw a random permutation using existing utility
        let perm_vec = bg_random_permutation(N, rng);
        let permutation: [usize; N] = core::array::from_fn(|i| perm_vec[i]);

        // Shuffle and re-randomize with the aggregated public key
        let (output_deck, rerands) = shuffle_and_rerandomize_random(
            input_deck,
            &permutation,
            self.aggregated_public_key,
            rng,
        );
        let input_vec = input_deck.to_vec();
        let sorted_pairs = output_deck
            .iter()
            .cloned()
            .map(|cipher| (cipher, C::BaseField::zero()))
            .collect();
        let rerand_vec = rerands.to_vec();
        let proof = ShuffleProof::new(input_vec, sorted_pairs, rerand_vec)
            .map_err(|err| anyhow!("failed to construct shuffle proof: {err}"))?;
        Ok((output_deck, proof))
    }

    fn provide_blinding_player_decryption_share<R: Rng>(
        &self,
        player_public_key: C,
        rng: &mut R,
    ) -> Result<PlayerTargetedBlindingContribution<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>,
    {
        // Use the shuffler's long-term secret as the blinding share δ_j.
        // This avoids introducing extra bounds (UniformRand) here and matches the requested trait signature.
        let delta_j = self.secret_key;

        let contribution = crate::shuffling::player_decryption::native::PlayerTargetedBlindingContribution::generate(
            delta_j,
            self.aggregated_public_key,
            player_public_key,
            rng,
        );
        Ok(contribution)
    }

    fn provide_unblinding_decryption_share(
        &self,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
    ) -> Result<PartialUnblindingShare<C>>
    where
        C::ScalarField: PrimeField,
    {
        // μ_{u,j} = A_u^{x_j}; index is self.index
        let share = crate::shuffling::generate_committee_decryption_share(
            player_ciphertext,
            self.secret_key,
            self.index,
        );
        Ok(share)
    }

    fn provide_community_decryption_share<R: Rng>(
        &self,
        ciphertext: &ElGamalCiphertext<C>,
        rng: &mut R,
    ) -> Result<CommunityDecryptionShare<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C: CurveAbsorb<C::BaseField>,
    {
        let share = crate::shuffling::CommunityDecryptionShare::generate(
            ciphertext,
            self.secret_key,
            self.index,
            rng,
        );
        Ok(share)
    }
}

#[derive(Clone, Debug)]
pub struct ShufflerRunConfig {
    pub rng_seed: [u8; 32],
    pub message_history_cap: usize,
}

impl ShufflerRunConfig {
    pub fn new(rng_seed: [u8; 32]) -> Self {
        Self {
            rng_seed,
            message_history_cap: 64,
        }
    }

    pub fn with_message_history_cap(mut self, cap: usize) -> Self {
        self.message_history_cap = cap;
        self
    }
}

#[derive(Debug)]
pub struct ShufflingHandState<C: CurveGroup> {
    pub expected_order: Vec<ShufflerId>,
    pub buffered: Vec<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    pub next_nonce: u64,
    pub turn_index: usize,
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub latest_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub acted: bool,
    pub rng: StdRng,
}

impl<C: CurveGroup> ShufflingHandState<C> {
    fn is_complete(&self) -> bool {
        self.buffered.len() >= self.expected_order.len()
    }
}
#[derive(Debug)]
struct HandRuntime<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub cancel: CancellationToken,
    pub state: Mutex<ShufflingHandState<C>>,
}

pub struct Shuffler<C, S>
where
    C: CurveGroup,
    S: SignatureScheme,
{
    index: usize,
    shuffler_id: ShufflerId,
    public_key: C,
    params: Arc<S::Parameters>,
    secret_key: Arc<S::SecretKey>,
    api: Arc<ShufflerKeypair<C>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    states: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
    deal_handles: Arc<DashMap<(GameId, HandId), JoinHandle<()>>>,
    rng: Mutex<StdRng>,
    config: ShufflerRunConfig,
}

impl<C, S> Shuffler<C, S>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::ScalarField: PrimeField + Absorb,
    S: SignatureScheme<PublicKey = C::Affine>,
{
    pub fn new(
        index: usize,
        shuffler_id: ShufflerId,
        public_key: C,
        aggregated_public_key: C,
        shuffle_secret: C::ScalarField,
        params: S::Parameters,
        secret_key: S::SecretKey,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        config: ShufflerRunConfig,
    ) -> Self {
        let rng = StdRng::from_seed(config.rng_seed);
        let api = Arc::new(ShufflerKeypair::new(
            index,
            shuffle_secret,
            public_key.clone(),
            aggregated_public_key.clone(),
        ));
        Self {
            index,
            shuffler_id,
            public_key,
            params: Arc::new(params),
            secret_key: Arc::new(secret_key),
            api,
            submit,
            states: Arc::new(DashMap::new()),
            deal_handles: Arc::new(DashMap::new()),
            rng: Mutex::new(rng),
            config,
        }
    }

    pub fn shuffler_id(&self) -> ShufflerId {
        self.shuffler_id
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn cancel_all(&self) {
        let mut keys = Vec::new();
        for entry in self.states.iter() {
            entry.value().cancel.cancel();
            keys.push(*entry.key());
        }
        for key in keys {
            self.states.remove(&key);
            if let Some((_, handle)) = self.deal_handles.remove(&key) {
                handle.abort();
            }
        }
    }

    pub async fn subscribe_per_hand(
        &self,
        game_id: GameId,
        hand_id: HandId,
        turn_index: usize,
        snapshot: &TableAtShuffling<C>,
        shuffle_updates: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    ) -> Result<HandSubscription<C, S>>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync,
        C::BaseField: PrimeField + Send + Sync,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
        S::Parameters: Send + Sync + 'static,
        S::SecretKey: Send + Sync + 'static,
    {
        let key = (game_id, hand_id);
        if self.states.contains_key(&key) {
            return Err(anyhow!(
                "hand {} for game {} already registered on shuffler {}",
                hand_id,
                game_id,
                self.shuffler_id
            ));
        }

        let mut global_rng = self.rng.lock();
        let mut hand_seed = [0u8; 32];
        global_rng.fill_bytes(&mut hand_seed);
        drop(global_rng);

        let expected_order = snapshot.shuffling.expected_order.clone();
        if expected_order.is_empty() {
            return Err(anyhow!(
                "hand {} for game {} has empty shuffler order",
                hand_id,
                game_id
            ));
        }
        if turn_index >= expected_order.len() {
            return Err(anyhow!(
                "turn index {} out of range ({} shufflers) for hand {}",
                turn_index,
                expected_order.len(),
                hand_id
            ));
        }

        let initial_deck = snapshot.shuffling.initial_deck.clone();
        let latest_deck = snapshot.shuffling.initial_deck.clone();
        let next_nonce = u64::from(snapshot.sequence);

        let state = ShufflingHandState {
            expected_order,
            buffered: Vec::new(),
            next_nonce,
            turn_index,
            initial_deck,
            latest_deck,
            acted: false,
            rng: StdRng::from_seed(hand_seed),
        };

        let cancel = CancellationToken::new();
        let runtime = Arc::new(HandRuntime {
            game_id,
            hand_id,
            cancel: cancel.clone(),
            state: Mutex::new(state),
        });

        let states = Arc::clone(&self.states);
        if states.insert(key, Arc::clone(&runtime)).is_some() {
            return Err(anyhow!(
                "hand {} for game {} already registered on shuffler {}",
                hand_id,
                game_id,
                self.shuffler_id
            ));
        }

        info!(
            target = LOG_TARGET,
            game_id,
            hand_id,
            shuffler_id = self.shuffler_id,
            turn_index,
            "registered hand subscription"
        );

        let api = Arc::clone(&self.api);
        let params = Arc::clone(&self.params);
        let secret = Arc::clone(&self.secret_key);
        let submit = self.submit.clone();
        let public_key = self.public_key.clone();
        let actor = ShufflerActor {
            shuffler_id: self.shuffler_id,
        };
        let history_cap = self.config.message_history_cap;
        let handle = Self::spawn_shuffle_loop(
            self.index,
            api.clone(),
            params.clone(),
            secret.clone(),
            submit.clone(),
            Arc::clone(&runtime),
            shuffle_updates,
            history_cap,
            public_key.clone(),
            actor,
        );

        Ok(HandSubscription::new(
            key,
            self.shuffler_id,
            self.index,
            Arc::clone(&self.states),
            Arc::clone(&self.deal_handles),
            cancel,
            handle,
            submit,
            api,
            params,
            secret,
            public_key,
        ))
    }

    pub async fn kick_start_hand(&self, game_id: GameId, hand_id: HandId) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        let key = (game_id, hand_id);
        let runtime_arc = {
            let entry = self
                .states
                .get(&key)
                .ok_or_else(|| anyhow!("hand {} for game {} not registered", hand_id, game_id))?;
            let runtime = Arc::clone(entry.value());
            drop(entry);
            runtime
        };

        {
            let state = runtime_arc.state.lock();
            if state.turn_index != 0 {
                return Err(anyhow!(
                    "shuffler {} cannot kick start hand {} turn index {}",
                    self.shuffler_id,
                    hand_id,
                    state.turn_index
                ));
            }
        }

        Self::emit_shuffle(
            &self.api,
            &self.params,
            &self.secret_key,
            &self.submit,
            &runtime_arc,
            &self.public_key,
            ShufflerActor {
                shuffler_id: self.shuffler_id,
            },
        )
        .await
    }

    fn spawn_shuffle_loop(
        shuffler_index: usize,
        api: Arc<ShufflerKeypair<C>>,
        params: Arc<S::Parameters>,
        secret: Arc<S::SecretKey>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: Arc<HandRuntime<C>>,
        shuffle_updates: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
        history_cap: usize,
        public_key: C,
        actor: ShufflerActor,
    ) -> JoinHandle<()>
    where
        C: Send + Sync + 'static,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + 'static,
        C::BaseField: PrimeField + Send + Sync + 'static,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
        S::Parameters: Send + Sync + 'static,
        S::SecretKey: Send + Sync + 'static,
    {
        tokio::spawn(async move {
            let game_id = runtime.game_id;
            let hand_id = runtime.hand_id;
            if let Err(err) = Self::shuffle_loop(
                api,
                params,
                secret,
                submit,
                Arc::clone(&runtime),
                shuffle_updates,
                history_cap,
                public_key,
                actor,
                shuffler_index,
            )
            .await
            {
                warn!(
                    target = LOG_TARGET,
                    game_id,
                    hand_id,
                    shuffler_index,
                    error = %err,
                    "shuffle loop exited with error"
                );
            } else {
                debug!(
                    target = LOG_TARGET,
                    game_id, hand_id, shuffler_index, "shuffle loop finished"
                );
            }
        })
    }

    async fn shuffle_loop(
        api: Arc<ShufflerKeypair<C>>,
        params: Arc<S::Parameters>,
        secret: Arc<S::SecretKey>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: Arc<HandRuntime<C>>,
        mut updates: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
        history_cap: usize,
        public_key: C,
        actor: ShufflerActor,
        shuffler_index: usize,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        loop {
            tokio::select! {
                _ = runtime.cancel.cancelled() => {
                    debug!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        shuffler_index,
                        "cancellation token triggered; stopping shuffle loop"
                    );
                    break;
                }
                msg = updates.recv() => {
                    match msg {
                        Ok(envelope) => {
                            let should_emit = Self::record_incoming(&runtime, &envelope, history_cap);
                            if should_emit {
                                if let Err(err) = Self::emit_shuffle(
                                    &api,
                                    &params,
                                    &secret,
                                    &submit,
                                    &runtime,
                                    &public_key,
                                    actor,
                                )
                                .await
                                {
                                    error!(
                                        target = LOG_TARGET,
                                        game_id = runtime.game_id,
                                        hand_id = runtime.hand_id,
                                        shuffler_index,
                                        error = %err,
                                        "failed to emit shuffle message"
                                    );
                                    break;
                                }
                            }

                            let is_complete = {
                                let state = runtime.state.lock();
                                state.is_complete()
                            };
                            if is_complete {
                                info!(
                                    target = LOG_TARGET,
                                    game_id = runtime.game_id,
                                    hand_id = runtime.hand_id,
                                    shuffler_index,
                                    "shuffling complete; exiting shuffle loop"
                                );
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                skipped,
                                "lagged on realtime updates"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                "realtime channel closed"
                            );
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn deal_loop(
        runtime: Arc<HandRuntime<C>>,
        mut updates: broadcast::Receiver<DealShufflerRequest<C>>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        api: Arc<ShufflerKeypair<C>>,
        params: Arc<S::Parameters>,
        secret: Arc<S::SecretKey>,
        public_key: C,
        actor: ShufflerActor,
        shuffler_index: usize,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        loop {
            tokio::select! {
                _ = runtime.cancel.cancelled() => {
                    debug!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        shuffler_index,
                        "deal loop cancellation triggered"
                    );
                    break;
                }
                update = updates.recv() => {
                    match update {
                        Ok(request) => {
                            if let Err(err) = Self::process_deal_request(
                                &runtime,
                                request,
                                &submit,
                                &api,
                                &params,
                                &secret,
                                &public_key,
                                actor,
                            ).await {
                                warn!(
                                    target = LOG_TARGET,
                                    game_id = runtime.game_id,
                                    hand_id = runtime.hand_id,
                                    shuffler_index,
                                    error = %err,
                                    "failed to process deal request"
                                );
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                skipped,
                                "lagged on deal requests"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                "deal request channel closed"
                            );
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_deal_request(
        runtime: &Arc<HandRuntime<C>>,
        request: DealShufflerRequest<C>,
        submit: &mpsc::Sender<AnyMessageEnvelope<C>>,
        api: &Arc<ShufflerKeypair<C>>,
        params: &Arc<S::Parameters>,
        secret: &Arc<S::SecretKey>,
        public_key: &C,
        actor: ShufflerActor,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        C: CurveAbsorb<C::BaseField>,
        C::Affine: Absorb,
        C::ScalarField: Absorb,
        S::Signature: SignatureEncoder,
    {
        match request {
            DealShufflerRequest::Player(req) => {
                Self::handle_player_request(
                    runtime, req, submit, api, params, secret, public_key, actor,
                )
                .await
            }
            DealShufflerRequest::Board(req) => {
                Self::handle_board_request(
                    runtime, req, submit, api, params, secret, public_key, actor,
                )
                .await
            }
        }
    }

    async fn handle_player_request(
        runtime: &Arc<HandRuntime<C>>,
        request: PlayerCardShufflerRequest<C>,
        submit: &mpsc::Sender<AnyMessageEnvelope<C>>,
        api: &Arc<ShufflerKeypair<C>>,
        params: &Arc<S::Parameters>,
        secret: &Arc<S::SecretKey>,
        public_key: &C,
        actor: ShufflerActor,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        C: CurveAbsorb<C::BaseField>,
        C::Affine: Absorb,
        C::ScalarField: Absorb,
        S::Signature: SignatureEncoder,
    {
        if request.game_id != runtime.game_id || request.hand_id != runtime.hand_id {
            warn!(
                target = LOG_TARGET,
                expected_game = runtime.game_id,
                expected_hand = runtime.hand_id,
                request_game = request.game_id,
                request_hand = request.hand_id,
                "received player deal request for mismatched hand"
            );
            return Ok(());
        }

        let (blinding_envelope, unblinding_envelope) = {
            let mut state = runtime.state.lock();
            let player_public_key = request.player_public_key.clone();
            let contribution = api
                .provide_blinding_player_decryption_share(player_public_key.clone(), &mut state.rng)
                .map_err(|err| anyhow!("failed to compute blinding contribution: {err}"))?;
            let blinding_msg = GameBlindingDecryptionMessage::new(
                request.deal_index,
                contribution,
                player_public_key.clone(),
            );
            let blinding_envelope = Self::sign_blinding_envelope(
                &mut state,
                runtime,
                params,
                secret,
                public_key,
                actor,
                blinding_msg,
            )?;

            let partial_share = api
                .provide_unblinding_decryption_share(&request.ciphertext)
                .map_err(|err| anyhow!("failed to compute partial unblinding share: {err}"))?;
            let unblinding_msg = GamePartialUnblindingShareMessage::new(
                request.deal_index,
                partial_share,
                player_public_key,
            );
            let unblinding_envelope = Self::sign_partial_unblinding_envelope(
                &mut state,
                runtime,
                params,
                secret,
                public_key,
                actor,
                unblinding_msg,
            )?;

            (blinding_envelope, unblinding_envelope)
        };

        debug!(
            target = LOG_TARGET,
            game_id = runtime.game_id,
            hand_id = runtime.hand_id,
            shuffler_id = actor.shuffler_id,
            deal_index = request.deal_index,
            seat = request.seat,
            hole_index = request.hole_index,
            player_key = ?request.player_public_key,
            "submitting player blinding and unblinding shares"
        );

        submit
            .send(blinding_envelope)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        submit
            .send(unblinding_envelope)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;

        info!(
            target = LOG_TARGET,
            game_id = runtime.game_id,
            hand_id = runtime.hand_id,
            shuffler_id = actor.shuffler_id,
            deal_index = request.deal_index,
            seat = request.seat,
            hole_index = request.hole_index,
            "submitted player blinding and unblinding shares"
        );

        Ok(())
    }

    async fn handle_board_request(
        runtime: &Arc<HandRuntime<C>>,
        request: BoardCardShufflerRequest<C>,
        _submit: &mpsc::Sender<AnyMessageEnvelope<C>>,
        _api: &Arc<ShufflerKeypair<C>>,
        _params: &Arc<S::Parameters>,
        _secret: &Arc<S::SecretKey>,
        _public_key: &C,
        actor: ShufflerActor,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        if request.game_id != runtime.game_id || request.hand_id != runtime.hand_id {
            warn!(
                target = LOG_TARGET,
                expected_game = runtime.game_id,
                expected_hand = runtime.hand_id,
                request_game = request.game_id,
                request_hand = request.hand_id,
                "received board deal request for mismatched hand"
            );
            return Ok(());
        }

        // TODO: emit community decryption share once ledger message type is defined.
        debug!(
            target = LOG_TARGET,
            game_id = runtime.game_id,
            hand_id = runtime.hand_id,
            shuffler_id = actor.shuffler_id,
            deal_index = request.deal_index,
            ?request.slot,
            "board deal requests are not yet supported"
        );
        Ok(())
    }

    fn sign_blinding_envelope(
        state: &mut ShufflingHandState<C>,
        runtime: &HandRuntime<C>,
        params: &Arc<S::Parameters>,
        secret: &Arc<S::SecretKey>,
        public_key: &C,
        actor: ShufflerActor,
        message: GameBlindingDecryptionMessage<C>,
    ) -> Result<AnyMessageEnvelope<C>>
    where
        S::Signature: SignatureEncoder,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
    {
        let meta = MetadataEnvelope {
            hand_id: runtime.hand_id,
            game_id: runtime.game_id,
            actor,
            nonce: state.next_nonce,
            public_key: public_key.clone(),
        };

        let signed = sign_enveloped_action::<S, C, GameBlindingDecryptionMessage<C>, _>(
            meta,
            message,
            params,
            secret,
            &mut state.rng,
        )?;

        state.next_nonce = state.next_nonce.saturating_add(1);

        Ok(Self::wrap_blinding_envelope(actor.shuffler_id, signed))
    }

    fn sign_partial_unblinding_envelope(
        state: &mut ShufflingHandState<C>,
        runtime: &HandRuntime<C>,
        params: &Arc<S::Parameters>,
        secret: &Arc<S::SecretKey>,
        public_key: &C,
        actor: ShufflerActor,
        message: GamePartialUnblindingShareMessage<C>,
    ) -> Result<AnyMessageEnvelope<C>>
    where
        S::Signature: SignatureEncoder,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
    {
        let meta = MetadataEnvelope {
            hand_id: runtime.hand_id,
            game_id: runtime.game_id,
            actor,
            nonce: state.next_nonce,
            public_key: public_key.clone(),
        };

        let signed = sign_enveloped_action::<S, C, GamePartialUnblindingShareMessage<C>, _>(
            meta,
            message,
            params,
            secret,
            &mut state.rng,
        )?;

        state.next_nonce = state.next_nonce.saturating_add(1);

        Ok(Self::wrap_partial_unblinding_envelope(
            actor.shuffler_id,
            signed,
        ))
    }

    fn record_incoming(
        runtime: &HandRuntime<C>,
        envelope: &EnvelopedMessage<C, GameShuffleMessage<C>>,
        history_cap: usize,
    ) -> bool {
        let mut state = runtime.state.lock();
        if envelope.hand_id != runtime.hand_id || envelope.game_id != runtime.game_id {
            return false;
        }
        if state.is_complete() {
            return false;
        }

        let position = state.buffered.len();
        if let Some(expected) = state.expected_order.get(position) {
            if *expected != envelope.actor.shuffler_id {
                warn!(
                    target = LOG_TARGET,
                    game_id = runtime.game_id,
                    hand_id = runtime.hand_id,
                    expected = *expected,
                    actual = envelope.actor.shuffler_id,
                    "incoming shuffle actor mismatch"
                );
            }
        }

        state.latest_deck = envelope.message.value.deck_out.clone();
        state.buffered.push(envelope.clone());
        if state.buffered.len() > history_cap {
            let drop_count = state.buffered.len() - history_cap;
            state.buffered.drain(0..drop_count);
        }
        state.next_nonce = state.next_nonce.max(envelope.nonce.saturating_add(1));

        !state.acted && state.buffered.len() == state.turn_index
    }

    async fn emit_shuffle(
        api: &Arc<ShufflerKeypair<C>>,
        params: &Arc<S::Parameters>,
        secret: &Arc<S::SecretKey>,
        submit: &mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: &Arc<HandRuntime<C>>,
        public_key: &C,
        actor: ShufflerActor,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        let (envelope_for_state, deck_out_state, nonce_for_update) = {
            let mut state = runtime.state.lock();
            if state.is_complete() || state.acted {
                return Ok(());
            }

            let position = state.buffered.len();
            if let Some(expected) = state.expected_order.get(position) {
                if *expected != actor.shuffler_id {
                    warn!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        expected = *expected,
                        actual = actor.shuffler_id,
                        "attempted to emit shuffle out of turn"
                    );
                    return Ok(());
                }
            }

            let deck_in = state.latest_deck.clone();
            let (deck_out, proof) = api.shuffle(&deck_in, &mut state.rng)?;
            let turn_index = u16::try_from(state.turn_index)
                .map_err(|_| anyhow!("turn index overflow for shuffle message"))?;
            let message =
                GameShuffleMessage::new(deck_in.clone(), deck_out.clone(), proof, turn_index);

            let meta = MetadataEnvelope {
                hand_id: runtime.hand_id,
                game_id: runtime.game_id,
                actor,
                nonce: state.next_nonce,
                public_key: public_key.clone(),
            };

            let signed = sign_enveloped_action::<S, C, GameShuffleMessage<C>, _>(
                meta,
                message,
                params,
                secret,
                &mut state.rng,
            )?;

            let deck_out_state = signed.message.value.deck_out.clone();
            let nonce = state.next_nonce;

            (signed, deck_out_state, nonce)
        };

        let any_envelope = Self::wrap_any_envelope(actor.shuffler_id, &envelope_for_state);
        submit
            .send(any_envelope)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;

        {
            let mut state = runtime.state.lock();
            state.next_nonce = nonce_for_update.saturating_add(1);
            state.latest_deck = deck_out_state;
            // History is updated via record_incoming when the broadcasted envelope arrives.
            state.acted = true;
        }

        info!(
            target = LOG_TARGET,
            game_id = runtime.game_id,
            hand_id = runtime.hand_id,
            shuffler_id = actor.shuffler_id,
            "emitted shuffle message"
        );

        Ok(())
    }

    fn wrap_any_envelope(
        shuffler_id: ShufflerId,
        envelope: &EnvelopedMessage<C, GameShuffleMessage<C>>,
    ) -> AnyMessageEnvelope<C> {
        let signed = envelope.message.clone();
        AnyMessageEnvelope {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor: AnyActor::Shuffler { shuffler_id },
            nonce: envelope.nonce,
            public_key: envelope.public_key,
            message: WithSignature {
                value: AnyGameMessage::Shuffle(signed.value),
                signature: signed.signature,
                transcript: signed.transcript,
            },
        }
    }

    fn wrap_blinding_envelope(
        shuffler_id: ShufflerId,
        envelope: EnvelopedMessage<C, GameBlindingDecryptionMessage<C>>,
    ) -> AnyMessageEnvelope<C> {
        let WithSignature {
            value,
            signature,
            transcript,
        } = envelope.message;

        AnyMessageEnvelope {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor: AnyActor::Shuffler { shuffler_id },
            nonce: envelope.nonce,
            public_key: envelope.public_key,
            message: WithSignature {
                value: AnyGameMessage::Blinding(value),
                signature,
                transcript,
            },
        }
    }

    fn wrap_partial_unblinding_envelope(
        shuffler_id: ShufflerId,
        envelope: EnvelopedMessage<C, GamePartialUnblindingShareMessage<C>>,
    ) -> AnyMessageEnvelope<C> {
        let WithSignature {
            value,
            signature,
            transcript,
        } = envelope.message;

        AnyMessageEnvelope {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor: AnyActor::Shuffler { shuffler_id },
            nonce: envelope.nonce,
            public_key: envelope.public_key,
            message: WithSignature {
                value: AnyGameMessage::PartialUnblinding(value),
                signature,
                transcript,
            },
        }
    }
}

fn spawn_deal_loop<C, S>(
    shuffler_index: usize,
    runtime: Arc<HandRuntime<C>>,
    updates: broadcast::Receiver<DealShufflerRequest<C>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    api: Arc<ShufflerKeypair<C>>,
    params: Arc<S::Parameters>,
    secret: Arc<S::SecretKey>,
    public_key: C,
    actor: ShufflerActor,
    handles: Arc<DashMap<(GameId, HandId), JoinHandle<()>>>,
    key: (GameId, HandId),
) -> JoinHandle<()>
where
    C: CurveGroup + Send + Sync + 'static,
    C::Config: CurveConfig<ScalarField = C::ScalarField>,
    C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + 'static + Absorb,
    C::BaseField: PrimeField + Send + Sync + 'static,
    C: CurveAbsorb<C::BaseField>,
    C::Affine: Absorb,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::Signature: SignatureEncoder + Send + Sync + 'static,
    S::Parameters: Send + Sync + 'static,
    S::SecretKey: Send + Sync + 'static,
{
    tokio::spawn(async move {
        let result = Shuffler::<C, S>::deal_loop(
            runtime.clone(),
            updates,
            submit,
            api,
            params,
            secret,
            public_key,
            actor,
            shuffler_index,
        )
        .await;

        if let Err(err) = result {
            warn!(
                target = LOG_TARGET,
                game_id = runtime.game_id,
                hand_id = runtime.hand_id,
                shuffler_index,
                error = %err,
                "deal loop exited with error"
            );
        } else {
            debug!(
                target = LOG_TARGET,
                game_id = runtime.game_id,
                hand_id = runtime.hand_id,
                shuffler_index,
                "deal loop finished"
            );
        }

        handles.remove(&key);
    })
}

pub struct HandSubscription<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
{
    key: (GameId, HandId),
    shuffler_id: ShufflerId,
    shuffler_index: usize,
    map: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
    deal_handles: Arc<DashMap<(GameId, HandId), JoinHandle<()>>>,
    cancel: CancellationToken,
    handle: Option<JoinHandle<()>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    api: Arc<ShufflerKeypair<C>>,
    params: Arc<S::Parameters>,
    secret: Arc<S::SecretKey>,
    public_key: C,
}

impl<C, S> HandSubscription<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
{
    fn new(
        key: (GameId, HandId),
        shuffler_id: ShufflerId,
        shuffler_index: usize,
        map: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
        deal_handles: Arc<DashMap<(GameId, HandId), JoinHandle<()>>>,
        cancel: CancellationToken,
        handle: JoinHandle<()>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        api: Arc<ShufflerKeypair<C>>,
        params: Arc<S::Parameters>,
        secret: Arc<S::SecretKey>,
        public_key: C,
    ) -> Self {
        Self {
            key,
            shuffler_id,
            shuffler_index,
            map,
            deal_handles,
            cancel,
            handle: Some(handle),
            submit,
            api,
            params,
            secret,
            public_key,
        }
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub(crate) fn shuffler_id(&self) -> ShufflerId {
        self.shuffler_id
    }

    pub(crate) fn handle_dealing_phase_started(
        &self,
        signal: &DealingPhaseStarted<C>,
        updates: broadcast::Receiver<DealShufflerRequest<C>>,
    ) -> Result<()>
    where
        C: Send + Sync + 'static,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + Absorb,
        C::BaseField: PrimeField + Send + Sync,
        C: CurveAbsorb<C::BaseField>,
        C::Affine: Absorb,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
        S::Parameters: Send + Sync + 'static,
        S::SecretKey: Send + Sync + 'static,
    {
        if signal.game_id != self.key.0 || signal.hand_id != self.key.1 {
            return Ok(());
        }
        if !signal.shufflers.iter().any(|&id| id == self.shuffler_id) {
            return Ok(());
        }

        let runtime = {
            let entry = self.map.get(&self.key).ok_or_else(|| {
                anyhow!("hand {} for game {} not registered", self.key.1, self.key.0)
            })?;
            Arc::clone(entry.value())
        };

        let actor = ShufflerActor {
            shuffler_id: self.shuffler_id,
        };
        let handle = spawn_deal_loop::<C, S>(
            self.shuffler_index,
            runtime,
            updates,
            self.submit.clone(),
            Arc::clone(&self.api),
            Arc::clone(&self.params),
            Arc::clone(&self.secret),
            self.public_key.clone(),
            actor,
            Arc::clone(&self.deal_handles),
            self.key,
        );

        if let Some(previous) = self.deal_handles.insert(self.key, handle) {
            previous.abort();
        }

        info!(
            target = LOG_TARGET,
            game_id = self.key.0,
            hand_id = self.key.1,
            shuffler_id = self.shuffler_id,
            "registered dealing phase listener"
        );

        Ok(())
    }
}

impl<C, S> Drop for HandSubscription<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
{
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        self.map.remove(&self.key);
        if let Some((_, handle)) = self.deal_handles.remove(&self.key) {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::shuffler_signals::BoardCardSlot;
    use crate::shuffling::{
        combine_blinding_contributions_for_player, decrypt_community_card,
        generate_random_ciphertexts, make_global_public_keys, recover_card_value,
    };
    use ark_ec::AffineRepr;
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;
    use std::collections::BTreeMap;
    use tokio::time::{timeout, Duration};

    const N_SHUFFLERS: usize = 3;
    const DECK_N: usize = 52;

    #[test]
    fn test_shuffle_and_player_targeted_recovery() {
        let mut rng = test_rng();

        // Build shufflers from random secrets
        let mut secrets = Vec::with_capacity(N_SHUFFLERS);
        let mut public_keys = Vec::with_capacity(N_SHUFFLERS);
        for _ in 0..N_SHUFFLERS {
            let secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = GrumpkinProjective::generator() * secret;
            secrets.push(secret);
            public_keys.push(public_key);
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());
        let shufflers: Vec<_> = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .enumerate()
            .map(|(idx, (secret, public_key))| {
                ShufflerKeypair::new(idx, secret, public_key, aggregated_public_key.clone())
            })
            .collect();

        let agg_pk = aggregated_public_key.clone();

        // Generate an initial encrypted deck using the aggregated public key
        let (mut deck, _r) =
            generate_random_ciphertexts::<GrumpkinProjective, DECK_N>(&agg_pk, &mut rng);

        // Sequentially shuffle across all shufflers
        for s in &shufflers {
            let (next_deck, _proof) = s.shuffle(&deck, &mut rng).expect("shuffle");
            deck = next_deck;
        }

        // Choose a safe card index (avoid last which could map to 52)
        let card_index = 10usize; // expected value = 11
        let card_ct = deck[card_index].clone();

        // Player keys
        let player_sk = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let player_pk = GrumpkinProjective::generator() * player_sk;

        // Each shuffler provides a blinding contribution for this player
        let mut contributions = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let c = s
                .provide_blinding_player_decryption_share(player_pk, &mut rng)
                .expect("blinding share");
            contributions.push(c);
        }

        // Combine into a player-accessible ciphertext
        let player_ciphertext =
            combine_blinding_contributions_for_player(&card_ct, &contributions, agg_pk, player_pk)
                .expect("combine blinding contributions");

        // Each shuffler provides partial unblinding
        let mut unblinding_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let u = s
                .provide_unblinding_decryption_share(&player_ciphertext)
                .expect("unblinding share");
            unblinding_shares.push(u);
        }

        // Recover card value via player-targeted path
        let recovered = recover_card_value::<GrumpkinProjective>(
            &player_ciphertext,
            player_sk,
            unblinding_shares,
            N_SHUFFLERS,
        )
        .expect("recover card value");

        // Also derive expected value via community decryption of the same post-shuffle ciphertext
        let mut comm_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            comm_shares.push(
                s.provide_community_decryption_share(&card_ct, &mut rng)
                    .expect("community share"),
            );
        }
        let expected_value =
            decrypt_community_card::<GrumpkinProjective>(&card_ct, comm_shares, N_SHUFFLERS)
                .expect("community decrypt");

        // Player-targeted recovery should match community decryption result
        assert_eq!(recovered, expected_value);
    }

    #[test]
    fn test_community_decryption_flow() {
        let mut rng = test_rng();

        let mut secrets = Vec::with_capacity(N_SHUFFLERS);
        let mut public_keys = Vec::with_capacity(N_SHUFFLERS);
        for _ in 0..N_SHUFFLERS {
            let secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = GrumpkinProjective::generator() * secret;
            secrets.push(secret);
            public_keys.push(public_key);
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());
        let shufflers: Vec<_> = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .enumerate()
            .map(|(idx, (secret, public_key))| {
                ShufflerKeypair::new(idx, secret, public_key, aggregated_public_key.clone())
            })
            .collect();
        let agg_pk = aggregated_public_key;

        // Encrypt a community card with known value in [0..51]
        let card_value: u8 = 25;
        let message = <GrumpkinProjective as PrimeGroup>::ScalarField::from(card_value as u64);
        let msg_point = GrumpkinProjective::generator() * message;
        let randomness = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let ciphertext = ElGamalCiphertext::encrypt(msg_point, randomness, agg_pk);

        // Collect community decryption shares from all shufflers
        let mut shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let share = s
                .provide_community_decryption_share(&ciphertext, &mut rng)
                .expect("community share");
            shares.push(share);
        }

        // Decrypt using all shares (n-of-n)
        let recovered =
            decrypt_community_card::<GrumpkinProjective>(&ciphertext, shares, N_SHUFFLERS)
                .expect("community decrypt");
        assert_eq!(recovered, card_value);
    }

    #[tokio::test]
    async fn deal_loop_handles_player_request() {
        type Curve = GrumpkinProjective;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEFu64);
        let shuffle_secret = <Curve as PrimeGroup>::ScalarField::rand(&mut rng);
        let shuffle_public = Curve::generator() * shuffle_secret;

        let schnorr_params = ShufflerScheme::<Curve>::setup(&mut rng).expect("schnorr params");
        let (sign_pk, sign_sk) =
            ShufflerScheme::<Curve>::keygen(&schnorr_params, &mut rng).expect("schnorr keygen");

        let (submit_tx, mut submit_rx) = mpsc::channel(8);
        let shuffler = Shuffler::<Curve, ShufflerScheme<Curve>>::new(
            0,
            0,
            sign_pk.into_group(),
            shuffle_public,
            shuffle_secret,
            schnorr_params,
            sign_sk,
            submit_tx,
            ShufflerRunConfig::new([1u8; 32]),
        );

        let key = (11i64, 22i64);
        let zero_cipher = ElGamalCiphertext::new(Curve::generator(), Curve::generator());
        let deck: [ElGamalCiphertext<Curve>; DECK_SIZE] =
            core::array::from_fn(|_| zero_cipher.clone());
        let runtime = Arc::new(HandRuntime {
            game_id: key.0,
            hand_id: key.1,
            cancel: CancellationToken::new(),
            state: Mutex::new(ShufflingHandState {
                expected_order: vec![0],
                buffered: Vec::new(),
                next_nonce: 0,
                turn_index: 0,
                initial_deck: deck.clone(),
                latest_deck: deck,
                acted: false,
                rng: StdRng::seed_from_u64(0xABCDu64),
            }),
        });
        shuffler.states.insert(key, Arc::clone(&runtime));

        let (deal_tx, _) = broadcast::channel(8);
        let start_signal = DealingPhaseStarted {
            game_id: key.0,
            hand_id: key.1,
            shuffle_tip_hash: Default::default(),
            shufflers: vec![0],
            card_plan: BTreeMap::new(),
            assignments: BTreeMap::new(),
        };
        let dummy_handle = tokio::spawn(async {});
        let subscription = HandSubscription::<Curve, ShufflerScheme<Curve>>::new(
            key,
            0,
            0,
            Arc::clone(&shuffler.states),
            Arc::clone(&shuffler.deal_handles),
            runtime.cancel.clone(),
            dummy_handle,
            shuffler.submit.clone(),
            Arc::clone(&shuffler.api),
            Arc::clone(&shuffler.params),
            Arc::clone(&shuffler.secret_key),
            shuffler.public_key.clone(),
        );
        subscription
            .handle_dealing_phase_started(&start_signal, deal_tx.subscribe())
            .expect("register dealing loop");

        let ciphertext = PlayerAccessibleCiphertext {
            blinded_base: Curve::generator(),
            blinded_message_with_player_key: Curve::generator(),
            player_unblinding_helper: Curve::generator(),
            shuffler_proofs: Vec::new(),
        };
        let request = PlayerCardShufflerRequest {
            game_id: key.0,
            hand_id: key.1,
            deal_index: 0,
            seat: 3,
            hole_index: 0,
            player_public_key: Curve::generator(),
            ciphertext,
        };
        deal_tx
            .send(DealShufflerRequest::Player(request))
            .expect("send player request");

        let first = timeout(Duration::from_secs(1), submit_rx.recv())
            .await
            .expect("wait blinding")
            .expect("blinding message");
        matches!(first.message.value, AnyGameMessage::Blinding(_))
            .then_some(())
            .expect("expected blinding message");

        let second = timeout(Duration::from_secs(1), submit_rx.recv())
            .await
            .expect("wait partial")
            .expect("partial message");
        matches!(second.message.value, AnyGameMessage::PartialUnblinding(_))
            .then_some(())
            .expect("expected partial unblinding message");

        runtime.cancel.cancel();
        shuffler.cancel_all();
    }

    #[tokio::test]
    async fn deal_loop_board_request_no_output() {
        type Curve = GrumpkinProjective;

        let mut rng = StdRng::seed_from_u64(0xFACEu64);
        let shuffle_secret = <Curve as PrimeGroup>::ScalarField::rand(&mut rng);
        let shuffle_public = Curve::generator() * shuffle_secret;

        let schnorr_params = ShufflerScheme::<Curve>::setup(&mut rng).expect("schnorr params");
        let (sign_pk, sign_sk) =
            ShufflerScheme::<Curve>::keygen(&schnorr_params, &mut rng).expect("schnorr keygen");

        let (submit_tx, mut submit_rx) = mpsc::channel(4);
        let shuffler = Shuffler::<Curve, ShufflerScheme<Curve>>::new(
            0,
            0,
            sign_pk.into_group(),
            shuffle_public,
            shuffle_secret,
            schnorr_params,
            sign_sk,
            submit_tx,
            ShufflerRunConfig::new([2u8; 32]),
        );

        let key = (5i64, 6i64);
        let zero_cipher = ElGamalCiphertext::new(Curve::zero(), Curve::zero());
        let deck = core::array::from_fn(|_| zero_cipher.clone());
        let runtime = Arc::new(HandRuntime {
            game_id: key.0,
            hand_id: key.1,
            cancel: CancellationToken::new(),
            state: Mutex::new(ShufflingHandState {
                expected_order: vec![0],
                buffered: Vec::new(),
                next_nonce: 0,
                turn_index: 0,
                initial_deck: deck.clone(),
                latest_deck: deck,
                acted: false,
                rng: StdRng::seed_from_u64(0xEEEEu64),
            }),
        });
        shuffler.states.insert(key, Arc::clone(&runtime));

        let (deal_tx, _) = broadcast::channel(4);
        let start_signal = DealingPhaseStarted {
            game_id: key.0,
            hand_id: key.1,
            shuffle_tip_hash: Default::default(),
            shufflers: vec![0],
            card_plan: BTreeMap::new(),
            assignments: BTreeMap::new(),
        };
        let dummy_handle = tokio::spawn(async {});
        let subscription = HandSubscription::<Curve, ShufflerScheme<Curve>>::new(
            key,
            0,
            0,
            Arc::clone(&shuffler.states),
            Arc::clone(&shuffler.deal_handles),
            runtime.cancel.clone(),
            dummy_handle,
            shuffler.submit.clone(),
            Arc::clone(&shuffler.api),
            Arc::clone(&shuffler.params),
            Arc::clone(&shuffler.secret_key),
            shuffler.public_key.clone(),
        );
        subscription
            .handle_dealing_phase_started(&start_signal, deal_tx.subscribe())
            .expect("register dealing loop");

        let board_request = BoardCardShufflerRequest {
            game_id: key.0,
            hand_id: key.1,
            deal_index: 7,
            slot: BoardCardSlot::Flop(0),
            ciphertext: ElGamalCiphertext::new(Curve::generator(), Curve::generator()),
        };
        deal_tx
            .send(DealShufflerRequest::Board(board_request))
            .expect("send board request");

        assert!(timeout(Duration::from_millis(100), submit_rx.recv())
            .await
            .is_err());

        runtime.cancel.cancel();
        shuffler.cancel_all();
    }
}
