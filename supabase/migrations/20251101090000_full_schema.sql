BEGIN;

-- Enumerated types
CREATE TYPE public.hand_status AS ENUM (
    'pending',
    'shuffling',
    'dealing',
    'betting',
    'showdown',
    'complete',
    'cancelled'
);

CREATE TYPE public.phase_kind AS ENUM (
    'shuffling',
    'dealing',
    'betting',
    'reveals'
);

CREATE TYPE public.event_phase AS ENUM (
    'pending',
    'shuffling',
    'dealing',
    'betting',
    'reveals',
    'showdown',
    'complete',
    'cancelled'
);

CREATE TYPE public.game_status AS ENUM (
    'onboarding',
    'active',
    'closed',
    'archived'
);

CREATE TYPE public.application_status AS ENUM (
    'success',
    'failure'
);

-- Demo table used by examples
CREATE TABLE public.test (
    foo INTEGER PRIMARY KEY,
    bar INTEGER NOT NULL,
    baz INTEGER NOT NULL
);

ALTER TABLE public.test
    REPLICA IDENTITY FULL;

-- Core ledger entities
CREATE TABLE public.players (
    id BIGSERIAL PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.shufflers (
    id BIGSERIAL PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.games (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    host_player_id BIGINT NOT NULL REFERENCES public.players(id),
    name TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'chips',
    max_players SMALLINT NOT NULL,
    small_blind BIGINT NOT NULL CHECK (small_blind >= 0),
    big_blind BIGINT NOT NULL CHECK (big_blind >= 0),
    ante BIGINT NOT NULL DEFAULT 0 CHECK (ante >= 0),
    rake_bps SMALLINT NOT NULL DEFAULT 0,
    status public.game_status NOT NULL DEFAULT 'onboarding'
);

CREATE TABLE public.game_players (
    game_id BIGINT NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
    player_id BIGINT NOT NULL REFERENCES public.players(id),
    seat_preference SMALLINT,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (game_id, player_id)
);

CREATE TABLE public.game_shufflers (
    game_id BIGINT NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
    shuffler_id BIGINT NOT NULL REFERENCES public.shufflers(id),
    sequence SMALLINT NOT NULL,
    public_key BYTEA NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (game_id, shuffler_id)
);

CREATE TABLE public.hands (
    id BIGSERIAL PRIMARY KEY,
    game_id BIGINT NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hand_no BIGINT NOT NULL,
    button_seat SMALLINT NOT NULL,
    small_blind_seat SMALLINT NOT NULL,
    big_blind_seat SMALLINT NOT NULL,
    deck_commitment BYTEA,
    status public.hand_status NOT NULL DEFAULT 'pending',
    current_sequence INT NOT NULL DEFAULT 0,
    current_state_hash BYTEA,
    current_phase public.phase_kind,
    UNIQUE (game_id, hand_no),
    UNIQUE (id, game_id)
);

ALTER TABLE public.games
    ADD COLUMN current_hand_id BIGINT REFERENCES public.hands(id),
    ADD COLUMN current_state_hash BYTEA,
    ADD COLUMN current_phase public.phase_kind;

CREATE INDEX idx_games_status ON public.games(status);
CREATE INDEX idx_games_current_hand ON public.games(current_hand_id);
CREATE INDEX idx_hands_game_sequence ON public.hands(game_id, current_sequence);

CREATE TABLE public.hand_shufflers (
    hand_id BIGINT NOT NULL REFERENCES public.hands(id) ON DELETE CASCADE,
    shuffler_id BIGINT NOT NULL REFERENCES public.shufflers(id),
    sequence SMALLINT NOT NULL,
    PRIMARY KEY (hand_id, shuffler_id)
);

CREATE TABLE public.events (
    id BIGSERIAL PRIMARY KEY,
    game_id BIGINT NOT NULL REFERENCES public.games(id),
    hand_id BIGINT NOT NULL REFERENCES public.hands(id) ON DELETE CASCADE,
    entity_kind SMALLINT NOT NULL,
    entity_id BIGINT NOT NULL,
    actor_kind SMALLINT NOT NULL,
    seat_id SMALLINT,
    shuffler_id SMALLINT,
    public_key BYTEA NOT NULL,
    nonce BIGINT NOT NULL,
    phase public.event_phase NOT NULL,
    snapshot_number INTEGER NOT NULL,
    is_successful BOOLEAN NOT NULL,
    failure_message TEXT,
    resulting_phase public.event_phase NOT NULL,
    message_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    signature BYTEA NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hand_id, entity_kind, entity_id, nonce)
);

CREATE INDEX idx_events_hand_instant
    ON public.events(hand_id, inserted_at);

CREATE TABLE public.hand_player (
    id BIGSERIAL PRIMARY KEY,
    game_id BIGINT NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
    hand_id BIGINT NOT NULL REFERENCES public.hands(id) ON DELETE CASCADE,
    player_id BIGINT NOT NULL REFERENCES public.players(id),
    seat SMALLINT NOT NULL CHECK (seat >= 0),
    nonce BIGINT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hand_id, seat),
    UNIQUE (hand_id, player_id),
    FOREIGN KEY (game_id, player_id)
        REFERENCES public.game_players(game_id, player_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_hand_player_game_player
    ON public.hand_player(game_id, player_id);

CREATE TABLE public.hand_configs (
    id BIGSERIAL PRIMARY KEY,
    game_id BIGINT NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
    small_blind BIGINT NOT NULL CHECK (small_blind >= 0),
    big_blind BIGINT NOT NULL CHECK (big_blind >= 0),
    ante BIGINT NOT NULL DEFAULT 0 CHECK (ante >= 0),
    button_seat SMALLINT NOT NULL,
    small_blind_seat SMALLINT NOT NULL,
    big_blind_seat SMALLINT NOT NULL,
    check_raise_allowed BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hand_configs_game_created_at
    ON public.hand_configs(game_id, created_at DESC);

ALTER TABLE public.games
    ADD COLUMN default_hand_config_id BIGINT REFERENCES public.hand_configs(id);

ALTER TABLE public.hands
    ADD COLUMN hand_config_id BIGINT NOT NULL REFERENCES public.hand_configs(id);

CREATE TABLE public.phases (
    hash BYTEA PRIMARY KEY,
    phase_type public.phase_kind NOT NULL,
    payload JSONB NOT NULL,
    message_id BIGINT REFERENCES public.events(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_phases_type_created_at
    ON public.phases(phase_type, created_at DESC);
CREATE INDEX idx_phases_message_id
    ON public.phases(message_id);

CREATE TABLE public.table_snapshots (
    snapshot_hash BYTEA PRIMARY KEY,
    game_id BIGINT NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
    hand_id BIGINT NOT NULL REFERENCES public.hands(id) ON DELETE CASCADE,
    sequence INT NOT NULL CHECK (sequence >= 0),
    state_hash BYTEA NOT NULL,
    previous_hash BYTEA REFERENCES public.table_snapshots(snapshot_hash) ON DELETE SET NULL,
    hand_config_id BIGINT NOT NULL REFERENCES public.hand_configs(id),
    player_stacks JSONB NOT NULL,
    shuffling_hash BYTEA REFERENCES public.phases(hash) ON DELETE SET NULL,
    dealing_hash BYTEA REFERENCES public.phases(hash) ON DELETE SET NULL,
    betting_hash BYTEA REFERENCES public.phases(hash) ON DELETE SET NULL,
    reveals_hash BYTEA REFERENCES public.phases(hash) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    application_status public.application_status NOT NULL,
    failure_reason TEXT,
    UNIQUE (hand_id, sequence)
);

CREATE INDEX idx_table_snapshots_hand_seq
    ON public.table_snapshots(hand_id, sequence DESC);
CREATE INDEX idx_table_snapshots_game_seq
    ON public.table_snapshots(game_id, sequence DESC);

-- Supabase Realtime publications
ALTER PUBLICATION supabase_realtime ADD TABLE public.test;

ALTER PUBLICATION supabase_realtime ADD TABLE public.events;
ALTER TABLE public.events REPLICA IDENTITY FULL;

COMMIT;
