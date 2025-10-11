BEGIN;

-- Ensure phase_kind enum exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'phase_kind'
    ) THEN
        CREATE TYPE phase_kind AS ENUM ('shuffling', 'dealing', 'betting', 'reveals');
    END IF;
END;
$$;

-- Update game_status enum to the new lifecycle values
CREATE TYPE game_status_new AS ENUM ('onboarding', 'active', 'closed', 'archived');

ALTER TABLE games
    ALTER COLUMN status DROP DEFAULT,
    ALTER COLUMN status TYPE game_status_new USING
        CASE status::text
            WHEN 'open' THEN 'onboarding'
            WHEN 'completed' THEN 'closed'
            WHEN 'active' THEN 'active'
            WHEN 'archived' THEN 'archived'
            ELSE 'onboarding'
        END::game_status_new,
    ALTER COLUMN status SET DEFAULT 'onboarding';

DROP TYPE game_status;
ALTER TYPE game_status_new RENAME TO game_status;

-- Extend games with current snapshot metadata
ALTER TABLE games
    ADD COLUMN current_hand_id BIGINT REFERENCES hands(id),
    ADD COLUMN current_state_hash BYTEA,
    ADD COLUMN current_phase phase_kind;

CREATE INDEX IF NOT EXISTS idx_games_status ON games(status);
CREATE INDEX IF NOT EXISTS idx_games_current_hand ON games(current_hand_id);

-- Extend hands with snapshot tracking fields
ALTER TABLE hands
    ADD COLUMN current_sequence INT NOT NULL DEFAULT 0,
    ADD COLUMN current_state_hash BYTEA,
    ADD COLUMN current_phase phase_kind;

CREATE INDEX IF NOT EXISTS idx_hands_game_sequence ON hands(game_id, current_sequence);

-- Replace hand_seating with hand_player roster
DROP TABLE IF EXISTS hand_seating;

CREATE TABLE hand_player (
    id         BIGSERIAL PRIMARY KEY,
    game_id    BIGINT   NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    hand_id    BIGINT   NOT NULL REFERENCES hands(id) ON DELETE CASCADE,
    player_id  BIGINT   NOT NULL REFERENCES players(id),
    seat       SMALLINT NOT NULL CHECK (seat >= 0),
    nonce      BIGINT   NOT NULL,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hand_id, seat),
    UNIQUE (hand_id, player_id),
    FOREIGN KEY (game_id, player_id)
        REFERENCES game_players(game_id, player_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_hand_player_game_player ON hand_player(game_id, player_id);

-- Hand configuration snapshots
CREATE TABLE hand_configs (
    id                  BIGSERIAL PRIMARY KEY,
    game_id             BIGINT      NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    small_blind         BIGINT      NOT NULL CHECK (small_blind >= 0),
    big_blind           BIGINT      NOT NULL CHECK (big_blind >= 0),
    ante                BIGINT      NOT NULL DEFAULT 0 CHECK (ante >= 0),
    button_seat         SMALLINT    NOT NULL,
    small_blind_seat    SMALLINT    NOT NULL,
    big_blind_seat      SMALLINT    NOT NULL,
    check_raise_allowed BOOLEAN     NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hand_configs_game_created_at
    ON hand_configs(game_id, created_at DESC);

-- Phase payload deduplication
CREATE TABLE phases (
    hash        BYTEA PRIMARY KEY,
    phase_type  phase_kind NOT NULL,
    payload     JSONB NOT NULL,
    message_id  BIGINT REFERENCES events(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_phases_type_created_at
    ON phases(phase_type, created_at DESC);
CREATE INDEX idx_phases_message_id
    ON phases(message_id);

-- Table snapshot history
CREATE TABLE table_snapshots (
    snapshot_hash   BYTEA PRIMARY KEY,
    game_id         BIGINT NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    hand_id         BIGINT NOT NULL REFERENCES hands(id) ON DELETE CASCADE,
    sequence        INT    NOT NULL CHECK (sequence >= 0),
    state_hash      BYTEA  NOT NULL,
    previous_hash   BYTEA  REFERENCES table_snapshots(snapshot_hash) ON DELETE SET NULL,
    hand_config_id  BIGINT REFERENCES hand_configs(id) ON DELETE SET NULL,
    player_stacks   JSONB  NOT NULL,
    shuffling_hash  BYTEA  REFERENCES phases(hash) ON DELETE SET NULL,
    dealing_hash    BYTEA  REFERENCES phases(hash) ON DELETE SET NULL,
    betting_hash    BYTEA  REFERENCES phases(hash) ON DELETE SET NULL,
    reveals_hash    BYTEA  REFERENCES phases(hash) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hand_id, sequence)
);

CREATE INDEX idx_table_snapshots_hand_seq
    ON table_snapshots(hand_id, sequence DESC);
CREATE INDEX idx_table_snapshots_game_seq
    ON table_snapshots(game_id, sequence DESC);

COMMIT;
