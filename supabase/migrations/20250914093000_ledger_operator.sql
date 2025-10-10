BEGIN;

-- Enum types
CREATE TYPE game_status AS ENUM ('open','active','completed','archived');
CREATE TYPE hand_status AS ENUM ('pending','shuffling','dealing','betting','showdown','complete','cancelled');

-- Participants
CREATE TABLE players (
    id            BIGSERIAL PRIMARY KEY,
    display_name  TEXT        NOT NULL,
    public_key    BYTEA       NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE shufflers (
    id            BIGSERIAL PRIMARY KEY,
    display_name  TEXT        NOT NULL,
    public_key    BYTEA       NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Games and membership
CREATE TABLE games (
    id             BIGSERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    host_player_id BIGINT      NOT NULL REFERENCES players(id),
    name           TEXT        NOT NULL,
    currency       TEXT        NOT NULL DEFAULT 'chips',
    max_players    SMALLINT    NOT NULL,
    small_blind    BIGINT      NOT NULL CHECK (small_blind >= 0),
    big_blind      BIGINT      NOT NULL CHECK (big_blind >= 0),
    ante           BIGINT      NOT NULL DEFAULT 0 CHECK (ante >= 0),
    rake_bps       SMALLINT    NOT NULL DEFAULT 0,
    status         game_status NOT NULL DEFAULT 'open'
);

CREATE TABLE game_players (
    game_id         BIGINT      NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    player_id       BIGINT      NOT NULL REFERENCES players(id),
    seat_preference SMALLINT,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (game_id, player_id)
);

CREATE TABLE game_shufflers (
    game_id     BIGINT      NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    shuffler_id BIGINT      NOT NULL REFERENCES shufflers(id),
    sequence    SMALLINT    NOT NULL,
    public_key  BYTEA       NOT NULL,
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (game_id, shuffler_id)
);

-- Hands
CREATE TABLE hands (
    id               BIGSERIAL PRIMARY KEY,
    game_id          BIGINT      NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hand_no          BIGINT      NOT NULL,
    button_seat      SMALLINT    NOT NULL,
    small_blind_seat SMALLINT    NOT NULL,
    big_blind_seat   SMALLINT    NOT NULL,
    deck_commitment  BYTEA,
    status           hand_status NOT NULL DEFAULT 'pending',
    UNIQUE (game_id, hand_no),
    UNIQUE (id, game_id)
);

CREATE TABLE hand_seating (
    hand_id           BIGINT      NOT NULL REFERENCES hands(id) ON DELETE CASCADE,
    game_id           BIGINT      NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    seat              SMALLINT    NOT NULL,
    player_id         BIGINT      NOT NULL,
    player_public_key BYTEA       NOT NULL,
    starting_stack    BIGINT      NOT NULL CHECK (starting_stack >= 0),
    PRIMARY KEY (hand_id, seat),
    UNIQUE (hand_id, player_id),
    FOREIGN KEY (game_id, player_id) REFERENCES game_players(game_id, player_id) ON DELETE CASCADE
);

CREATE TABLE hand_shufflers (
    hand_id     BIGINT   NOT NULL REFERENCES hands(id) ON DELETE CASCADE,
    shuffler_id BIGINT   NOT NULL REFERENCES shufflers(id),
    sequence    SMALLINT NOT NULL,
    PRIMARY KEY (hand_id, shuffler_id)
);

-- Event log
CREATE TABLE events (
    id           BIGSERIAL PRIMARY KEY,
    hand_id      BIGINT      NOT NULL REFERENCES hands(id) ON DELETE CASCADE,
    entity_kind  SMALLINT    NOT NULL,
    entity_id    BIGINT      NOT NULL,
    actor_kind   SMALLINT    NOT NULL,
    seat_id      SMALLINT,
    shuffler_id  SMALLINT,
    public_key   BYTEA       NOT NULL,
    nonce        BIGINT      NOT NULL,
    phase        hand_status NOT NULL,
    message_type TEXT        NOT NULL,
    payload      JSONB       NOT NULL,
    signature    BYTEA       NOT NULL,
    inserted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hand_id, entity_kind, entity_id, nonce)
);

-- Indexes
CREATE INDEX idx_hands_game_status ON hands (game_id, status);
CREATE INDEX idx_events_hand_instant ON events (hand_id, inserted_at);
CREATE INDEX idx_hand_seating_game_seat ON hand_seating (hand_id, seat);
CREATE INDEX idx_hand_seating_game_player ON hand_seating (hand_id, player_id);

COMMIT;
