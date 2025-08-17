-- =============================================
-- ZK Poker Database Schema
-- =============================================

-- =============================================
-- 1. CREATE ENUM TYPES
-- =============================================

-- Room status enum
CREATE TYPE room_status AS ENUM (
    'waiting',
    'playing',
    'finished'
);

-- Actor type enum for transcript entries
CREATE TYPE actor_type AS ENUM (
    'player',
    'shuffler',
    'system'
);

-- Transcript category enum
CREATE TYPE transcript_category AS ENUM (
    'command',
    'event',
    'proof',
    'status'
);

-- Member role enum
CREATE TYPE member_role AS ENUM (
    'player',
    'spectator'
);

-- =============================================
-- 2. CREATE TABLES
-- =============================================

-- Rooms table - represents game rooms
CREATE TABLE rooms (
    room_id SERIAL PRIMARY KEY,
    status room_status NOT NULL DEFAULT 'waiting',
    seats INT NOT NULL DEFAULT 6,
    required_shufflers INT NOT NULL DEFAULT 5,
    owner_id TEXT,
    nonce TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Room members table - tracks players and spectators in rooms
CREATE TABLE room_members (
    room_id INT NOT NULL,
    user_id TEXT NOT NULL,
    role member_role NOT NULL DEFAULT 'player',
    seat INT,
    pk_player TEXT, -- Player's public key
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Primary key on composite
    PRIMARY KEY (room_id, user_id),

    -- Foreign key to rooms
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE,

    -- Unique constraint for seat assignment
    CONSTRAINT uq_room_seat UNIQUE (room_id, seat)
);

-- Room shufflers table - tracks shufflers assigned to rooms
CREATE TABLE room_shufflers (
    room_id INT NOT NULL,
    shuffler_id TEXT NOT NULL,
    pk_shuffle TEXT NOT NULL, -- Shuffler's public key
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Primary key on composite
    PRIMARY KEY (room_id, shuffler_id),

    -- Foreign key to rooms
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);

-- Transcripts table - event log for all game actions
CREATE TABLE transcripts (
    seq BIGSERIAL PRIMARY KEY,
    room_id INT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_type actor_type NOT NULL,
    actor_id TEXT NOT NULL,
    category transcript_category NOT NULL,
    kind TEXT NOT NULL,
    correlation_id TEXT NOT NULL, -- Links related events (e.g., game_id)
    idempotency_key TEXT,
    payload JSONB NOT NULL DEFAULT '{}',
    prev_hash TEXT, -- For chain verification
    hash TEXT, -- For chain verification

    -- Foreign key to rooms
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE,

    -- Unique constraint for idempotency
    CONSTRAINT uq_idem_command UNIQUE (room_id, actor_id, idempotency_key)
);

-- =============================================
-- 3. CREATE INDEXES
-- =============================================

-- Indexes on transcripts for efficient querying
CREATE INDEX idx_transcript_room_seq
    ON transcripts(room_id, seq);

CREATE INDEX idx_transcript_room_corr_seq
    ON transcripts(room_id, correlation_id, seq);

-- Additional useful indexes
CREATE INDEX idx_transcript_ts
    ON transcripts(ts DESC);

CREATE INDEX idx_transcript_actor
    ON transcripts(actor_type, actor_id);

CREATE INDEX idx_transcript_kind
    ON transcripts(kind);

CREATE INDEX idx_transcript_correlation
    ON transcripts(correlation_id);

-- Index on rooms for querying by status
CREATE INDEX idx_rooms_status
    ON rooms(status);

CREATE INDEX idx_rooms_created
    ON rooms(created_at DESC);

-- =============================================
-- 4. ENABLE ROW LEVEL SECURITY (RLS)
-- =============================================

-- Enable RLS on all tables
ALTER TABLE rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE room_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE room_shufflers ENABLE ROW LEVEL SECURITY;
ALTER TABLE transcripts ENABLE ROW LEVEL SECURITY;

-- =============================================
-- 5. CREATE RLS POLICIES
-- =============================================

-- Rooms policies
CREATE POLICY "Rooms are viewable by everyone"
    ON rooms FOR SELECT
    USING (true);

CREATE POLICY "Rooms can be created by anyone"
    ON rooms FOR INSERT
    WITH CHECK (true);

CREATE POLICY "Rooms can be updated by owner"
    ON rooms FOR UPDATE
    USING (true) -- Modify based on auth strategy
    WITH CHECK (true);

-- Room members policies
CREATE POLICY "Room members are viewable by everyone"
    ON room_members FOR SELECT
    USING (true);

CREATE POLICY "Room members can be added"
    ON room_members FOR INSERT
    WITH CHECK (true);

CREATE POLICY "Room members can be updated"
    ON room_members FOR UPDATE
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Room members can be removed"
    ON room_members FOR DELETE
    USING (true);

-- Room shufflers policies
CREATE POLICY "Room shufflers are viewable by everyone"
    ON room_shufflers FOR SELECT
    USING (true);

CREATE POLICY "Room shufflers can be added"
    ON room_shufflers FOR INSERT
    WITH CHECK (true);

-- Transcripts policies
CREATE POLICY "Transcripts are viewable by everyone"
    ON transcripts FOR SELECT
    USING (true);

CREATE POLICY "Transcripts can be created by anyone"
    ON transcripts FOR INSERT
    WITH CHECK (true);

-- Transcripts should be immutable after creation
-- No UPDATE or DELETE policies

-- =============================================
-- 6. ENABLE REALTIME
-- =============================================

-- Enable realtime for relevant tables
ALTER PUBLICATION supabase_realtime ADD TABLE rooms;
ALTER PUBLICATION supabase_realtime ADD TABLE room_members;
ALTER PUBLICATION supabase_realtime ADD TABLE room_shufflers;
ALTER PUBLICATION supabase_realtime ADD TABLE transcripts;

-- =============================================
-- 7. CREATE HELPER FUNCTIONS
-- =============================================

-- Function to get all events for a specific game
CREATE OR REPLACE FUNCTION get_game_events(p_correlation_id TEXT)
RETURNS SETOF transcripts
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM transcripts
    WHERE correlation_id = p_correlation_id
    ORDER BY seq ASC;
END;
$$;

-- Function to get the latest room status
CREATE OR REPLACE FUNCTION get_room_status(p_room_id INT)
RETURNS room_status
LANGUAGE plpgsql
AS $$
DECLARE
    v_status room_status;
BEGIN
    SELECT status INTO v_status
    FROM rooms
    WHERE room_id = p_room_id;

    RETURN v_status;
END;
$$;

-- Function to count active players in a room
CREATE OR REPLACE FUNCTION count_active_players(p_room_id INT)
RETURNS INT
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM room_members
    WHERE room_id = p_room_id
    AND role = 'player';

    RETURN COALESCE(v_count, 0);
END;
$$;

-- =============================================
-- 8. COMMENTS FOR DOCUMENTATION
-- =============================================

COMMENT ON TABLE rooms IS 'Game rooms where poker games are played';
COMMENT ON TABLE room_members IS 'Players and spectators in each room';
COMMENT ON TABLE room_shufflers IS 'Shuffler nodes assigned to each room';
COMMENT ON TABLE transcripts IS 'Immutable event log of all game actions';

COMMENT ON COLUMN rooms.nonce IS 'Random nonce for room verification';
COMMENT ON COLUMN room_members.pk_player IS 'Player public key for ZK operations';
COMMENT ON COLUMN room_shufflers.pk_shuffle IS 'Shuffler public key for ZK operations';
COMMENT ON COLUMN transcripts.correlation_id IS 'Links related events, typically game_id';
COMMENT ON COLUMN transcripts.prev_hash IS 'Hash of previous transcript for chain verification';
COMMENT ON COLUMN transcripts.hash IS 'Hash of current transcript for chain verification';
