BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'application_status'
    ) THEN
        CREATE TYPE application_status AS ENUM ('success', 'failure');
    END IF;
END;
$$;

ALTER TABLE table_snapshots
    ADD COLUMN IF NOT EXISTS application_status application_status NOT NULL DEFAULT 'success',
    ADD COLUMN IF NOT EXISTS failure_reason TEXT;

UPDATE table_snapshots
SET application_status = 'success'
WHERE application_status IS NULL;

ALTER TABLE table_snapshots
    ALTER COLUMN application_status DROP DEFAULT;

COMMIT;
