BEGIN;
ALTER TABLE public.game_shufflers
    ADD COLUMN IF NOT EXISTS sequence SMALLINT;
UPDATE public.game_shufflers
SET sequence = 0
WHERE sequence IS NULL;
ALTER TABLE public.game_shufflers
    ALTER COLUMN sequence SET NOT NULL;
COMMIT;
