-- Migration: Add voice channel flag and member role column
-- Run this against the PostgreSQL database used by the application

BEGIN;

-- Add is_voice to rooms
ALTER TABLE rooms
ADD COLUMN IF NOT EXISTS is_voice BOOLEAN DEFAULT false;

-- Add role to server_members
ALTER TABLE server_members
ADD COLUMN IF NOT EXISTS role VARCHAR(32) DEFAULT 'member';

COMMIT;

-- Notes:
--  - `is_voice` marks channels intended for voice (audio) use.
--  - `role` supports values like 'member', 'moderator', 'admin', 'owner'.
