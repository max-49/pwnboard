CREATE USER metabase_user WITH PASSWORD 'password';

-- 1. Create the database and explicitly make metabase_user the owner
CREATE DATABASE metabase_db OWNER metabase_user;

-- 2. Grant Read-Only access to the pwnboard_db
GRANT CONNECT ON DATABASE pwnboard_db TO metabase_user;
GRANT USAGE ON SCHEMA public TO metabase_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO metabase_user;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO metabase_user;
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO metabase_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO metabase_user;