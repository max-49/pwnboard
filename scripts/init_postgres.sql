CREATE USER grafana_user WITH PASSWORD 'password';

-- 2. Grant Read-Only access to the pwnboard_db
GRANT CONNECT ON DATABASE pwnboard_db TO grafana_user;
GRANT USAGE ON SCHEMA public TO grafana_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_user;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO grafana_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO grafana_user;