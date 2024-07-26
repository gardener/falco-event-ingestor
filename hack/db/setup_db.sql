-- Create roles
DO
$do$
BEGIN
   IF EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'gardener') THEN

      RAISE NOTICE 'Role "gardener" already exists. Skipping.';
   ELSE
      CREATE ROLE gardener LOGIN PASSWORD '';
   END IF;
END
$do$;

DO
$do$
BEGIN
   IF EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'gardener_rw') THEN

      RAISE NOTICE 'Role "gardener_rw" already exists. Skipping.';
   ELSE
      CREATE ROLE gardener_rw LOGIN PASSWORD '';
   END IF;
END
$do$;


-- Create Database
CREATE DATABASE falco OWNER gardener;
SELECT 'CREATE DATABASE falco'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'falco')\gexec

-- Create Table
\c falco;
CREATE TABLE IF NOT EXISTS falco_events (
    id BIGSERIAL PRIMARY KEY,
    landscape varchar(50),
    project varchar(50),
    cluster varchar(50),
    uuid uuid,
    hostname varchar(255),
    time timestamp,
    rule varchar(80),
    priority varchar(30),
    tags varchar(126),
    source varchar(50),
    message varchar(5000),
    output_fields jsonb
);

-- Create Index
CREATE INDEX IF NOT EXISTS project_index ON falco_events (project);
CREATE INDEX IF NOT EXISTS cluster_index ON falco_events (cluster);
CREATE INDEX IF NOT EXISTS uuid_index  ON falco_events (uuid);
CREATE INDEX IF NOT EXISTS hostname_index ON falco_events (hostname);
CREATE INDEX IF NOT EXISTS time_index ON falco_events (time);
CREATE INDEX IF NOT EXISTS rule_index ON falco_events (rule);
CREATE INDEX IF NOT EXISTS priority_index ON falco_events (priority);
CREATE INDEX IF NOT EXISTS tags_index ON falco_events (tags);
CREATE INDEX IF NOT EXISTS source_index ON falco_events (source);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON TABLE falco_events TO gardener_rw;
GRANT CONNECT ON DATABASE falco TO gardener_rw;
