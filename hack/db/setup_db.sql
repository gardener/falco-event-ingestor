-- CREATE DB
CREATE ROLE falco_master LOGIN password '';
CREATE ROLE falco_reader LOGIN password '';
CREATE ROLE falco_writer LOGIN password '';

CREATE DATABASE falco OWNER falco_master;
SELECT 'CREATE DATABASE falco'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'falco')\gexec

\c falco;
CREATE TABLE falco_events (
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
-- CREATE INDEX ON landscape
CREATE INDEX project_index ON falco_events (project);
CREATE INDEX cluster_index ON falco_events (cluster);
CREATE INDEX uuid_index ON falco_events (uuid);
CREATE INDEX hostname_index ON falco_events (hostname);
CREATE INDEX time_index ON falco_events (time);
CREATE INDEX rule_index ON falco_events (rule);
CREATE INDEX priority_index ON falco_events (priority);
CREATE INDEX tags_index ON falco_events (tags);
CREATE INDEX source_index ON falco_events (source);
-- We need additional permissions for the writer
GRANT ALL PRIVILEGES ON TABLE falco_events TO falco_writer;
GRANT ALL PRIVILEGES ON SEQUENCE falco_events_id_seq TO falco_writer;
