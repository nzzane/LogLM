-- ══════════════════════════════════════════════════════════════════════════
-- Migration: convert events / firewall_flows / snmp_metrics to partitioned
-- tables. Run ONCE on an existing install; fresh installs get partitions
-- from init.sql.
--
-- Strategy per table:
--   1. Rename old table → _old
--   2. Create new partitioned table with same columns
--   3. Create initial partitions
--   4. INSERT ... SELECT from _old (batched by month)
--   5. Drop _old
--
-- WARNING: this locks the tables briefly during rename. Schedule during a
-- maintenance window. The processor should be stopped.
-- ══════════════════════════════════════════════════════════════════════════

BEGIN;

-- ── events ─────────────────────────────────────────────────────────────────
DO $migrate_events$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'events' AND c.relkind = 'r' AND n.nspname = 'public'
    ) THEN
        RAISE NOTICE 'migrating events to partitioned table...';
        ALTER TABLE events RENAME TO events_old;
        ALTER INDEX IF EXISTS idx_events_timestamp RENAME TO idx_events_timestamp_old;
        ALTER INDEX IF EXISTS idx_events_ts_brin RENAME TO idx_events_ts_brin_old;

        CREATE SEQUENCE IF NOT EXISTS events_id_seq;
        SELECT setval('events_id_seq', COALESCE((SELECT MAX(id) FROM events_old), 1));

        CREATE TABLE events (
            id          BIGINT NOT NULL DEFAULT nextval('events_id_seq'),
            timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            host        TEXT NOT NULL,
            source      TEXT NOT NULL,
            severity    TEXT NOT NULL,
            program     TEXT,
            message     TEXT NOT NULL,
            structured  JSONB DEFAULT '{}',
            verdict     TEXT NOT NULL,
            event_hash  BYTEA
        ) PARTITION BY RANGE (timestamp);

        ALTER SEQUENCE events_id_seq OWNED BY events.id;

        CREATE INDEX idx_events_ts_brin     ON events USING BRIN (timestamp) WITH (pages_per_range = 32);
        CREATE INDEX idx_events_host        ON events (host);
        CREATE INDEX idx_events_host_ts     ON events (host, timestamp DESC);
        CREATE INDEX idx_events_structured  ON events USING GIN (structured jsonb_path_ops);
        CREATE INDEX idx_events_msg_trgm    ON events USING GIN (message gin_trgm_ops);
        CREATE UNIQUE INDEX uq_events_hash  ON events (event_hash, timestamp) WHERE event_hash IS NOT NULL;

        SELECT create_monthly_partitions('events', 2);

        INSERT INTO events SELECT * FROM events_old;

        DROP TABLE events_old CASCADE;
        RAISE NOTICE 'events migration complete';
    ELSE
        RAISE NOTICE 'events already partitioned or missing, skipping';
    END IF;
END $migrate_events$;


-- ── firewall_flows ─────────────────────────────────────────────────────────
DO $migrate_ff$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'firewall_flows' AND c.relkind = 'r' AND n.nspname = 'public'
    ) THEN
        RAISE NOTICE 'migrating firewall_flows to partitioned table...';
        ALTER TABLE firewall_flows RENAME TO firewall_flows_old;

        CREATE SEQUENCE IF NOT EXISTS firewall_flows_id_seq;
        SELECT setval('firewall_flows_id_seq', COALESCE((SELECT MAX(id) FROM firewall_flows_old), 1));

        CREATE TABLE firewall_flows (
            id              BIGINT NOT NULL DEFAULT nextval('firewall_flows_id_seq'),
            timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            host            TEXT NOT NULL,
            action          TEXT NOT NULL,
            blocked         BOOLEAN NOT NULL DEFAULT FALSE,
            direction       TEXT,
            src_ip          INET,
            dst_ip          INET,
            src_port        INT,
            dst_port        INT,
            proto           TEXT,
            in_iface        TEXT,
            out_iface       TEXT,
            port_name       TEXT,
            concerning      BOOLEAN NOT NULL DEFAULT FALSE,
            concerning_reasons TEXT[] NOT NULL DEFAULT '{}',
            event_id        BIGINT
        ) PARTITION BY RANGE (timestamp);

        ALTER SEQUENCE firewall_flows_id_seq OWNED BY firewall_flows.id;

        CREATE INDEX idx_ff_ts_brin    ON firewall_flows USING BRIN (timestamp) WITH (pages_per_range = 32);
        CREATE INDEX idx_ff_host       ON firewall_flows (host, timestamp DESC);
        CREATE INDEX idx_ff_src        ON firewall_flows (src_ip);
        CREATE INDEX idx_ff_dst_port   ON firewall_flows (dst_port) WHERE blocked;
        CREATE INDEX idx_ff_concerning ON firewall_flows (timestamp DESC) WHERE concerning;

        SELECT create_monthly_partitions('firewall_flows', 2);

        INSERT INTO firewall_flows SELECT * FROM firewall_flows_old;

        DROP TABLE firewall_flows_old CASCADE;
        RAISE NOTICE 'firewall_flows migration complete';
    ELSE
        RAISE NOTICE 'firewall_flows already partitioned or missing, skipping';
    END IF;
END $migrate_ff$;


-- ── snmp_metrics ───────────────────────────────────────────────────────────
DO $migrate_snmp$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'snmp_metrics' AND c.relkind = 'r' AND n.nspname = 'public'
    ) THEN
        RAISE NOTICE 'migrating snmp_metrics to partitioned table...';
        ALTER TABLE snmp_metrics RENAME TO snmp_metrics_old;

        CREATE SEQUENCE IF NOT EXISTS snmp_metrics_id_seq;
        SELECT setval('snmp_metrics_id_seq', COALESCE((SELECT MAX(id) FROM snmp_metrics_old), 1));

        CREATE TABLE snmp_metrics (
            id              BIGINT NOT NULL DEFAULT nextval('snmp_metrics_id_seq'),
            timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            host            TEXT NOT NULL,
            sys_name        TEXT,
            avg_cpu         REAL,
            wifi_clients    INT,
            interfaces_up   INT,
            interfaces_down INT,
            total_in_bps    REAL,
            total_out_bps   REAL,
            total_errors    REAL,
            raw_data        JSONB DEFAULT '{}'
        ) PARTITION BY RANGE (timestamp);

        ALTER SEQUENCE snmp_metrics_id_seq OWNED BY snmp_metrics.id;

        CREATE INDEX idx_snmp_ts_brin  ON snmp_metrics USING BRIN (timestamp) WITH (pages_per_range = 32);
        CREATE INDEX idx_snmp_host_ts  ON snmp_metrics (host, timestamp DESC);

        SELECT create_monthly_partitions('snmp_metrics', 2);

        INSERT INTO snmp_metrics SELECT * FROM snmp_metrics_old;

        DROP TABLE snmp_metrics_old CASCADE;
        RAISE NOTICE 'snmp_metrics migration complete';
    ELSE
        RAISE NOTICE 'snmp_metrics already partitioned or missing, skipping';
    END IF;
END $migrate_snmp$;

COMMIT;
