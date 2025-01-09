// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"

	mymetrics "github.com/gardener/falco-event-ingestor/pkg/metrics"
)

type ClusterIdentity struct {
	project   string
	cluster   string
	uuid      string
	landscape string
}

type PostgresConfig struct {
	user              string
	password          string
	host              string
	port              int
	dbname            string
	dbpool            *pgxpool.Pool
	retentionDuration time.Duration
}

type EventStruct struct {
	Uuid         string                     `json:"uuid"`
	Output       string                     `json:"output"`
	Priority     string                     `json:"priority"`
	Rule         string                     `json:"rule"`
	Time         time.Time                  `json:"time"`
	OutputFields map[string]json.RawMessage `json:"output_fields"`
	Source       string                     `json:"source"`
	Tags         json.RawMessage            `json:"tags"`
	Hostname     string                     `json:"hostname"`
}

func NewPostgresConfig(user, password, host string, port int, dbname string, retentionDays int) *PostgresConfig {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s", host, port, user, password, dbname)

	retentionDuration, err := time.ParseDuration(fmt.Sprintf("%dh", retentionDays*24))
	if err != nil {
		log.Fatalf("Could not parse event retention days %v", err)
	}

	config, err := pgxpool.ParseConfig(connStr)

	if err != nil {
		log.Fatalf("Unable to parse database connection string: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v", err)
	}

	if pingErr := pool.Ping(context.Background()); pingErr != nil {
		log.Fatalf("Unable to ping database: %v", pingErr)
	}

	log.Info("Connection to database succeded")

	return &PostgresConfig{
		user:              user,
		password:          password,
		host:              host,
		port:              port,
		dbname:            dbname,
		dbpool:            pool,
		retentionDuration: retentionDuration,
	}
}

func (c *PostgresConfig) SetPassword(password string) {
	c.password = password
}

func parseClusterId(event EventStruct) (*ClusterIdentity, error) {
	clusterId, err := json.Marshal(event.OutputFields["cluster_id"])
	if err != nil {
		return nil, err
	}

	clusterIdString, err := strconv.Unquote(string(clusterId))
	if err != nil {
		return nil, err
	}

	re := `^shoot--([\w-]+)--([\w-]+)-([a-fA-F\d]{8}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{12})-([\w-]+)$`
	r := regexp.MustCompile(re)
	match := r.FindStringSubmatch(clusterIdString)
	if match == nil {
		return nil, errors.New("cluster id does not match pattern")
	}

	return &ClusterIdentity{
		project:   match[1],
		cluster:   match[2],
		uuid:      match[3],
		landscape: match[4],
	}, nil
}

func (pgconf *PostgresConfig) Insert(events []EventStruct) error {
	rows := make([][]interface{}, len(events))
	for i, event := range events {
		clusterIdentity, err := parseClusterId(event)
		if err != nil {
			errStr := fmt.Sprintf("Error parsing cluster id: %s", err)
			log.Error(errStr)
			continue
		}

		outputJson, err := json.Marshal(event.OutputFields)
		if err != nil {
			errStr := fmt.Sprintf("Error marshalling output fields: %s", err)
			log.Error(errStr)
			continue
		}

		rows[i] = []interface{}{
			clusterIdentity.landscape,
			clusterIdentity.project,
			clusterIdentity.cluster,
			clusterIdentity.uuid,
			event.Hostname,
			event.Time,
			event.Rule,
			event.Priority,
			event.Tags,
			event.Source,
			event.Output,
			outputJson,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := pgconf.dbpool.CopyFrom(
		ctx,
		pgx.Identifier{"falco_events"},
		[]string{
			"landscape",
			"project",
			"cluster",
			"uuid",
			"hostname",
			"time",
			"rule",
			"priority",
			"tags",
			"source",
			"message",
			"output_fields",
		},
		pgx.CopyFromRows(rows),
	)

	if err != nil {
		return fmt.Errorf("failed to insert events: %w", err)
	}

	mymetrics.InsertSuccess.Add(float64(len(events)))
	log.Infof("Inserted %d events", len(events))
	return nil
}

func (pgconf *PostgresConfig) CheckHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pgconf.dbpool.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	rows, err := pgconf.dbpool.Query(ctx, `SELECT version()`)
	if err != nil {
		return fmt.Errorf("failed to run test query: %w", err)
	}
	defer rows.Close()

	return nil
}

func (pgconf *PostgresConfig) DeleteRows() error {
	log.Infof("Deleting rows older than %s", pgconf.retentionDuration)

	sql, args := buildDeleteStatement(pgconf.retentionDuration)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	res, err := pgconf.dbpool.Exec(ctx, sql, args...)
	if err != nil {
		log.Errorf("Delete query failed: %v", err)
		return err
	}

	rowsNum := res.RowsAffected()
	log.Infof("Deleted %d rows", rowsNum)
	return nil
}

func buildDeleteStatement(maxAge time.Duration) (string, []interface{}) {
	maxTime := time.Now().UTC().Add(-maxAge)

	sb := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	sb.DeleteFrom("falco_events")
	sb.Where(sb.LessThan("time", maxTime))

	sql, args := sb.Build()
	return sql, args
}
