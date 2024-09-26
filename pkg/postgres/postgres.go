// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/huandu/go-sqlbuilder"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

const INSERT_STATEMENT = "INSERT INTO falco_events(landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"

var REQUIRED_FIELDS = []string{"landscape", "project", "cluster", "uuid", "hostname", "time", "rule", "priority", "tags", "source"}

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
	db                *sql.DB
	stmt              *sql.Stmt
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
	log.Infof("Trying connection: host=%s port=%d user=%s password=%s dbname=%s", host, port, user, "******", dbname)

	retentionDuration, err := time.ParseDuration(fmt.Sprintf("%dh", retentionDays * 24))
	if err != nil {
		log.Fatalf("Could not parse event retention days %v", err)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}

	db.SetConnMaxLifetime(0)
	db.SetMaxIdleConns(3)
	db.SetMaxOpenConns(10)
	stmt, err := prepareInsert(db)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Connection to database succeded")
	log.Info(password)

	postgresConfigInstance := PostgresConfig{
		user:              user,
		password:          password,
		host:              host,
		port:              port,
		dbname:            dbname,
		db:                db,
		stmt:              stmt,
		retentionDuration: retentionDuration,
	}

	go postgresConfigInstance.DeleteLoop(time.Second*60)

	return &postgresConfigInstance
}

func (c *PostgresConfig) SetPassword(password string) {
	c.password = password
}

func parseClusterId(event *EventStruct) (*ClusterIdentity, error) {
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

func prepareInsert(db *sql.DB) (*sql.Stmt, error) {
	stmt, err := db.Prepare(INSERT_STATEMENT)
	if err != nil {
		return nil, fmt.Errorf("could not prepare sql statement: %s due to error: %s", INSERT_STATEMENT, err.Error())
	}
	return stmt, nil
}

func (pgconf *PostgresConfig) DeleteLoop(frequency time.Duration) {
	for {
		sql, args := buildDeleteStatement(pgconf.retentionDuration)

		// --------------------------- DO NOT ENABLE YET----------------------------
		fmt.Println(sql)
		fmt.Println(args...)
		// _, err := pgconf.db.Query(sql, args...)
		// if err != nil {
		// 	log.Errorf("Delete query failed: %v", err)
		// }
		// --------------------------- DO NOT ENABLE YET----------------------------

		time.Sleep(frequency)
	}
}

func (pgconf *PostgresConfig) Insert(event *EventStruct) {
	clusterIdentity, err := parseClusterId(event)
	if err != nil {
		log.Errorf("Error inserting event into database: %s", err)
	}

	outputJson, err := json.Marshal(event.OutputFields)
	if err != nil {
		log.Errorf("Failed to marshal")
	}
	_, err2 := pgconf.stmt.Exec(clusterIdentity.landscape, clusterIdentity.project, clusterIdentity.cluster, clusterIdentity.uuid, event.Hostname, event.Time, event.Rule, event.Priority, event.Tags, event.Source, event.Output, outputJson)
	if err2 != nil {
		log.Errorf("Error inserting event into database: %s", err2)
		return
	}
	log.Info("Database insert request finished without error")
}

func (pgconf *PostgresConfig) CheckHealth() error {
	db := pgconf.db
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT version()`)
	if err != nil {
		return fmt.Errorf("failed to run test query: %w", err)
	}

	if err = rows.Close(); err != nil {
		return fmt.Errorf("failed to close selected rows: %w", err)
	}

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
