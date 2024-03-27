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

	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

const INSERT_STATEMENT = "INSERT INTO falco_events(landscape, project, cluster, hostname, time, rule, priority, tags, source, message) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"

var REQUIRED_FIELDS = []string{"landscape", "project", "cluster", "hostname", "time", "rule", "priority", "tags", "source"}

type ClusterIdentity struct {
	project   string
	cluster   string
	uuid      string
	landscape string
}

type PostgresConfig struct {
	user     string
	password string
	host     string
	port     int
	dbname   string
	db       *sql.DB
	stmt     *sql.Stmt
}

type EventStruct struct {
	Uuid         string                     `json:"uuid"`
	Output       string                     `json:"output"`
	Priority     string                     `json:"priority"`
	Rule         string                     `json:"rule"`
	Time         time.Time                  `json:"time"`
	OutputFields map[string]json.RawMessage `json:"output_fields"`
	Source       string                     `json:"source"`
	Tags         json.RawMessage            `json:"tags"` // possibly should be []string
	Hostname     string                     `json:"hostname"`
	Landscape    string                     `json:"landscape"`
	Cluster      string                     `json:"cluster"`
	Project      string                     `json:"project"`
}

func NewPostgresConfig(user, password, host string, port int, dbname string) *PostgresConfig {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s", host, port, user, password, dbname)
	log.Infof("Trying connection: %s", connStr)

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
	stmt, err := PrepareInsert(db)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Connection to database succeded")

	return &PostgresConfig{
		user:     user,
		password: password,
		host:     host,
		port:     port,
		dbname:   dbname,
		db:       db,
		stmt:     stmt,
	}
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

// we cannot do anything here if this fails ... Not returning an error
func (c *PostgresConfig) Insert(event *EventStruct) {
	clusterIdentity, err := parseClusterId(event)
	if err != nil {
		log.Errorf("Error inserting event into database: %s", err)
	}

	_, err2 := c.stmt.Exec("tst", clusterIdentity.project, clusterIdentity.cluster, event.Hostname, event.Time, event.Rule, event.Priority, event.Tags, event.Source, event.Output)
	if err2 != nil {
		log.Errorf("Error inserting event into database: %s", err2)
		return
	}
	log.Info("Database insert request finished without error")
}

func PrepareInsert(db *sql.DB) (*sql.Stmt, error) {
	stmt, err := db.Prepare(INSERT_STATEMENT)
	if err != nil {
		return nil, fmt.Errorf("could not prepare sql statement: %s due to error: %s", INSERT_STATEMENT, err.Error())
	}
	return stmt, nil
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
