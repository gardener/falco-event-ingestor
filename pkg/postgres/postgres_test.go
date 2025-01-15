// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
)

func TestHealthGood(t *testing.T) {
	t.Skip("Skipping test until pgxmock.PgxPoolIface.Acquire is implemented")

	pool, err := pgxmock.NewPool()
	if err != nil {
		panic(err)
	}

	pool.ExpectQuery(regexp.QuoteMeta(`SELECT version()`)).WillReturnRows(pgxmock.NewRows([]string{"version"}).AddRow("123"))
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer conn.Release()

	pgconf := &PostgresConfig{}
	if err := pgconf.CheckHealth(); err != nil {
		t.Errorf("Health check failed: %s", err.Error())
	}

	if err := pool.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestHealthPingFail(t *testing.T) {
	t.Skip("Skipping test until pgxmock.PgxPoolIface.Acquire is implemented")
	pool, err := pgxmock.NewPool()
	if err != nil {
		panic(err)
	}

	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer conn.Release()

	pgconf := &PostgresConfig{}
	if err := pgconf.CheckHealth(); err == nil {
		t.Errorf("Database was closed but able to be pinnged")
	}
}

func TestHealthQueryFail(t *testing.T) {
	t.Skip("Skipping test until pgxmock.PgxPoolIface.Acquire is implemented")
	pool, err := pgxmock.NewPool()
	if err != nil {
		panic(err)
	}

	pool.ExpectQuery(regexp.QuoteMeta(`SELECT version()`))

	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer conn.Release()

	pgconf := &PostgresConfig{}
	if err := pgconf.CheckHealth(); err == nil {
		t.Error("Health check succeded")
	}

	if err := pool.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestHealthQueryRowsClosed(t *testing.T) {
	t.Skip("Skipping test until pgxmock.PgxPoolIface.Acquire is implemented")
	pool, err := pgxmock.NewPool()
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	rows := pgxmock.NewRows([]string{"version"}).AddRow("123")
	rows.CloseError(errors.New("Trigger closing failure"))
	pool.ExpectQuery(regexp.QuoteMeta(`SELECT version()`)).WillReturnRows(rows)

	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer conn.Release()

	pgconf := &PostgresConfig{}
	if err := pgconf.CheckHealth(); err == nil {
		t.Errorf("Rows in health check could be closed")
	}

	if err := pool.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestParseClusterId(t *testing.T) {
	validExample := `"shoot--project--cluster-123e4567-e89b-12d3-a456-426614174000-landscape"`
	invalidExamples := []string{
		`"shoot-project--cluster-123e4567-e89b-12d3-a456-426614174000-landscape"`,  // missing double dash after "shoot"
		`"shoot--project-cluster-123e4567-e89b-12d3-a456-426614174000-landscape"`,  // missing double dash after "project"
		`"shoot--project--cluster-123e4567-e89b-12d3-a456-42661417400-landscape"`,  // invalid UUID (one character short)
		`"shoot--project--cluster-123e4567-e89b-12d3-a456-426614174000"`,           // missing landscape part
		`"sht----cluster-123esss4567-e89b-12d3-a456-426614174000-landscape-extra"`, // broken UUID
	}

	good := EventStruct{
		OutputFields: map[string]json.RawMessage{
			"cluster_id": json.RawMessage(validExample),
		},
	}

	_, err := parseClusterId(good)
	if err != nil {
		t.Errorf("Valid cluster ID parsing failed: %s", err)
	}

	for _, example := range invalidExamples {
		bad := EventStruct{
			OutputFields: map[string]json.RawMessage{
				"cluster_id": json.RawMessage(example),
			},
		}

		_, err := parseClusterId(bad)
		if err == nil {
			t.Errorf("Invalid cluster ID parsing succeeded: %s", example)
		}
	}
}

func TestBuildDeleteStatement(t *testing.T) {
	age := time.Duration(24) * time.Hour
	past := time.Now().UTC().Add(-age)

	expected := "DELETE FROM falco_events WHERE time < $1"
	statement, args := buildDeleteStatement(age)
	if statement != expected {
		t.Errorf("\nExpected statement: %s\nActual statement  : %s", expected, statement)
	}

	timeArg := time.Time(args[0].(time.Time))

	if timeArg.Before(past) {
		t.Errorf("\nExpected age ~: %s\nActual age   ~: %s", past, timeArg)
	}
}
