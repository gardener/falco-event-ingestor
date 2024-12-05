// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"regexp"
	"testing"

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

	pgconf := &PostgresConfig{healthConn: conn}
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

	pgconf := &PostgresConfig{healthConn: conn}
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

	pgconf := &PostgresConfig{healthConn: conn}
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

	pgconf := &PostgresConfig{healthConn: conn}
	if err := pgconf.CheckHealth(); err == nil {
		t.Errorf("Rows in health check could be closed")
	}

	if err := pool.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
