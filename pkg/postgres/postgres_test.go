// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestHealthGood(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version()`)).WithoutArgs().WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow("123"))

	pgconf := &PostgresConfig{db: db}
	if err := pgconf.CheckHealth(); err != nil {
		t.Errorf("Health check failed: %s", err.Error())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestHealthPingFail(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	db.Close()

	pgconf := &PostgresConfig{db: db}
	if err := pgconf.CheckHealth(); err == nil {
		t.Errorf("Database was closed but able to be pinnged")
	}
}

func TestHealthQueryFail(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version()`)).WithoutArgs()

	pgconf := &PostgresConfig{db: db}
	if err := pgconf.CheckHealth(); err == nil {
		t.Error("Health check succeded")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestHealthQueryRowsClosed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Test postgres could not be setup: %s", err.Error())
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"version"}).AddRow("123")
	rows.CloseError(errors.New("Trigger closing failure"))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version()`)).WithoutArgs().WillReturnRows(rows)

	pgconf := &PostgresConfig{db: db}
	if err := pgconf.CheckHealth(); err == nil {
		t.Errorf("Rows in health check could be closed")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
