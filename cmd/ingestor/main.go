// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	postgres "github.com/gardener/falco-event-ingestor/pkg/postgres"
	"github.com/gardener/falco-event-ingestor/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	// Version is injected by build
	Version string
	// ImageTag is injected by build
	ImageTag string
)

func configureLogging() {
	log.SetLevel(log.InfoLevel)
}

func initConfig(configFile string, verificationKey string, postgresPassword string) (*postgres.PostgresConfig, *auth.Auth) {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	configureLogging()
	validator := auth.NewAuth()
	if err := validator.LoadKey(verificationKey); err != nil {
		os.Stderr.WriteString("Cannot load token verification key: " + err.Error() + "\n")
		os.Exit(1)
	}
	postpresPassword, err := os.ReadFile(postgresPassword)
	if err != nil {
		os.Stderr.WriteString("Cannot read postgres password: " + err.Error() + "\n")
		os.Exit(1)
	}
	postgresConfig := postgres.NewPostgresConfig(
		viper.GetString("postgres.user"),
		string(postpresPassword),
		viper.GetString("postgres.host"),
		viper.GetInt("postgres.port"),
		viper.GetString("postgres.dbname"),
	)
	return postgresConfig, validator
}

func main() {
	// Password for the postgres user
	postgresPassword := flag.String("postgres-password-file", "", "path to file containing the password for the postgres user")
	// TlS certificate file
	tlsCertFile := flag.String("tls-certificate", "", "path to file containing tls certificate")
	// TlS key file
	tlsKeyFile := flag.String("tls-key", "", "path to file containing tls key")
	// Key to verify JWT tokens
	verificationKey := flag.String("key-file", "", "path to file containing the public key to verify JWT tokens")
	// Configuration file
	configFile := flag.String("config-file", "", "path to the configuration file")
	// Daily limit of events received by one cluster
	clusterDailyEventLimit := flag.Int("cluster-daily-event-limit", 10000, "daily limit of falco events received from one cluster")

	flag.Parse()

	postgresConfig, validator := initConfig(*configFile, *verificationKey, *postgresPassword)

	server.NewServer(validator, postgresConfig, viper.GetInt("server.port"), *clusterDailyEventLimit, *tlsCertFile, *tlsKeyFile)
}
