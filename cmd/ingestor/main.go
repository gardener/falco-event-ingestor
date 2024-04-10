// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	postgres "github.com/gardener/falco-event-ingestor/pkg/postgres"
	"github.com/gardener/falco-event-ingestor/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Version is injected by build.
	Version string
	// ImageTag is injected by build.
	ImageTag string
	// Password for the postgres user
	postgresPassword string
	// Key to verify JWT tokens
	verificationKey string
	// Configuration file
	configFile string
	// Daily limit of events received by one cluster
	clusterDailyEventLimit int

	// postgres object
	postgresConfig *postgres.PostgresConfig

	validator *auth.Auth

	rootCmd = &cobra.Command{
		Use:   "ingestor",
		Short: "Falco event ingestor for Postgres (" + Version + ")",
		Run: func(cmd *cobra.Command, args []string) {
			server.NewServer(validator, postgresConfig, viper.GetInt("server.port"), clusterDailyEventLimit)
			cmd.Help()
		},
	}
)

func configureLogging() {
	// log.SetFormatter(&log.JSONFormatter{})
	// log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func initConfig() {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	configureLogging()
	validator = auth.NewAuth()
	if err := validator.LoadKey(verificationKey); err != nil {
		os.Stderr.WriteString("Cannot load token verification key: " + err.Error() + "\n")
		os.Exit(1)
	}
	postpresPassword, err := os.ReadFile(postgresPassword)
	if err != nil {
		os.Stderr.WriteString("Cannot read postgres password: " + err.Error() + "\n")
		os.Exit(1)
	}
	postgresConfig = postgres.NewPostgresConfig(
		viper.GetString("postgres.user"),
		string(postpresPassword),
		viper.GetString("postgres.host"),
		viper.GetInt("postgres.port"),
		viper.GetString("postgres.dbname"),
	)

}

func main() {
	cobra.OnInitialize(initConfig)
	rootCmd.Flags().StringVarP(&configFile, "config-file", "", "", "configuration file")
	rootCmd.Flags().StringVarP(&verificationKey, "key-file", "", "", "public key to verify JWT tokens")
	rootCmd.Flags().StringVarP(&postgresPassword, "postgres-password-file", "", "", "password for the postgres user")
	rootCmd.Flags().IntVar(&clusterDailyEventLimit, "cluster-daily-event-limit", 10000, "daily limit of falco events received from one cluster")
	rootCmd.MarkFlagRequired("config-file")
	rootCmd.MarkFlagRequired("key-file")
	rootCmd.MarkFlagRequired("postgres-password-file")
	err := rootCmd.Execute()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
