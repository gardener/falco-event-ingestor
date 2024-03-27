// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gardener/falco-event-ingestor/pkg/postgres"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

func NewServer(v *auth.Auth, p *postgres.PostgresConfig, port int) {
	rateLimit := rate.Limit(10) // n events per second
	burst := 10
	limiter := rate.NewLimiter(rateLimit, burst) // shared limiter for all endpoints

	http.HandleFunc("/healthz", newHandleHealth(p))
	http.HandleFunc("/ingestor/api/v1/push", rateLimiter(limiter, newHandlePush(v, p)))

	log.Info("Starting server at port " + strconv.Itoa(port))
	if err := http.ListenAndServe(":"+strconv.Itoa(port), nil); err != nil {
		log.Fatal(err)
	}
}

func newHandleHealth(p *postgres.PostgresConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.CheckHealth(); err != nil {
			log.Info("health check failed due to " + err.Error())
			http.Error(w, "database not ready", http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(200)
			if _, err := w.Write([]byte("ok")); err != nil {
				log.Errorf("could not set health http header: %s", err)
			}
		}
	}
}

func newHandlePush(v *auth.Auth, p *postgres.PostgresConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := v.ExtractToken(r)
		if err != nil {
			log.Debug("Error extracting token " + err.Error())
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		tokenValues, err := v.VerifyToken(*token)
		if err != nil {
			log.Debug("Error validating token " + err.Error())
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		eventStruct, err := requestToEvent(r)
		if err != nil {
			log.Debug("Error unmarshalling event " + err.Error())
			http.Error(w, "cannot parse http body", http.StatusBadRequest)
			return
		}

		if err := verifyEventTokenMatch(eventStruct, tokenValues); err != nil {
			log.Info("Token and event do not match " + err.Error())
			log.Info(eventStruct)
			http.Error(w, "token and event are mismatched", http.StatusBadRequest)
			return
		}

		p.Insert(eventStruct)
		w.WriteHeader(http.StatusCreated)
	}
}

func rateLimiter(limiter *rate.Limiter, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		} else {
			handler(w, r)
		}
	})
}

func verifyEventTokenMatch(event *postgres.EventStruct, token *auth.TokenValues) error {
	clusterId, err := json.Marshal(event.OutputFields["cluster_id"])
	if err != nil {
		return fmt.Errorf("could not parse cluster id: %s", err)
	}

	clusterIdString, err := strconv.Unquote(string(clusterId))
	if err != nil {
		return fmt.Errorf("could not parse cluster id: %s", err)
	}

	if clusterIdString != token.ClusterId {
		return errors.New("cluster identity does not match")
	}
	return nil
}

func requestToEvent(req *http.Request) (*postgres.EventStruct, error) {
	eventStruct := postgres.EventStruct{}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields() // catch unwanted fields

	if err := decoder.Decode(&eventStruct); err != nil {
		return nil, fmt.Errorf("cannot parse http body: %s", err.Error())
	}
	return &eventStruct, nil
}
