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
	"sync"
	"time"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gardener/falco-event-ingestor/pkg/postgres"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type Server struct {
	validator      *auth.Auth
	postgres       *postgres.PostgresConfig
	clusterLimits  map[string]*clusterLimiter
	limterMutex    sync.Mutex
	clusterLimit   rate.Limit
	clusterBurst   int
	generalLimiter *rate.Limiter
}

type clusterLimiter struct {
	limit    *rate.Limiter
	lastSeen time.Time
}

func NewServer(v *auth.Auth, p *postgres.PostgresConfig, port int, clusterDailyEventLimit int, tlsCertFile string, tlsKeyFile string) *Server {
	veryHighLimit := 10000
	generalLimiter := rate.NewLimiter(rate.Limit(veryHighLimit), veryHighLimit) // Shared limiter for all endpoints

	clusterLim := rate.Every(24 * time.Hour / time.Duration(clusterDailyEventLimit)) // Casting required
	clusterBurst := int(float64(clusterDailyEventLimit) * 0.3)                       // We allow bursts of 30% of the daily limit

	server := Server{v, p, map[string]*clusterLimiter{}, sync.Mutex{}, clusterLim, clusterBurst, generalLimiter}

	healthPort := 3210
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", newHandleHealth(p))

	ingestorMux := http.NewServeMux()
	ingestorMux.HandleFunc("/ingestor/api/v1/push", newHandlePush(v, p, &server))

	if tlsCertFile == "" || tlsKeyFile == "" {
		go func() {
			log.Info("Starting non-tls server at port " + strconv.Itoa(port))
			if err := http.ListenAndServe(":"+strconv.Itoa(port), ingestorMux); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		go func() {
			log.Info("Starting tls server at port " + strconv.Itoa(port))
			if err := http.ListenAndServeTLS(":"+strconv.Itoa(port), tlsCertFile, tlsKeyFile, ingestorMux); err != nil {
				log.Fatal(err)
			}
		}()
	}
	go server.cleanLimits()

	log.Info("Starting health server at port " + strconv.Itoa(healthPort))
	if err := http.ListenAndServe(":"+strconv.Itoa(healthPort), healthMux); err != nil {
		log.Fatal(err)
	}

	return &server
}

func (s *Server) checkLimits(clusterId string) error {
	s.limterMutex.Lock()
	defer s.limterMutex.Unlock()
	if _, ok := s.clusterLimits[clusterId]; !ok {
		s.clusterLimits[clusterId] = newShootLimiter(s.clusterLimit, s.clusterBurst)
	}
	shootLimit := s.clusterLimits[clusterId]
	shootLimit.lastSeen = time.Now()
	if !shootLimit.limit.Allow() {
		return fmt.Errorf("limiting instance %s", clusterId)
	}
	return nil
}

func (s *Server) cleanLimits() {
	for {
		time.Sleep(time.Hour)
		s.limterMutex.Lock()
		for cluster, clusterLimit := range s.clusterLimits {
			if time.Since(clusterLimit.lastSeen) > time.Hour*24 {
				delete(s.clusterLimits, cluster)
			}
		}
		s.limterMutex.Unlock()
	}
}

func newShootLimiter(lim rate.Limit, burst int) *clusterLimiter {
	return &clusterLimiter{
		limit: rate.NewLimiter(lim, burst),
	}
}

func newHandleHealth(p *postgres.PostgresConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.CheckHealth(); err != nil {
			log.Error("Health check failed due to: " + err.Error())
			http.Error(w, "database not ready", http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(200)
			if _, err := w.Write([]byte("ok")); err != nil {
				log.Errorf("Could not set health http header: %s", err)
			}
		}
	}
}

func newHandlePush(v *auth.Auth, p *postgres.PostgresConfig, s *Server) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.generalLimiter.Allow() {
			log.Error("Too many requests: limiting all incoming requests")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		token, err := v.ExtractToken(r)
		if err != nil {
			log.Errorf("Error extracting token: %s", err)
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		tokenValues, err := v.VerifyToken(*token)
		if err != nil {
			log.Errorf("Error validating token: %s", err)
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		if err := s.checkLimits(tokenValues.ClusterId); err != nil {
			log.Errorf("Error too many requests: %s", err)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		eventStruct, err := requestToEvent(r)
		if err != nil {
			log.Errorf("Error unmarshalling event: " + err.Error())
			http.Error(w, "cannot parse http body", http.StatusBadRequest)
			return
		}

		if err := verifyEventTokenMatch(eventStruct, tokenValues); err != nil {
			log.Errorf("Token and event do not match: " + err.Error())
			log.Debug(eventStruct)
			http.Error(w, "token and event are mismatched", http.StatusBadRequest)
			return
		}

		p.Insert(eventStruct)
		w.WriteHeader(http.StatusCreated)
	}
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
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&eventStruct); err != nil {
		return nil, fmt.Errorf("cannot parse http body: %s", err.Error())
	}
	return &eventStruct, nil
}
