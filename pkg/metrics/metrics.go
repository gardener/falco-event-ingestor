// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace = "falco_event_ingestor"
)

var (
	RequestsHist = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "Total number of successful insert requests.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	Limit = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "requests_limit",
			Help:      "Represents whether general rate limiting is active.",
		},
	)

	ClusterRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_cluster_total",
			Help:      "Total number of successful insert requests.",
		},
		[]string{"cluster"},
	)

	ClusterLimit = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "requests_cluster_limit",
			Help:      "Represents whether cluster is rate limited.",
		},
		[]string{"cluster"},
	)
)
