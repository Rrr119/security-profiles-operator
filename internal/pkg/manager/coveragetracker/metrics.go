/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package coveragetracker

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamespace = "security_profiles_operator"
	metricsSubsystem = "profile_coverage"
)

// namespaceCount is the aggregated coverage of the pods of a namespace for a
// profile mechanism.
type namespaceCount struct {
	// total is the number of the running pods, see coveragetracker.Reconcile.
	total int
	// constrained is the number of the pods whose every container is
	// constrained by the mechanism.
	constrained int
}

// coverageStore keeps the latest coverage per namespace and profile
// mechanism. It is the source of the Prometheus gauges.
type coverageStore struct {
	mu     sync.RWMutex
	counts map[string]map[ProfileKind]*namespaceCount
}

func newCoverageStore() *coverageStore {
	return &coverageStore{counts: map[string]map[ProfileKind]*namespaceCount{}}
}

// Replace sets the coverage of the namespace to the provided counts. It is
// called after every full scan of the pods of a namespace, which also removes
// namespaces without running pods through Delete.
func (s *coverageStore) Replace(namespace string, counts map[ProfileKind]*namespaceCount) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(counts) == 0 {
		delete(s.counts, namespace)

		return
	}

	s.counts[namespace] = counts
}

// Delete removes the coverage of the namespace.
func (s *coverageStore) Delete(namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.counts, namespace)
}

// Snapshot returns a copy of the coverage of every namespace.
func (s *coverageStore) Snapshot() map[string]map[ProfileKind]namespaceCount {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]map[ProfileKind]namespaceCount, len(s.counts))
	for namespace, byKind := range s.counts {
		kindCounts := make(map[ProfileKind]namespaceCount, len(byKind))
		for kind, count := range byKind {
			kindCounts[kind] = *count
		}

		out[namespace] = kindCounts
	}

	return out
}

// coverageMetrics are the Prometheus gauges of the coverage. They get
// registered on the controller-runtime registry, so the manager serves them
// alongside its own metrics.
type coverageMetrics struct {
	total       *prometheus.GaugeVec
	constrained *prometheus.GaugeVec
	ratio       *prometheus.GaugeVec
	store       *coverageStore
}

func newCoverageMetrics(store *coverageStore) *coverageMetrics {
	labels := []string{"namespace", "profile"}

	return &coverageMetrics{
		store: store,
		total: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "pods_total",
			Help: "Number of running pods in the namespace considered by the " +
				"profile coverage tracking.",
		}, labels),
		constrained: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "constrained_pods",
			Help: "Number of running pods whose every container is constrained " +
				"by the profile mechanism.",
		}, labels),
		ratio: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "ratio",
			Help: "Ratio of constrained pods over all running pods in the " +
				"namespace for the profile mechanism, between 0 and 1.",
		}, labels),
	}
}

// Describe implements prometheus.Collector.
func (m *coverageMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.total.Describe(ch)
	m.constrained.Describe(ch)
	m.ratio.Describe(ch)
}

// Collect recomputes the gauges from the store on every scrape.
func (m *coverageMetrics) Collect(ch chan<- prometheus.Metric) {
	snapshot := m.store.Snapshot()

	m.total.Reset()
	m.constrained.Reset()
	m.ratio.Reset()

	for namespace, byKind := range snapshot {
		for _, kind := range ProfileKinds {
			count, ok := byKind[kind]
			if !ok {
				continue
			}

			labels := prometheus.Labels{
				"namespace": namespace,
				"profile":   string(kind),
			}

			m.total.With(labels).Set(float64(count.total))
			m.constrained.With(labels).Set(float64(count.constrained))

			ratio := 0.0
			if count.total > 0 {
				ratio = float64(count.constrained) / float64(count.total)
			}

			m.ratio.With(labels).Set(ratio)
		}
	}

	m.total.Collect(ch)
	m.constrained.Collect(ch)
	m.ratio.Collect(ch)
}
