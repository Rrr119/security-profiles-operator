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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const (
	namespaceEnforcing = "enforcing"
	namespaceMixed     = "mixed"
	namespaceUnmanaged = "unmanaged"
)

func newTestReconciler(t *testing.T, objs ...client.Object) (
	*CoverageTrackerReconciler, *events.FakeRecorder,
) {
	t.Helper()

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(objs...).
		Build()

	recorder := events.NewFakeRecorder(64)

	r := &CoverageTrackerReconciler{
		client:  c,
		reader:  c,
		log:     logr.Discard(),
		record:  recorder,
		store:   newCoverageStore(),
		alerted: map[types.NamespacedName]map[ProfileKind]struct{}{},
	}
	r.metrics = newCoverageMetrics(r.store)

	return r, recorder
}

func namespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func testPod(namespace, name string, phase corev1.PodPhase, containers ...corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.PodSpec{Containers: containers},
		Status: corev1.PodStatus{
			Phase: phase,
		},
	}
}

func constrainedContainer(name string) corev1.Container {
	return corev1.Container{
		Name: name,
		SecurityContext: &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
			AppArmorProfile: &corev1.AppArmorProfile{
				Type: corev1.AppArmorProfileTypeRuntimeDefault,
			},
		},
	}
}

func unconfinedContainer(name string) corev1.Container {
	return corev1.Container{
		Name: name,
		SecurityContext: &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeUnconfined,
			},
			AppArmorProfile: &corev1.AppArmorProfile{
				Type: corev1.AppArmorProfileTypeUnconfined,
			},
		},
	}
}

func bareContainer(name string) corev1.Container {
	return corev1.Container{Name: name}
}

// TestReconcileCoverageAcrossNamespaces is the acceptance test for the three
// namespace configurations:
//   - enforcing: every pod is fully constrained,
//   - mixed: one constrained and one unconstrained pod,
//   - unmanaged: every pod runs without a profile.
func TestReconcileCoverageAcrossNamespaces(t *testing.T) {
	t.Parallel()

	objs := []client.Object{
		namespace(namespaceEnforcing),
		namespace(namespaceMixed),
		namespace(namespaceUnmanaged),
		// Enforcing namespace: two fully constrained pods.
		testPod(namespaceEnforcing, "pod-1", corev1.PodRunning, constrainedContainer("app")),
		testPod(namespaceEnforcing, "pod-2", corev1.PodRunning, constrainedContainer("app")),
		// Mixed namespace: one constrained, one unconstrained pod.
		testPod(namespaceMixed, "good", corev1.PodRunning, constrainedContainer("app")),
		testPod(namespaceMixed, "bad", corev1.PodRunning, unconfinedContainer("app")),
		// Unmanaged namespace: two pods without any profile.
		testPod(namespaceUnmanaged, "wild-1", corev1.PodRunning, bareContainer("app")),
		testPod(namespaceUnmanaged, "wild-2", corev1.PodPending, bareContainer("sidecar")),
	}

	r, recorder := newTestReconciler(t, objs...)

	// A full scan reconciles every namespace.
	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: rescanRequest},
	})
	require.NoError(t, err)

	assertNamespaceCounts := func(ns string, total, seccompConstrained, appArmorConstrained int) {
		t.Helper()

		snapshot := r.store.Snapshot()
		require.Contains(t, snapshot, ns)
		require.Equal(t, total, snapshot[ns][ProfileKindSeccomp].total)
		require.Equal(t, seccompConstrained,
			snapshot[ns][ProfileKindSeccomp].constrained)
		require.Equal(t, appArmorConstrained,
			snapshot[ns][ProfileKindAppArmor].constrained)
	}

	assertNamespaceCounts(namespaceEnforcing, 2, 2, 2)
	assertNamespaceCounts(namespaceMixed, 2, 1, 1)
	assertNamespaceCounts(namespaceUnmanaged, 2, 0, 0)

	// The unconstrained pods raise one warning event per mechanism, the
	// constrained ones raise none. The scan sees three unconstrained pods:
	// one in mixed and two in unmanaged.
	var events []string

loop:
	for {
		select {
		case got := <-recorder.Events:
			events = append(events, got)
		default:
			break loop
		}
	}

	require.Len(t, events, 6, "one event per unconstrained pod and mechanism")

	for _, got := range events {
		require.True(t, strings.HasPrefix(got, "Warning "+reasonMissingProfile),
			"unexpected event %q", got)
		require.Contains(t, got, "without a constraining")
	}

	// The metrics expose the same numbers, including the ratios.
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(r.metrics))

	gaugeValue := func(metricName, namespace string, kind ProfileKind) float64 {
		t.Helper()

		return gatherGauge(t, registry, metricsNamespace+"_"+metricsSubsystem+"_"+metricName,
			map[string]string{"namespace": namespace, "profile": string(kind)})
	}

	require.Equal(t, 2.0,
		gaugeValue("pods_total", namespaceEnforcing, ProfileKindSeccomp))
	require.Equal(t, 1.0,
		gaugeValue("constrained_pods", namespaceMixed, ProfileKindAppArmor))
	require.Equal(t, 0.0,
		gaugeValue("ratio", namespaceUnmanaged, ProfileKindSeccomp))
	require.Equal(t, 0.5,
		gaugeValue("ratio", namespaceMixed, ProfileKindSeccomp))
	require.Equal(t, 1.0,
		gaugeValue("ratio", namespaceEnforcing, ProfileKindAppArmor))
}

// gatherGauge reads the value of one gauge series from the registered
// collectors, failing the test if the series does not exist.
func gatherGauge(
	t *testing.T,
	registry *prometheus.Registry,
	metricName string,
	labels map[string]string,
) float64 {
	t.Helper()

	families, err := registry.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != metricName {
			continue
		}

		for _, metric := range family.GetMetric() {
			matches := len(metric.GetLabel()) == len(labels)
			for _, label := range metric.GetLabel() {
				matches = matches && labels[label.GetName()] == label.GetValue()
			}

			if matches {
				require.NotNil(t, metric.Gauge, "metric %s is not a gauge", metricName)

				return metric.GetGauge().GetValue()
			}
		}
	}

	require.Failf(t, "metric series not found", "%s %v", metricName, labels)

	return 0
}

// TestAlertDedupAndRecovery makes sure a pod is warned only once while it stays
// unconstrained, that fixing it stops the alerts, and that the tracker never
// blocks or mutates the pod.
func TestAlertDedupAndRecovery(t *testing.T) {
	t.Parallel()

	pod := testPod(namespaceMixed, "bad", corev1.PodRunning, unconfinedContainer("app"))
	r, recorder := newTestReconciler(t, namespace(namespaceMixed), pod)

	reconcilePod := func() {
		t.Helper()

		_, err := r.Reconcile(t.Context(), reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(pod),
		})
		require.NoError(t, err)
	}

	reconcilePod()
	utiltest.RequireEvent(t, recorder,
		"Warning "+reasonMissingProfile+
			" Pod has containers without a constraining seccomp profile: app")
	utiltest.RequireEvent(t, recorder,
		"Warning "+reasonMissingProfile+
			" Pod has containers without a constraining apparmor profile: app")

	// Reconciling the unchanged pod again must not spam more events.
	reconcilePod()
	utiltest.RequireNoEvent(t, recorder)

	// Fix the pod: it now carries runtime default profiles.
	updated := pod.DeepCopy()
	updated.Spec.Containers[0] = constrainedContainer("app")
	require.NoError(t, r.client.Update(t.Context(), updated))

	reconcilePod()
	utiltest.RequireNoEvent(t, recorder)

	// The pod must not have been mutated by the controller.
	got := &corev1.Pod{}
	require.NoError(t, r.client.Get(t.Context(), client.ObjectKeyFromObject(pod), got))
	require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault,
		got.Spec.Containers[0].SecurityContext.SeccompProfile.Type)

	// Breaking it again re-enables the alerts.
	broken := got.DeepCopy()
	broken.Spec.Containers[0] = bareContainer("app")
	require.NoError(t, r.client.Update(t.Context(), broken))

	reconcilePod()

	var count int
loop:
	for {
		select {
		case <-recorder.Events:
			count++
		default:
			break loop
		}
	}

	require.Equal(t, 2, count)
}

// TestCompletedAndDeletedPods verifies that finished pods leave the counts and
// the alert state without blocking anything.
func TestCompletedAndDeletedPods(t *testing.T) {
	t.Parallel()

	pod := testPod(namespaceUnmanaged, "job", corev1.PodRunning, bareContainer("worker"))
	r, recorder := newTestReconciler(t, namespace(namespaceUnmanaged), pod)

	key := client.ObjectKeyFromObject(pod)

	_, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	require.Len(t, r.alerted, 1)
	require.Equal(t, 1, r.store.Snapshot()[namespaceUnmanaged][ProfileKindSeccomp].total)

	// Drain the initial alerts.
drain:
	for {
		select {
		case <-recorder.Events:
		default:
			break drain
		}
	}

	completed := pod.DeepCopy()
	completed.Status.Phase = corev1.PodSucceeded
	require.NoError(t, r.client.Status().Update(t.Context(), completed))

	_, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	require.Empty(t, r.alerted)
	_, tracked := r.store.Snapshot()[namespaceUnmanaged]
	require.False(t, tracked, "namespace without running pods is pruned")
	utiltest.RequireNoEvent(t, recorder)
}

// TestScanAllPrunesNamespaces verifies the periodic scan removes the metrics
// of namespaces which disappeared.
func TestScanAllPrunesNamespaces(t *testing.T) {
	t.Parallel()

	r, _ := newTestReconciler(t,
		namespace(namespaceEnforcing),
		testPod(namespaceEnforcing, "pod", corev1.PodRunning, constrainedContainer("app")),
	)

	require.NoError(t, r.scanNamespace(t.Context(), namespaceEnforcing))
	require.Len(t, r.store.Snapshot(), 1)

	// Simulate a stale namespace left in the store.
	r.store.Replace("gone", map[ProfileKind]*namespaceCount{
		ProfileKindSeccomp: {total: 1},
	})

	require.NoError(t, r.scanAll(t.Context()))

	snapshot := r.store.Snapshot()
	require.Len(t, snapshot, 1)
	require.Contains(t, snapshot, namespaceEnforcing)
}
