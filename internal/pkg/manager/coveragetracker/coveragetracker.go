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
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// rescanInterval is the period of the full scan which keeps the
	// coverage metrics and the alert state consistent even if an event was
	// missed.
	rescanInterval   = 10 * time.Minute
	reconcileTimeout = 1 * time.Minute

	// reasonMissingProfile is the reason of the warning event recorded for
	// a pod with an unconstrained container.
	reasonMissingProfile = "MissingSecurityProfile"

	// rescanRequest is the name of the request which triggers a scan of the
	// pods of every namespace.
	rescanRequest = "rescan"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &CoverageTrackerReconciler{}
}

// CoverageTrackerReconciler watches pods and measures how many of them run
// with a seccomp and AppArmor profile. It never mutates the pods and never
// blocks their scheduling: unconstrained pods only produce a warning event
// and coverage metrics.
type CoverageTrackerReconciler struct {
	client  client.Client
	reader  client.Reader
	log     logr.Logger
	record  util.EventRecorder
	store   *coverageStore
	metrics *coverageMetrics

	// alertMu guards alerted. The state is in memory: after an operator
	// restart the periodic scan re-evaluates the pods and re-alerts once.
	alertMu sync.Mutex
	alerted map[types.NamespacedName]map[ProfileKind]struct{}
}

// Name returns the name of the controller.
func (r *CoverageTrackerReconciler) Name() string {
	return "coverage-tracker"
}

// SchemeBuilder returns nil: the controller only reads core resources, which
// the default scheme of the manager already knows.
func (r *CoverageTrackerReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return nil
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile either scans every namespace or evaluates a single pod.
func (r *CoverageTrackerReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if req.Namespace == "" && req.Name == rescanRequest {
		if err := r.scanAll(ctx); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	}

	if err := r.reconcilePod(ctx, req.NamespacedName); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// reconcilePod evaluates one pod, updates its alert state and refreshes the
// coverage of its namespace. A deleted or completed pod drops its alerts.
func (r *CoverageTrackerReconciler) reconcilePod(
	ctx context.Context,
	key types.NamespacedName,
) error {
	pod := &corev1.Pod{}

	err := r.client.Get(ctx, key, pod)
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("getting pod: %w", err)
	}

	if err != nil || util.PodCompleted(pod) {
		r.dropAlerts(key)
		// Both the completed pod and the deleted one change the counts of
		// the namespace, which scanNamespace recomputes from the cache.
		return r.scanNamespace(ctx, key.Namespace)
	}

	r.updateAlerts(pod)

	return r.scanNamespace(ctx, pod.Namespace)
}

// scanAll recomputes the coverage of every namespace and prunes the alert
// state and the metrics of namespaces without running pods.
func (r *CoverageTrackerReconciler) scanAll(ctx context.Context) error {
	namespaces := &corev1.NamespaceList{}
	if err := r.reader.List(ctx, namespaces, client.UnsafeDisableDeepCopy); err != nil {
		return fmt.Errorf("listing namespaces: %w", err)
	}

	seen := make(map[string]struct{}, len(namespaces.Items))

	for i := range namespaces.Items {
		namespace := namespaces.Items[i].Name
		seen[namespace] = struct{}{}

		pods := &corev1.PodList{}
		if err := r.reader.List(
			ctx, pods,
			client.InNamespace(namespace),
			client.UnsafeDisableDeepCopy,
		); err != nil {
			return fmt.Errorf("listing pods of namespace %s: %w", namespace, err)
		}

		for j := range pods.Items {
			pod := &pods.Items[j]
			if util.PodCompleted(pod) {
				r.dropAlerts(client.ObjectKeyFromObject(pod))

				continue
			}

			r.updateAlerts(pod)
		}

		if err := r.storeNamespaceCounts(namespace, pods); err != nil {
			return err
		}
	}

	// Prune namespaces which no longer exist or hold no running pods.
	for namespace := range r.store.Snapshot() {
		if _, ok := seen[namespace]; !ok {
			r.store.Delete(namespace)
		}
	}

	// Drop the alert state of pods whose namespace is gone.
	r.alertMu.Lock()
	for key := range r.alerted {
		if _, ok := seen[key.Namespace]; !ok {
			delete(r.alerted, key)
		}
	}
	r.alertMu.Unlock()

	return nil
}

// scanNamespace recomputes the coverage of the running pods of a namespace.
func (r *CoverageTrackerReconciler) scanNamespace(ctx context.Context, namespace string) error {
	pods := &corev1.PodList{}
	if err := r.reader.List(
		ctx, pods,
		client.InNamespace(namespace),
		client.UnsafeDisableDeepCopy,
	); err != nil {
		return fmt.Errorf("listing pods of namespace %s: %w", namespace, err)
	}

	return r.storeNamespaceCounts(namespace, pods)
}

// storeNamespaceCounts evaluates the pods and writes their aggregated
// coverage into the metric store. Namespaces without running pods are pruned.
func (r *CoverageTrackerReconciler) storeNamespaceCounts(namespace string, pods *corev1.PodList) error {
	counts := make(map[ProfileKind]*namespaceCount, len(ProfileKinds))
	for _, kind := range ProfileKinds {
		counts[kind] = &namespaceCount{}
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if util.PodCompleted(pod) {
			continue
		}

		coverage := Evaluate(pod)

		for _, kind := range ProfileKinds {
			counts[kind].total++
			if coverage.IsConstrained(kind) {
				counts[kind].constrained++
			}
		}
	}

	if counts[ProfileKindSeccomp].total == 0 {
		r.store.Delete(namespace)

		return nil
	}

	r.store.Replace(namespace, counts)

	return nil
}

// updateAlerts records a warning event for every mechanism under which the
// pod has an unconstrained container, and drops the alerts of mechanisms the
// pod is now constrained by. It never blocks the pod.
func (r *CoverageTrackerReconciler) updateAlerts(pod *corev1.Pod) {
	key := client.ObjectKeyFromObject(pod)
	coverage := Evaluate(pod)

	missing := map[ProfileKind]struct{}{}

	for kind := range coverage.MissingProfiles() {
		missing[kind] = struct{}{}

		if r.hasAlert(key, kind) {
			continue
		}

		r.log.Info(
			"Pod runs without a constraining profile",
			"pod", key, "profile", kind,
			"containers", coverage.Missing[kind],
		)

		r.record.Eventf(
			pod, nil, corev1.EventTypeWarning, reasonMissingProfile,
			util.EventActionUpdate,
			"Pod has containers without a constraining %s profile: %s",
			kind, strings.Join(coverage.Missing[kind], ", "),
		)

		r.markAlert(key, kind)
	}

	for _, kind := range ProfileKinds {
		if _, stillMissing := missing[kind]; !stillMissing {
			r.clearAlert(key, kind)
		}
	}
}

func (r *CoverageTrackerReconciler) dropAlerts(key types.NamespacedName) {
	r.alertMu.Lock()
	defer r.alertMu.Unlock()

	delete(r.alerted, key)
}

func (r *CoverageTrackerReconciler) hasAlert(key types.NamespacedName, kind ProfileKind) bool {
	r.alertMu.Lock()
	defer r.alertMu.Unlock()

	kinds, ok := r.alerted[key]
	if !ok {
		return false
	}

	_, has := kinds[kind]

	return has
}

func (r *CoverageTrackerReconciler) markAlert(key types.NamespacedName, kind ProfileKind) {
	r.alertMu.Lock()
	defer r.alertMu.Unlock()

	if r.alerted == nil {
		r.alerted = map[types.NamespacedName]map[ProfileKind]struct{}{}
	}

	if r.alerted[key] == nil {
		r.alerted[key] = map[ProfileKind]struct{}{}
	}

	r.alerted[key][kind] = struct{}{}
}

func (r *CoverageTrackerReconciler) clearAlert(key types.NamespacedName, kind ProfileKind) {
	r.alertMu.Lock()
	defer r.alertMu.Unlock()

	if kinds, ok := r.alerted[key]; ok {
		delete(kinds, kind)
		if len(kinds) == 0 {
			delete(r.alerted, key)
		}
	}
}
