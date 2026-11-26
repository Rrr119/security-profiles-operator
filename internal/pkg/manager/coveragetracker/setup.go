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
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// rescanSource enqueues a full scan on startup and every rescanInterval. The
// periodic full scan keeps the gauges and the alert state consistent even if
// an informer event was missed.
func rescanSource() source.Source {
	return source.Func(func(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		request := reconcile.Request{
			NamespacedName: types.NamespacedName{Name: rescanRequest},
		}
		queue.Add(request)

		ticker := time.NewTicker(rescanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				queue.Add(request)
			}
		}
	})
}

// Setup wires the controller to the manager.
func (r *CoverageTrackerReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	const name = "coverage-tracker"

	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(name)
	r.record = util.NewEventRecorder(mgr, name)
	r.alerted = map[types.NamespacedName]map[ProfileKind]struct{}{}
	r.store = newCoverageStore()
	r.metrics = newCoverageMetrics(r.store)

	// A previous Setup may have registered a collector of the same
	// descriptors, for example in tests which build several managers.
	if err := ctrlmetrics.Registry.Register(r.metrics); err != nil {
		if ok := ctrlmetrics.Registry.Unregister(r.metrics); !ok {
			return fmt.Errorf("registering coverage metrics: %w", err)
		}

		if err := ctrlmetrics.Registry.Register(r.metrics); err != nil {
			return fmt.Errorf("re-registering coverage metrics: %w", err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(controller.Options(ctx)).
		For(&corev1.Pod{}, builder.WithPredicates(podCoverageChanged())).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(namespaceRequests),
			builder.OnlyMetadata,
		).
		WatchesRawSource(rescanSource()).
		Complete(r)
}

// podCoverageChanged filters pod events down to the ones which can change the
// coverage: creation, deletion and updates of the security contexts, the
// containers or the phase. Label or status-only updates are ignored.
func podCoverageChanged() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, oldOk := e.ObjectOld.(*corev1.Pod)
			newPod, newOk := e.ObjectNew.(*corev1.Pod)
			if !oldOk || !newOk {
				return false
			}

			return util.PodCompletedNow(e.ObjectOld, e.ObjectNew) ||
				!equalPodSecurity(oldPod, newPod)
		},
	}
}

// equalPodSecurity reports whether the fields which determine the coverage
// are identical.
func equalPodSecurity(oldPod, newPod *corev1.Pod) bool {
	return reflect.DeepEqual(oldPod.Spec.SecurityContext, newPod.Spec.SecurityContext) &&
		reflect.DeepEqual(containerSecurityProfiles(oldPod), containerSecurityProfiles(newPod))
}

// containerSecurityProfiles returns the name and the security context of every init,
// regular and ephemeral container, which are the pod fields the coverage
// depends on. Comparing the names catches added or removed containers too.
func containerSecurityProfiles(pod *corev1.Pod) []containerSecurityProfile {
	profiles := make([]containerSecurityProfile, 0)
	for ctr := range util.AllContainers(pod) {
		profiles = append(profiles, containerSecurityProfile{
			name:            ctr.Name,
			securityContext: ctr.SecurityContext,
		})
	}

	return profiles
}

type containerSecurityProfile struct {
	name            string
	securityContext *corev1.SecurityContext
}

// namespaceRequests maps a namespace event to a full rescan, so that a new
// namespace gets metrics without waiting for the periodic scan.
func namespaceRequests(_ context.Context, obj client.Object) []reconcile.Request {
	return []reconcile.Request{{
		NamespacedName: types.NamespacedName{Name: rescanRequest},
	}}
}
