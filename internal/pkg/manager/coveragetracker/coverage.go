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
	"iter"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// ProfileKind identifies a security profile mechanism whose coverage the
// tracker measures. Its values are used as the "profile" metric label.
type ProfileKind string

const (
	// ProfileKindSeccomp is the seccomp profile mechanism.
	ProfileKindSeccomp ProfileKind = "seccomp"
	// ProfileKindAppArmor is the AppArmor profile mechanism.
	ProfileKindAppArmor ProfileKind = "apparmor"
)

// ProfileKinds is the ordered list of the measured profile mechanisms.
var ProfileKinds = []ProfileKind{ProfileKindSeccomp, ProfileKindAppArmor}

// ContainerProfile describes the effective profile of one container for one
// mechanism. A container without a security context field inherits the one
// of the pod.
type ContainerProfile struct {
	// Container is the name of the container.
	Container string
	// Kind is the profile mechanism.
	Kind ProfileKind
	// Constrained is false if the container runs without an enforcing
	// profile: the field is unset or explicitly set to Unconfined.
	Constrained bool
}

// PodCoverage is the coverage of a single pod.
type PodCoverage struct {
	// Namespace of the pod.
	Namespace string
	// Name of the pod.
	Name string
	// Containers is the number of the init, regular and ephemeral
	// containers of the pod.
	Containers int
	// Constrained maps every profile mechanism to the number of its
	// constrained containers.
	Constrained map[ProfileKind]int
	// Missing lists the unconstrained containers per profile mechanism.
	Missing map[ProfileKind][]string
}

// IsConstrained reports whether every container of the pod is constrained for
// the given mechanism. A pod without containers is considered constrained, so
// that it does not raise an alert or skew the coverage.
func (c *PodCoverage) IsConstrained(kind ProfileKind) bool {
	return len(c.Missing[kind]) == 0
}

// Evaluate computes the seccomp and AppArmor coverage of the pod. The pod
// level security context applies to every container which does not override
// the corresponding field.
func Evaluate(pod *corev1.Pod) *PodCoverage {
	coverage := &PodCoverage{
		Namespace:   pod.Namespace,
		Name:        pod.Name,
		Constrained: make(map[ProfileKind]int, len(ProfileKinds)),
		Missing:     make(map[ProfileKind][]string, len(ProfileKinds)),
	}

	podSeccomp, podAppArmor := podProfiles(pod.Spec.SecurityContext)

	for ctr := range util.AllContainers(pod) {
		coverage.Containers++

		ctrSeccomp, ctrAppArmor := podSeccomp, podAppArmor
		if sc := ctr.SecurityContext; sc != nil {
			if sc.SeccompProfile != nil {
				ctrSeccomp = sc.SeccompProfile
			}

			if sc.AppArmorProfile != nil {
				ctrAppArmor = sc.AppArmorProfile
			}
		}

		if seccompConstrained(ctrSeccomp) {
			coverage.Constrained[ProfileKindSeccomp]++
		} else {
			coverage.Missing[ProfileKindSeccomp] =
				append(coverage.Missing[ProfileKindSeccomp], ctr.Name)
		}

		if appArmorConstrained(ctrAppArmor) {
			coverage.Constrained[ProfileKindAppArmor]++
		} else {
			coverage.Missing[ProfileKindAppArmor] =
				append(coverage.Missing[ProfileKindAppArmor], ctr.Name)
		}
	}

	return coverage
}

// podProfiles returns the seccomp and AppArmor profiles of a security
// context, tolerating a nil one.
func podProfiles(sc *corev1.PodSecurityContext) (
	seccomp *corev1.SeccompProfile, apparmor *corev1.AppArmorProfile,
) {
	if sc == nil {
		return nil, nil
	}

	return sc.SeccompProfile, sc.AppArmorProfile
}

// seccompConstrained reports whether the effective seccomp profile enforces a
// profile. Unset and Unconfined leave the container unconstrained, while
// RuntimeDefault and Localhost constrain it.
func seccompConstrained(profile *corev1.SeccompProfile) bool {
	return profile != nil && profile.Type != corev1.SeccompProfileTypeUnconfined
}

// appArmorConstrained reports whether the effective AppArmor profile enforces
// a profile. Unset and Unconfined leave the container unconstained, while
// RuntimeDefault and Localhost constrain it.
func appArmorConstrained(profile *corev1.AppArmorProfile) bool {
	return profile != nil && profile.Type != corev1.AppArmorProfileTypeUnconfined
}

// MissingProfiles yields the mechanisms under which at least one container of
// the pod is unconstrained.
func (c *PodCoverage) MissingProfiles() iter.Seq[ProfileKind] {
	return func(yield func(ProfileKind) bool) {
		for _, kind := range ProfileKinds {
			if !c.IsConstrained(kind) && !yield(kind) {
				return
			}
		}
	}
}
