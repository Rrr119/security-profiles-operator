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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func seccomp(profileType corev1.SeccompProfileType) *corev1.SeccompProfile {
	return &corev1.SeccompProfile{Type: profileType}
}

func apparmor(profileType corev1.AppArmorProfileType) *corev1.AppArmorProfile {
	return &corev1.AppArmorProfile{Type: profileType}
}

func container(
	name string,
	seccompProfile *corev1.SeccompProfile,
	apparmorProfile *corev1.AppArmorProfile,
) corev1.Container {
	return corev1.Container{
		Name: name,
		SecurityContext: &corev1.SecurityContext{
			SeccompProfile:  seccompProfile,
			AppArmorProfile: apparmorProfile,
		},
	}
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name             string
		pod              *corev1.Pod
		wantContainers   int
		wantSeccompOK    bool
		wantAppArmorOK   bool
		wantSeccompMiss  []string
		wantAppArmorMiss []string
	}{
		{
			name: "fully constrained with localhost profiles",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "constrained", Namespace: "ns-a"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						container(
							"app",
							seccomp(corev1.SeccompProfileTypeLocalhost),
							apparmor(corev1.AppArmorProfileTypeLocalhost),
						),
					},
				},
			},
			wantContainers: 1,
			wantSeccompOK:  true,
			wantAppArmorOK: true,
		},
		{
			name: "runtime default counts as constrained",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns-a"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						container(
							"app",
							seccomp(corev1.SeccompProfileTypeRuntimeDefault),
							apparmor(corev1.AppArmorProfileTypeRuntimeDefault),
						),
					},
				},
			},
			wantContainers: 1,
			wantSeccompOK:  true,
			wantAppArmorOK: true,
		},
		{
			name: "unconfined and unset are unconstrained",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "loose", Namespace: "ns-b"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "unconfined",
							SecurityContext: &corev1.SecurityContext{
								SeccompProfile:  seccomp(corev1.SeccompProfileTypeUnconfined),
								AppArmorProfile: apparmor(corev1.AppArmorProfileTypeUnconfined),
							},
						},
						{Name: "unset"},
					},
				},
			},
			wantContainers:   2,
			wantSeccompMiss:  []string{"unconfined", "unset"},
			wantAppArmorMiss: []string{"unconfined", "unset"},
		},
		{
			name: "pod security context is inherited",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "inherited", Namespace: "ns-c"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile:  seccomp(corev1.SeccompProfileTypeRuntimeDefault),
						AppArmorProfile: apparmor(corev1.AppArmorProfileTypeRuntimeDefault),
					},
					Containers: []corev1.Container{{Name: "first"}, {Name: "second"}},
				},
			},
			wantContainers: 2,
			wantSeccompOK:  true,
			wantAppArmorOK: true,
		},
		{
			name: "container overrides the pod security context",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "ns-c"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: seccomp(corev1.SeccompProfileTypeRuntimeDefault),
					},
					Containers: []corev1.Container{
						{
							Name: "wild",
							SecurityContext: &corev1.SecurityContext{
								SeccompProfile: seccomp(corev1.SeccompProfileTypeUnconfined),
							},
						},
					},
				},
			},
			wantContainers:   1,
			wantSeccompMiss:  []string{"wild"},
			wantAppArmorMiss: []string{"wild"},
		},
		{
			name: "init containers are evaluated too",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "init", Namespace: "ns-c"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						container(
							"setup",
							seccomp(corev1.SeccompProfileTypeRuntimeDefault), nil,
						),
					},
					Containers: []corev1.Container{
						container(
							"app",
							seccomp(corev1.SeccompProfileTypeRuntimeDefault),
							apparmor(corev1.AppArmorProfileTypeRuntimeDefault),
						),
					},
				},
			},
			wantContainers:   2,
			wantSeccompOK:    true,
			wantAppArmorMiss: []string{"setup"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			coverage := Evaluate(tc.pod)
			require.Equal(t, tc.wantContainers, coverage.Containers)
			require.Equal(t, tc.wantSeccompOK,
				coverage.IsConstrained(ProfileKindSeccomp))
			require.Equal(t, tc.wantAppArmorOK,
				coverage.IsConstrained(ProfileKindAppArmor))
			require.ElementsMatch(t, tc.wantSeccompMiss,
				coverage.Missing[ProfileKindSeccomp])
			require.ElementsMatch(t, tc.wantAppArmorMiss,
				coverage.Missing[ProfileKindAppArmor])
		})
	}
}

func TestEvaluateNoContainersIsConstrained(t *testing.T) {
	t.Parallel()

	coverage := Evaluate(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "ns"},
	})

	for _, kind := range ProfileKinds {
		require.True(t, coverage.IsConstrained(kind))
	}

	require.Equal(t, 0, coverage.Containers)
}

func TestMissingProfiles(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "only-seccomp",
					SecurityContext: &corev1.SecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
				},
			},
		},
	}

	var missing []ProfileKind
	for kind := range Evaluate(pod).MissingProfiles() {
		missing = append(missing, kind)
	}

	require.Equal(t, []ProfileKind{ProfileKindAppArmor}, missing)
}

func TestCoverageStore(t *testing.T) {
	t.Parallel()

	store := newCoverageStore()
	store.Replace("ns-a", map[ProfileKind]*namespaceCount{
		ProfileKindSeccomp: {total: 4, constrained: 3},
	})

	snapshot := store.Snapshot()
	require.Len(t, snapshot, 1)
	require.Equal(t, 4, snapshot["ns-a"][ProfileKindSeccomp].total)

	// Mutating the returned snapshot must not change the store.
	mutated := snapshot["ns-a"][ProfileKindSeccomp]
	mutated.total = 99
	require.Equal(t, 4, store.Snapshot()["ns-a"][ProfileKindSeccomp].total)

	store.Delete("ns-a")
	require.Empty(t, store.Snapshot())

	store.Replace("ns-empty", map[ProfileKind]*namespaceCount{})
	require.Empty(t, store.Snapshot())
}
