package main

import data.lib.kubernetes
import data.lib.utils

default failSeccompProfileType = false

# containers
getContainersWithDisallowedSeccompProfileType[name] {
	container := kubernetes.containers[_]
	type := container.securityContext.seccompProfile.type
	not type == "RuntimeDefault"
	name := container.name
}

# pods
failSeccompProfileType {
	pod := kubernetes.pods[_]
	type := pod.spec.securityContext.seccompProfile.type
	not type == "RuntimeDefault"
}

# annotations (Kubernetes pre-v1.19)
failSeccompAnnotation {
	annotations := kubernetes.annotations[_]
	val := annotations["seccomp.security.alpha.kubernetes.io/pod"]
	val != "runtime/default"
}

# annotations
deny[msg] {
	failSeccompAnnotation

	msg := kubernetes.format(sprintf("%s '%s' should set 'seccomp.security.alpha.kubernetes.io/pod' to 'runtime/default'", [kubernetes.kind, kubernetes.name]))

}

# pods
deny[msg] {
	failSeccompProfileType

	msg := kubernetes.format(sprintf("%s '%s' should set 'spec.securityContext.seccompProfile.type' to 'RuntimeDefault'", [kubernetes.kind, kubernetes.name]))

}

# containers
deny[res] {
	count(getContainersWithDisallowedSeccompProfileType) > 0

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'spec.containers[*].securityContext.seccompProfile.type' to 'RuntimeDefault'", [getContainersWithDisallowedSeccompProfileType[_], kubernetes.kind, kubernetes.name]))

}