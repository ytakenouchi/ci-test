package main

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

# failProcMountOpts is true if securityContext.procMount is set in any container
failProcMountOpts {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext, "procMount")
}

deny[msg] {
	failProcMountOpts

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.containers[*].securityContext.procMount' or 'spec.initContainers[*].securityContext.procMount'", [kubernetes.kind, kubernetes.name]))
}