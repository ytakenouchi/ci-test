package main

import data.lib.kubernetes
import data.lib.utils

default failHostProcess = false

# containers 
getContainersWithDisallowedhostProcess[name] {
	container := kubernetes.containers[_]
	options := container.securityContext.windowsOptions
	options.hostProcess == true
	name := container.name
}

# pods
failhostProcess {
	pod := kubernetes.pods[_]
	hostProcess := pod.spec.securityContext.windowsOptions.hostProcess
	hostProcess == true
}

# pods
deny[msg] {
	failhostProcess

	msg := kubernetes.format(sprintf("%s '%s' should set 'spec.securityContext.windowsOptions.hostProcess' to false", [kubernetes.kind, kubernetes.name]))
}

# containers
deny[msg] {
	count(getContainersWithDisallowedhostProcess) > 0

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'spec.securityContext.windowsOptions.hostProcess' to false", [getContainersWithDisallowedhostProcess[_], kubernetes.kind, kubernetes.name]))
}