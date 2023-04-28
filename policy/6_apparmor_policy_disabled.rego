package main

import data.lib.kubernetes

default failAppArmor = false

apparmor_keys[container] = key {
	container := kubernetes.containers[_].name
	key := sprintf("%s/%s", ["container.apparmor.security.beta.kubernetes.io", container])
}

custom_apparmor_containers[container] {
	key := apparmor_keys[container]
	annotations := kubernetes.annotations[_]
	val := annotations[key]
	val != "runtime/default"
}

deny[msg] {
	container := custom_apparmor_containers[_]

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should specify an AppArmor profile", [container, kubernetes.kind, kubernetes.name]))

}