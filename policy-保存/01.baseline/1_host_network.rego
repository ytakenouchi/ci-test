package main

import data.lib.kubernetes

default failHostNetwork = false

# failHostNetwork is true if spec.hostNetwork is set to true (on all controllers)
failHostNetwork {
	kubernetes.host_networks[_] == true
}

deny[msg] {
	failHostNetwork

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostNetwork' to true", [kubernetes.kind, kubernetes.name]))

}