package appshield.kubernetes.KSV010

import data.lib.kubernetes

default failHostPID = false

# failHostPID is true if spec.hostPID is set to true (on all controllers)
failHostPID {
	kubernetes.host_pids[_] == true
}

deny[res] {
	failHostPID

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostPID' to true", [kubernetes.kind, kubernetes.name]))

}