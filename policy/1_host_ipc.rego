package main

import data.lib.kubernetes

default failHostIPC = false

# failHostIPC is true if spec.hostIPC is set to true (on all resources)
failHostIPC {
	kubernetes.host_ipcs[_] == true
}

deny[msg] {
	failHostIPC

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostIPC' to true", [kubernetes.kind, kubernetes.name]))
	
}