package main

import data.lib.kubernetes
import data.lib.utils

default failSysctls = false

# Add allowed sysctls
allowed_sysctls = {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
}

# failSysctls is true if a disallowed sysctl is set
failSysctls {
	pod := kubernetes.pods[_]
	set_sysctls := {sysctl | sysctl := pod.spec.securityContext.sysctls[_].name}
	sysctls_not_allowed := set_sysctls - allowed_sysctls
	count(sysctls_not_allowed) > 0
}

deny[msg] {
	failSysctls

	msg := kubernetes.format(sprintf("%s '%s' should set 'securityContext.sysctl' to the allowed values", [kubernetes.kind, kubernetes.name]))

}