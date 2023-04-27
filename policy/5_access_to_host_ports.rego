package main
import data.lib.kubernetes

default failHostPorts = false

# Add allowed host ports to this set
#allowed_host_ports = set()
allowed_host_ports = set(443)

# getContainersWithDisallowedHostPorts returns a list of containers which have
# host ports not included in the allowed host port list
getContainersWithDisallowedHostPorts[container] {
	allContainers := kubernetes.containers[_]
	set_host_ports := {port | port := allContainers.ports[_].hostPort}
	host_ports_not_allowed := set_host_ports - allowed_host_ports
	count(host_ports_not_allowed) > 0
	container := allContainers.name
}

# host_ports_msg is a string of allowed host ports to be print as part of deny message
host_ports_msg = "" {
	count(allowed_host_ports) == 0
} else = msg {
	msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_host_ports)])
}

# failHostPorts is true if there are containers which set host ports
# not included in the allowed host ports list
failHostPorts {
	count(getContainersWithDisallowedHostPorts) > 0
}

deny[msg] {
	failHostPorts

	msg := sprintf("Container '%s' of %s '%s' should not set host ports, 'ports[*].hostPort'%s", [getContainersWithDisallowedHostPorts[_], kubernetes.kind, kubernetes.name, host_ports_msg])
}