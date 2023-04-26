package main

import data.lib.kubernetes
import data.lib.utils

default failHostPathVolume = false

failHostPathVolume {
	volumes := kubernetes.volumes
	utils.has_key(volumes[_], "hostPath")
}

deny[msg] {
	failHostPathVolume

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.volumes.hostPath'", [kubernetes.kind, kubernetes.name]))

}