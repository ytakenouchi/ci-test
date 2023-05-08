package main

import data.lib.kubernetes
import data.lib.utils

default failSELinux = false

allowed_selinux_types := ["container_t", "container_init_t", "container_kvm_t"]

getAllSecurityContexts[context] {
	context := kubernetes.containers[_].securityContext
}

getAllSecurityContexts[context] {
	context := kubernetes.pods[_].spec.securityContext
}

failSELinuxType[type] {
	context := getAllSecurityContexts[_]

	trace(context.seLinuxOptions.type)
	context.seLinuxOptions != null
	context.seLinuxOptions.type != null

	not hasAllowedType(context.seLinuxOptions)

	type := context.seLinuxOptions.type
}

failForbiddenSELinuxProperties[key] {
	context := getAllSecurityContexts[_]

	context.seLinuxOptions != null

	forbiddenProps := getForbiddenSELinuxProperties(context)
	key := forbiddenProps[_]
}

getForbiddenSELinuxProperties(context) = keys {
	forbiddenProperties = ["role", "user"]
	keys := {msg |
		key := forbiddenProperties[_]
		utils.has_key(context.seLinuxOptions, key)
		msg := sprintf("'%s'", [key])
	}
}

hasAllowedType(options) {
	allowed_selinux_types[_] == options.type
}

deny[msg] {
	type := failSELinuxType[_]

	msg := kubernetes.format(sprintf("%s '%s' uses invalid seLinux type '%s'", [kubernetes.kind, kubernetes.name, type]))
}

deny[msg] {
	keys := failForbiddenSELinuxProperties

	count(keys) > 0

	msg := kubernetes.format(sprintf("%s '%s' uses restricted properties in seLinuxOptions: (%s)", [kubernetes.kind, kubernetes.name, concat(", ", keys)]))

}