package main

import data.lib.kubernetes
import data.lib.utils

# Add disallowed volume type
disallowed_volume_types = [
	"gcePersistentDisk",
	"awsElasticBlockStore",
	# "hostPath", Baseline detects spec.volumes[*].hostPath
	"gitRepo",
	"nfs",
	"iscsi",
	"glusterfs",
	"rbd",
	"flexVolume",
	"cinder",
	"cephFS",
	"flocker",
	"fc",
	"azureFile",
	"vsphereVolume",
	"quobyte",
	"azureDisk",
	"portworxVolume",
	"scaleIO",
	"storageos",
	"csi",
]

# getDisallowedVolumes returns a list of volume names
# which set volume type to any of the disallowed volume types
getDisallowedVolumes[name] {
	volume := kubernetes.volumes[_]
	type := disallowed_volume_types[_]
	utils.has_key(volume, type)
	name := volume.name
}

# failVolumeTypes is true if any of volume has a disallowed
# volume type
failVolumeTypes {
	count(getDisallowedVolumes) > 0
}

deny[msg] {
	failVolumeTypes

	msg := kubernetes.format(sprintf("%s '%s' should set 'spec.volumes[*]' to type 'PersistentVolumeClaim'", [kubernetes.kind, kubernetes.name]))
}