package model

import "github.com/thinkonmay/global-proxy/api/pkg/bus"

// ClusterRoutingUpdatedMsg is published when a cluster's VM routing table changes.
type ClusterRoutingUpdatedMsg struct {
	Domain   string `json:"domain"`
	Revision int64  `json:"revision"`
}

// TopicClusterRoutingUpdated notifies all cluster masters to refresh peer routing.
var TopicClusterRoutingUpdated = bus.NewTopic[ClusterRoutingUpdatedMsg]("cluster.routing.updated")
