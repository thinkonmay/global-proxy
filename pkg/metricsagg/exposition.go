package metricsagg

import (
	"bytes"
	"fmt"
	"time"
)

func buildExposition(nodes []NodeSnapshot) []byte {
	var buf bytes.Buffer
	active := 0
	for _, n := range nodes {
		if !n.Stale && len(n.Body) > 0 {
			active++
		}
	}
	buf.WriteString("# HELP thinkmay_metrics_cache_nodes Number of worker nodes with fresh cached exporter payloads.\n")
	buf.WriteString("# TYPE thinkmay_metrics_cache_nodes gauge\n")
	buf.WriteString(fmt.Sprintf("thinkmay_metrics_cache_nodes %d\n", active))

	now := time.Now().Unix()
	for _, n := range nodes {
		if n.Stale {
			buf.WriteString(fmt.Sprintf("thinkmay_node_up{node=%q} 0\n", n.Node))
			continue
		}
		buf.WriteString(fmt.Sprintf("# node %s\n", n.Node))
		buf.WriteString(fmt.Sprintf("thinkmay_node_up{node=%q} 1\n", n.Node))
		buf.WriteString(fmt.Sprintf("thinkmay_node_push_seconds{node=%q} %d\n", n.Node, now))
		buf.Write(n.Body)
		if len(n.Body) > 0 && n.Body[len(n.Body)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}
