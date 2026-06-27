package metricsagg

import (
	"bytes"
	"fmt"
	"strings"
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
	fmt.Fprintf(&buf, "thinkmay_metrics_cache_nodes %d\n", active)

	now := time.Now().Unix()
	for _, n := range nodes {
		if n.Stale {
			fmt.Fprintf(&buf, "thinkmay_node_up{node=%q} 0\n", n.Node)
			continue
		}
		fmt.Fprintf(&buf, "# node %s\n", n.Node)
		fmt.Fprintf(&buf, "thinkmay_node_up{node=%q} 1\n", n.Node)
		fmt.Fprintf(&buf, "thinkmay_node_push_seconds{node=%q} %d\n", n.Node, now)
		buf.Write(relabelMetricsForNode(n.Body, n.Node))
	}
	return buf.Bytes()
}

// relabelMetricsForNode injects node=<name> into every sample line so merged
// worker exporter payloads do not collide on the same label set at scrape time.
func relabelMetricsForNode(body []byte, node string) []byte {
	node = strings.TrimSpace(node)
	if len(body) == 0 || node == "" {
		return nil
	}
	var out bytes.Buffer
	for line := range bytes.Lines(body) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}
		relabeled, ok := injectNodeLabel(line, node)
		if !ok {
			continue
		}
		out.Write(relabeled)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func injectNodeLabel(line []byte, node string) ([]byte, bool) {
	space := bytes.IndexByte(line, ' ')
	if space <= 0 {
		return nil, false
	}
	metricPart := line[:space]
	valuePart := bytes.TrimSpace(line[space+1:])
	if len(valuePart) == 0 {
		return nil, false
	}

	open := bytes.IndexByte(metricPart, '{')
	if open < 0 {
		return fmt.Appendf(nil, "%s{node=%q} %s", metricPart, node, valuePart), true
	}
	if metricPart[len(metricPart)-1] != '}' {
		return nil, false
	}
	metric := metricPart[:open]
	labels := metricPart[open+1 : len(metricPart)-1]
	if len(labels) == 0 {
		return fmt.Appendf(nil, "%s{node=%q} %s", metric, node, valuePart), true
	}
	return fmt.Appendf(nil, "%s{node=%q,%s} %s", metric, node, labels, valuePart), true
}
