package model

import "testing"

func TestTopicNames(t *testing.T) {
	if TopicVolumeJob.Name != "jobs.volume" {
		t.Fatalf("volume topic: %s", TopicVolumeJob.Name)
	}
	if TopicVolumeDLQ.Name != "jobs.volume.dlq" {
		t.Fatalf("dlq topic: %s", TopicVolumeDLQ.Name)
	}
	if TopicUsage.Name != "usage.snapshot" {
		t.Fatalf("usage topic: %s", TopicUsage.Name)
	}
	if TopicSSE.Name != "sse" {
		t.Fatalf("sse topic: %s", TopicSSE.Name)
	}
}
