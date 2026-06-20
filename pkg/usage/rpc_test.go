package usage

import (
	"context"
	"encoding/json"
	"testing"
)

type fakeMissionProgress struct {
	daily  int
	streak int
}

func (f *fakeMissionProgress) DailySessionCount(_ context.Context, _ string) (int, error) {
	return f.daily, nil
}

func (f *fakeMissionProgress) PlayStreak(_ context.Context, _ string) (int, error) {
	return f.streak, nil
}

func TestMergeMissionUsageProgress(t *testing.T) {
	raw := json.RawMessage(`[
		{"id":1,"code":"DAILY","category":"play","type":"DAILY_SESSION","target_value":3,"reward_stars":5,"title_key":"t","description_key":"d","icon":"🎯","is_repeatable":true,"progress":0,"status":"in_progress"},
		{"id":2,"code":"STREAK","category":"play","type":"PLAY_STREAK","target_value":7,"reward_stars":10,"title_key":"t","description_key":"d","icon":"🔥","is_repeatable":false,"progress":0,"status":"in_progress"},
		{"id":3,"code":"REF","category":"ref","type":"REFERRAL_SIGNUP","target_value":1,"reward_stars":1,"title_key":"t","description_key":"d","icon":"🤝","is_repeatable":false,"progress":2,"status":"completed"}
	]`)
	out, err := MergeMissionUsageProgress(context.Background(), &fakeMissionProgress{daily: 4, streak: 9}, "u@example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	var rows []MissionRow
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Progress != 4 || rows[0].Status != "completed" {
		t.Fatalf("daily: %+v", rows[0])
	}
	if rows[1].Progress != 9 || rows[1].Status != "completed" {
		t.Fatalf("streak: %+v", rows[1])
	}
	if rows[2].Progress != 2 {
		t.Fatalf("referral unchanged: %+v", rows[2])
	}
}

func TestUsageRPCEmail(t *testing.T) {
	raw := json.RawMessage(`{"target_email":"a@b.com"}`)
	if got := UsageRPCEmail(raw); got != "a@b.com" {
		t.Fatalf("got %q", got)
	}
}

func TestHeatmapJSON(t *testing.T) {
	b, err := HeatmapJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Fatalf("unexpected %s", b)
	}
}
