package persona_test

import (
	"encoding/json"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
)

func TestEngagementFeedbackJSONCDP3(t *testing.T) {
	raw := []byte(`{
		"star_balance": 10,
		"mission_claims_30d": 2,
		"referrals_made": 1,
		"feedback_count": 5,
		"feedbacks": {
			"count_30d": 2,
			"avg_overall_all_time": 4.5,
			"avg_overall_30d": 5,
			"avg_dimensions_30d": {
				"latency": 4,
				"overall_rating": 5
			},
			"recent": [
				{"created_at":"2026-06-01T10:00:00Z","overall_rating":5,"feedback":"Great stream"}
			]
		}
	}`)
	var out persona.EngagementContextForTest
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.FeedbackCount != 5 || out.Feedbacks.Count30d != 2 {
		t.Fatalf("unexpected counts: %+v", out)
	}
	if len(out.Feedbacks.Recent) != 1 || out.Feedbacks.Recent[0].Feedback != "Great stream" {
		t.Fatalf("recent: %+v", out.Feedbacks.Recent)
	}
}
