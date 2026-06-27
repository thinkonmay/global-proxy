package persona

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

type Config struct {
	Every            time.Duration
	MaxBatch         int
	Concurrent       int
	RybbitMinSpacing time.Duration
	Rybbit           RybbitConfig
	LLM              LLMConfig
}

type Worker struct {
	pr     *postgrest.Client
	rybbit *Rybbit
	llm    *synthesizer
	cfg    Config
	log    *slog.Logger

	rybbitMu      sync.Mutex
	lastRybbitHit time.Time
}

func NewWorker(pr *postgrest.Client, cfg Config, log *slog.Logger) (*Worker, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 20
	}
	if cfg.Concurrent <= 0 {
		cfg.Concurrent = 10
	}
	if cfg.RybbitMinSpacing <= 0 {
		cfg.RybbitMinSpacing = 250 * time.Millisecond
	}
	rybbit, err := NewRybbit(cfg.Rybbit)
	if err != nil {
		return nil, err
	}
	return &Worker{
		pr:     pr,
		rybbit: rybbit,
		llm:    newSynthesizer(cfg.LLM),
		cfg:    cfg,
		log:    log,
	}, nil
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.Every)
	defer ticker.Stop()
	w.log.Info("persona worker started",
		"every", w.cfg.Every,
		"max_batch", w.cfg.MaxBatch,
		"concurrent", w.cfg.Concurrent,
		"rybbit_spacing", w.cfg.RybbitMinSpacing,
	)
	for {
		select {
		case <-ctx.Done():
			w.log.Info("persona worker stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()

	candidates, err := w.listCandidates(ctx)
	if err != nil {
		w.log.Error("persona list candidates failed", "err", err)
		return
	}
	if len(candidates) == 0 {
		return
	}

	sem := make(chan struct{}, w.cfg.Concurrent)
	var wg sync.WaitGroup
	for _, c := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(c Candidate) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := w.refreshOne(ctx, c); err != nil {
				w.log.Warn("persona refresh failed", "email", c.Email, "err", err)
			}
		}(c)
	}
	wg.Wait()
}

func (w *Worker) listCandidates(ctx context.Context) ([]Candidate, error) {
	var rows []Candidate
	err := w.pr.RPC(ctx, "list_persona_refresh_candidates", map[string]any{
		"p_limit": w.cfg.MaxBatch,
	}, &rows)
	return rows, err
}

func (w *Worker) refreshOne(ctx context.Context, c Candidate) error {
	pbUID := c.PBUserID
	if pbUID == "" {
		var err error
		pbUID, err = w.resolveAnalyticsUserID(ctx, c.Email)
		if err != nil {
			return err
		}
	}

	if err := w.waitRybbitSlot(ctx); err != nil {
		return err
	}
	sessionsYAML, err := w.rybbit.FetchSessionYAML(ctx, pbUID)
	if err != nil {
		_ = w.pr.RPC(ctx, "touch_persona_refresh", map[string]any{"p_email": c.Email}, nil)
		return err
	}

	var payments []PaymentRecord
	if err := w.pr.RPC(ctx, "get_payment_history", map[string]any{"email": c.Email}, &payments); err != nil {
		payments = nil
	}

	result, err := w.llm.Synthesize(ctx, sessionsYAML, payments)
	if err != nil {
		_ = w.pr.RPC(ctx, "touch_persona_refresh", map[string]any{"p_email": c.Email}, nil)
		return err
	}

	summary, _ := json.Marshal(result.UsageSummary)
	profile, _ := json.Marshal(result.UserProfile)
	recs, _ := json.Marshal(result.UserRecommendation)

	return w.pr.RPC(ctx, "upsert_persona", map[string]any{
		"p_email":          c.Email,
		"p_pb_user_id":     pbUID,
		"p_summary":        json.RawMessage(summary),
		"p_profile":        json.RawMessage(profile),
		"p_recommendations": json.RawMessage(recs),
	}, nil)
}

func (w *Worker) waitRybbitSlot(ctx context.Context) error {
	w.rybbitMu.Lock()
	defer w.rybbitMu.Unlock()
	if !w.lastRybbitHit.IsZero() {
		wait := w.cfg.RybbitMinSpacing - time.Since(w.lastRybbitHit)
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	w.lastRybbitHit = time.Now()
	return nil
}

func (w *Worker) resolveAnalyticsUserID(ctx context.Context, email string) (string, error) {
	var rows []struct {
		AuthUserID string `json:"auth_user_id"`
	}
	q := url.Values{}
	q.Set("select", "auth_user_id")
	q.Set("email", "eq."+strings.ToLower(strings.TrimSpace(email)))
	q.Set("limit", "1")
	if err := w.pr.SelectService(ctx, "users", q, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 || rows[0].AuthUserID == "" {
		return "", fmt.Errorf("auth user id not found for %s", email)
	}
	return rows[0].AuthUserID, nil
}

// FetchProfile reads persona profile JSON for gateway/PWA handlers.
func FetchProfile(ctx context.Context, pr *postgrest.Client, email string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("select", "profile")
	q.Set("email", "eq."+email)
	q.Set("limit", "1")
	var rows []struct {
		Profile json.RawMessage `json:"profile"`
	}
	if err := pr.SelectService(ctx, "persona", q, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0].Profile, nil
}

// FetchRecommendations reads persona recommendations for Explore carousels.
func FetchRecommendations(ctx context.Context, pr *postgrest.Client, email string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("select", "recommendations")
	q.Set("email", "eq."+email)
	q.Set("limit", "1")
	var rows []struct {
		Recommendations json.RawMessage `json:"recommendations"`
	}
	if err := pr.SelectService(ctx, "persona", q, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0].Recommendations, nil
}
