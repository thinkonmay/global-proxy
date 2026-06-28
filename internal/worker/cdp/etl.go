package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	cdprollup "github.com/thinkonmay/global-proxy/api/pkg/cdp"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/rybbit"
)

type Handler struct {
	pr *postgrest.Client
}

func New(pr *postgrest.Client) *Handler {
	return &Handler{pr: pr}
}

// Start runs the Rybbit CH → Postgres batch ETL loop (CDP-3b).
func (h *Handler) Start(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	ec := cfg.CDP.FrontendETL
	if !ec.Enabled {
		return nil
	}
	if cfg.CDP.RybbitSiteID <= 0 {
		return fmt.Errorf("cdp.rybbitSiteId required when frontend ETL enabled")
	}
	if log == nil {
		log = slog.Default()
	}
	every, err := time.ParseDuration(ec.Every)
	if err != nil {
		return fmt.Errorf("cdp.frontendETL.every: %w", err)
	}
	chConn, err := rybbit.OpenCH(rybbit.ConfigFromGateway(cfg.CDP.RybbitClickHouse))
	if err != nil {
		return err
	}
	days := ec.Days
	if days <= 0 {
		days = 30
	}
	etl := &etlWorker{
		pr:     h.pr,
		rybbit: rybbit.NewQuerier(chConn),
		siteID: cfg.CDP.RybbitSiteID,
		days:   days,
		log:    log,
	}
	go etl.run(ctx, every)
	log.Info("cdp frontend etl started", "every", every, "site_id", cfg.CDP.RybbitSiteID, "days", days)
	return nil
}

type etlWorker struct {
	pr     *postgrest.Client
	rybbit *rybbit.Querier
	siteID int
	days   int
	log    *slog.Logger
}

func (e *etlWorker) run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	e.syncOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			e.log.Info("cdp frontend etl stopped")
			return
		case <-ticker.C:
			e.syncOnce(ctx)
		}
	}
}

func (e *etlWorker) syncOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	rollups, err := e.rybbit.RollupsBySite(ctx, e.siteID, e.days)
	if err != nil {
		e.log.Warn("cdp frontend etl: rybbit query failed", "err", err)
		return
	}
	if len(rollups) == 0 {
		return
	}

	userIDs := make([]string, 0, len(rollups))
	for _, r := range rollups {
		if id := strings.TrimSpace(r.UserID); id != "" {
			userIDs = append(userIDs, id)
		}
	}
	emailByUser := e.resolveEmails(ctx, userIDs)
	syncedAt := time.Now().UTC()
	wrote := 0
	for _, r := range rollups {
		email := emailByUser[strings.TrimSpace(r.UserID)]
		if email == "" {
			continue
		}
		payload, err := json.Marshal(cdprollup.BuildFrontendRollup(
			e.days, r.Pageviews, r.CustomEvents, r.Sessions, r.TopPaths, r.TopEvents, r.LastSeen, syncedAt,
		))
		if err != nil {
			continue
		}
		if err := e.pr.RPC(ctx, "upsert_cdp_frontend_rollup", map[string]any{
			"p_email":   email,
			"p_payload": json.RawMessage(payload),
		}, nil); err != nil {
			e.log.Warn("cdp frontend etl: upsert failed", "email", email, "err", err)
			continue
		}
		wrote++
	}
	e.log.Info("cdp frontend etl tick complete", "rybbit_users", len(rollups), "upserted", wrote)
}

func (e *etlWorker) resolveEmails(ctx context.Context, userIDs []string) map[string]string {
	out := make(map[string]string, len(userIDs))
	if len(userIDs) == 0 {
		return out
	}
	filter := "in.(" + strings.Join(userIDs, ",") + ")"

	var personaRows []struct {
		Email    string `json:"email"`
		PBUserID string `json:"pb_user_id"`
	}
	q := url.Values{}
	q.Set("select", "email,pb_user_id")
	q.Set("pb_user_id", filter)
	if err := e.pr.SelectService(ctx, "persona", q, &personaRows); err == nil {
		for _, row := range personaRows {
			if row.Email != "" && row.PBUserID != "" {
				out[row.PBUserID] = strings.ToLower(row.Email)
			}
		}
	}

	missing := make([]string, 0)
	for _, id := range userIDs {
		if out[id] == "" {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return out
	}
	missingFilter := "in.(" + strings.Join(missing, ",") + ")"
	var userRows []struct {
		Email      string `json:"email"`
		AuthUserID string `json:"auth_user_id"`
	}
	uq := url.Values{}
	uq.Set("select", "email,auth_user_id")
	uq.Set("auth_user_id", missingFilter)
	if err := e.pr.SelectService(ctx, "users", uq, &userRows); err == nil {
		for _, row := range userRows {
			if row.Email != "" && row.AuthUserID != "" {
				out[row.AuthUserID] = strings.ToLower(row.Email)
			}
		}
	}
	return out
}
