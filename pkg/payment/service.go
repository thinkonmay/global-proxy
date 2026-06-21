package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const defaultPollInterval = 10 * time.Second

// Service owns outbound payment-provider HTTP (checkout + status poll).
// Replaces Postgres extensions.http in get_*_data and verify_all_transactions_v2.
type Service struct {
	pr        *postgrest.Client
	http      *http.Client
	log       *slog.Logger
	pollEvery time.Duration
	providers providerConfig
}

// Config configures checkout backfill and status polling intervals.
type Config struct {
	PollEvery     time.Duration
	CheckoutEvery time.Duration
	Providers     providerConfig
}

func NewService(pr *postgrest.Client, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	every := cfg.PollEvery
	if every <= 0 {
		every = defaultPollInterval
	}
	return &Service{
		pr:        pr,
		http:      &http.Client{Timeout: 15 * time.Second},
		log:       log,
		pollEvery: every,
		providers: cfg.Providers,
	}
}

// NewPoller is a legacy alias for NewService.
func NewPoller(pr *postgrest.Client, cfg Config, log *slog.Logger) *Service {
	return NewService(pr, cfg, log)
}

// Run starts checkout backfill and provider status polling until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	s.log.Info("payment checkout worker started", "every", s.pollEvery)
	go s.runCheckoutLoop(ctx)
	s.log.Info("payment status poller started", "every", s.pollEvery)
	go s.runPollLoop(ctx)
}

func (s *Service) runCheckoutLoop(ctx context.Context) {
	t := time.NewTicker(s.pollEvery)
	defer t.Stop()
	s.processPendingCheckouts(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.processPendingCheckouts(ctx)
		}
	}
}

func (s *Service) runPollLoop(ctx context.Context) {
	t := time.NewTicker(s.pollEvery)
	defer t.Stop()
	s.tickPoll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tickPoll(ctx)
		}
	}
}

func (s *Service) processPendingCheckouts(ctx context.Context) {
	txns, err := s.listNeedsCheckout(ctx)
	if err != nil {
		s.log.Warn("payment checkout: list", "err", err)
		return
	}
	for _, txn := range txns {
		if _, err := s.FillCheckout(ctx, txn.ID); err != nil {
			s.log.Warn("payment checkout: fill", "id", txn.ID, "provider", txn.Provider, "err", err)
			continue
		}
		s.log.Info("payment checkout filled", "id", txn.ID, "provider", txn.Provider)
	}
}

func (s *Service) listNeedsCheckout(ctx context.Context) ([]txnRow, error) {
	var rows []txnRow
	q := url.Values{}
	q.Set("select", "id,email,amount,currency,provider,status,data,metadata")
	q.Set("provider", "not.is.null")
	q.Set("or", "(data.is.null,data.eq.{})")
	q.Set("status", "in.(PENDING,_PENDING)")
	q.Set("limit", "20")
	if err := s.pr.SelectService(ctx, "transactions", q, &rows); err != nil {
		return nil, err
	}
	out := make([]txnRow, 0, len(rows))
	for _, row := range rows {
		if dataIsEmpty(row.Data) && strings.TrimSpace(row.Provider) != "" {
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *Service) tickPoll(ctx context.Context) {
	cfg := s.loadProviderConfig()
	txns, err := s.listPending(ctx)
	if err != nil {
		s.log.Warn("payment poller: list pending", "err", err)
		return
	}
	if len(txns) == 0 {
		return
	}
	var updated int
	for _, txn := range txns {
		status, ok := s.resolveStatus(ctx, cfg, txn)
		if !ok || status == "" || strings.EqualFold(status, txn.Status) {
			continue
		}
		if err := s.patchStatus(ctx, txn.ID, status); err != nil {
			s.log.Warn("payment poller: patch", "id", txn.ID, "err", err)
			continue
		}
		updated++
	}
	if updated > 0 {
		s.log.Info("payment poller tick", "pending", len(txns), "updated", updated)
	}
}

func (s *Service) listPending(ctx context.Context) ([]txnRow, error) {
	var rows []txnRow
	q := url.Values{}
	q.Set("select", "id,provider,status,data,expire_at")
	q.Set("status", "in.(PENDING,_PENDING)")
	q.Set("expire_at", "gt."+time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))
	if err := s.pr.SelectService(ctx, "transactions", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *Service) resolveStatus(ctx context.Context, cfg providerConfig, txn txnRow) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(txn.Provider)) {
	case "PAYOS":
		return s.pollPayOS(ctx, cfg.PayOS, txn)
	case "STRIPE":
		return s.pollStripe(ctx, cfg.Stripe, txn)
	case "PAYERMAX":
		return s.pollPayerMax(ctx, cfg.PayerMax, txn)
	default:
		return "", false
	}
}

func (s *Service) patchStatus(ctx context.Context, id int64, status string) error {
	q := url.Values{}
	q.Set("id", "eq."+formatID(id))
	return s.pr.Update(ctx, "transactions", q, map[string]any{"status": status}, nil)
}

func formatID(id int64) string {
	return fmt.Sprintf("%d", id)
}

type paymentError struct {
	msg string
}

func (e paymentError) Error() string { return e.msg }

func errNotFound(id int64) error {
	return paymentError{msg: fmt.Sprintf("transaction %d not found", id)}
}

func errUnsupportedCurrency(currency string) error {
	return paymentError{msg: fmt.Sprintf("currency %s not supported", currency)}
}

// EnrichDepositResult re-runs FillCheckout for each row returned by create_pocket_deposit_v4.
func (s *Service) EnrichDepositResult(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var rows []struct {
		ID   int64           `json:"id"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return raw, err
	}
	for i := range rows {
		if !dataIsEmpty(rows[i].Data) {
			continue
		}
		data, err := s.FillCheckout(ctx, rows[i].ID)
		if err != nil {
			return raw, err
		}
		rows[i].Data = data
	}
	return json.Marshal(rows)
}
