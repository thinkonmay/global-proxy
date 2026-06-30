package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) ListPlans(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.URL.Query().Get("view")) == "credit" {
		h.listPlansCredit(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", strings.Join([]string{
		"name", "extendable", "total_hours", "total_days", "credit", "active",
		"configuration->max_duration",
		"policy->v4_policy->>CPU",
		"policy->v4_policy->>RAM",
		"policy->v4_policy->>GPU",
		"policy->v4_policy->>DISK",
		"policy->v4_policy->>only_cluster",
		"price->storage",
		"price->allowances",
		"price->VND",
		"price->USD",
		"price->IDR",
	}, ", "))
	q.Set("metadata->v4_hide", "is.null")
	if active := strings.TrimSpace(r.URL.Query().Get("active")); active == "" || active == "true" {
		q.Set("active", "eq.true")
	}
	if cluster := strings.TrimSpace(r.URL.Query().Get("cluster")); cluster != "" {
		q.Set("policy->v4_policy->>only_cluster", "eq."+cluster)
	}

	var rows []map[string]any
	if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) listPlansCredit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "credit,name")
	q.Set("active", "eq.true")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if len(rows) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "no plan available")
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) GetPlan(w http.ResponseWriter, r *http.Request) {
	planName := strings.TrimSpace(r.PathValue("planName"))
	if planName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan name required")
		return
	}
	view := strings.TrimSpace(r.URL.Query().Get("view"))
	if view == "" {
		view = "full"
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	switch view {
	case "policy":
		q := url.Values{}
		q.Set("select", "total_days,disk:configuration->>disk")
		q.Set("active", "eq.true")
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []struct {
			TotalDays *float64 `json:"total_days"`
			Disk      *string  `json:"disk"`
		}
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			httpx.WritePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			httpx.WriteError(w, http.StatusNotFound, fmt.Sprintf("plan %s not found", planName))
			return
		}
		disk := float64(0)
		if rows[0].Disk != nil {
			disk, _ = strconv.ParseFloat(*rows[0].Disk, 64)
		}
		httpx.WriteData(w, map[string]any{"total_days": rows[0].TotalDays, "disk": disk})
	case "price":
		currency := strings.TrimSpace(r.URL.Query().Get("currency"))
		if currency == "" {
			httpx.WriteError(w, http.StatusBadRequest, "missing currency")
			return
		}
		q := url.Values{}
		q.Set("select", fmt.Sprintf("price->%s", currency))
		q.Set("active", "eq.true")
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []map[string]json.RawMessage
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			httpx.WritePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			httpx.WriteError(w, http.StatusNotFound, fmt.Sprintf("plan %s not found", planName))
			return
		}
		raw, ok := rows[0][currency]
		if !ok {
			httpx.WriteError(w, http.StatusNotFound, "price not found")
			return
		}
		var amount float64
		if err := json.Unmarshal(raw, &amount); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httpx.WriteData(w, amount)
	case "credit":
		q := url.Values{}
		q.Set("select", "credit,name")
		q.Set("active", "eq.true")
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []map[string]any
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			httpx.WritePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			httpx.WriteError(w, http.StatusNotFound, fmt.Sprintf("plan %s not found", planName))
			return
		}
		httpx.WriteData(w, rows[0])
	default:
		q := url.Values{}
		q.Set("select", strings.Join([]string{
			"name", "extendable", "total_hours", "total_days", "credit",
			"configuration->max_duration",
			"policy->v4_policy->>CPU",
			"policy->v4_policy->>RAM",
			"policy->v4_policy->>GPU",
			"policy->v4_policy->>DISK",
			"policy->v4_policy->>only_cluster",
			"price->storage",
			"price->allowances",
			"price->VND",
			"price->USD",
			"price->IDR",
		}, ", "))
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []map[string]any
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			httpx.WritePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			httpx.WriteError(w, http.StatusNotFound, fmt.Sprintf("plan %s not found", planName))
			return
		}
		httpx.WriteData(w, rows[0])
	}
}
