package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

// machineRow holds the minimal shape returned by get_machines that this handler needs.
type machineRow struct {
	ID int64 `json:"id"`
}

// machineAddonRow is one row from get_machine_addons with the originating machine_id injected.
type machineAddonRow struct {
	MachineID  int64           `json:"machine_id"`
	AddonID    int64           `json:"addon_id"`
	Name       string          `json:"name"`
	UnitCount  int64           `json:"unit_count"`
	UnitPrice  json.RawMessage `json:"unit_price"`
	CreatedAt  string          `json:"created_at"`
}

// addonChargeRow is one row from list_addon_charges with the originating machine_id injected.
type addonChargeRow struct {
	MachineID    int64   `json:"machine_id"`
	AddonName    string  `json:"addon_name"`
	UsageUnits   int64   `json:"usage_units"`
	BillableUnits int64  `json:"billable_units"`
	PricePerUnit float64 `json:"price_per_unit"`
	TotalAmount  int64   `json:"total_amount"`
}

// getMachines calls get_machines and returns the list of machine rows for the user.
func (h *Handler) getMachines(ctx context.Context, email string) ([]machineRow, error) {
	var rows []machineRow
	if err := h.pr.RPC(ctx, "get_machines", map[string]any{"p_email": email}, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// AddonCharges returns per-machine addon overage charges for the authenticated user.
// It fans out to list_addon_charges for each active machine and merges the results.
// GET /v1/billing/addon-charges
func (h *Handler) AddonCharges(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	machines, err := h.getMachines(ctx, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	merged := make([]addonChargeRow, 0)
	for _, m := range machines {
		var rows []struct {
			AddonName    string  `json:"addon_name"`
			UsageUnits   int64   `json:"usage_units"`
			BillableUnits int64  `json:"billable_units"`
			PricePerUnit float64 `json:"price_per_unit"`
			TotalAmount  int64   `json:"total_amount"`
		}
		if err := h.pr.RPC(ctx, "list_addon_charges", map[string]any{
			"p_email":      email,
			"p_machine_id": m.ID,
		}, &rows); err != nil {
			httpx.WriteUpstreamErr(w, err)
			return
		}
		for _, row := range rows {
			merged = append(merged, addonChargeRow{
				MachineID:    m.ID,
				AddonName:    row.AddonName,
				UsageUnits:   row.UsageUnits,
				BillableUnits: row.BillableUnits,
				PricePerUnit: row.PricePerUnit,
				TotalAmount:  row.TotalAmount,
			})
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"data": merged})
}

// ListActiveAddons returns all active addons for each machine owned by the authenticated user.
// It fans out to get_machine_addons per machine and merges the results with machine_id included.
// GET /v1/billing/addons
func (h *Handler) ListActiveAddons(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	machines, err := h.getMachines(ctx, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	merged := make([]machineAddonRow, 0)
	for _, m := range machines {
		var rows []struct {
			AddonID   int64           `json:"addon_id"`
			Name      string          `json:"name"`
			UnitCount int64           `json:"unit_count"`
			UnitPrice json.RawMessage `json:"unit_price"`
			CreatedAt string          `json:"created_at"`
		}
		if err := h.pr.RPC(ctx, "get_machine_addons", map[string]any{
			"p_machine_id": m.ID,
		}, &rows); err != nil {
			httpx.WriteUpstreamErr(w, err)
			return
		}
		for _, row := range rows {
			merged = append(merged, machineAddonRow{
				MachineID: m.ID,
				AddonID:   row.AddonID,
				Name:      row.Name,
				UnitCount: row.UnitCount,
				UnitPrice: row.UnitPrice,
				CreatedAt: row.CreatedAt,
			})
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"data": merged})
}

// SubscribeAddon subscribes the given addon to a specific machine for the authenticated user.
// Body: {"machine_id": <int>, "addon_id": <int>}
// POST /v1/billing/addons
func (h *Handler) SubscribeAddon(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	var body struct {
		MachineID int64 `json:"machine_id"`
		AddonID   int64 `json:"addon_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AddonID <= 0 || body.MachineID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "machine_id and addon_id required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "subscribe_addon", map[string]any{
		"p_email":      email,
		"p_machine_id": body.MachineID,
		"p_addon_id":   body.AddonID,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

// UnsubscribeAddon removes an addon from a specific machine for the authenticated user.
// Path: /v1/billing/addons/{addonId}  Query: ?machine_id=<int>
// DELETE /v1/billing/addons/{addonId}
func (h *Handler) UnsubscribeAddon(w http.ResponseWriter, r *http.Request) {
	addonID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("addonId")), 10, 64)
	if err != nil || addonID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid addon id")
		return
	}
	machineIDStr := strings.TrimSpace(r.URL.Query().Get("machine_id"))
	if machineIDStr == "" {
		httpx.WriteError(w, http.StatusBadRequest, "machine_id query parameter required")
		return
	}
	machineID, err := strconv.ParseInt(machineIDStr, 10, 64)
	if err != nil || machineID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "machine_id must be a positive integer")
		return
	}

	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "unsubscribe_addon", map[string]any{
		"p_email":      email,
		"p_machine_id": machineID,
		"p_addon_id":   addonID,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

// PayAddonCharges pays all outstanding addon charges across every machine for the authenticated user.
// POST /v1/billing/addon-charges/pay
func (h *Handler) PayAddonCharges(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), billingQueryTimeout)
	defer cancel()

	machines, err := h.getMachines(ctx, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}

	for _, m := range machines {
		// pay_addon_charges returns void; pass nil dest to skip decoding.
		if err := h.pr.RPC(ctx, "pay_addon_charges", map[string]any{
			"p_email":      email,
			"p_machine_id": m.ID,
		}, nil); err != nil {
			httpx.WriteUpstreamErr(w, fmt.Errorf("machine %d: %w", m.ID, err))
			return
		}
	}
	httpx.WriteData(w, true)
}
