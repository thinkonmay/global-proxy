package pwa

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
)

const pwaAuthTimeout = 5 * time.Second

func (h *Handler) isSuperuserEmail(ctx context.Context, email string) (bool, error) {
	if !h.pbAdmin.Configured() {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pwaAuthTimeout)
	defer cancel()
	var page struct {
		Items []struct {
			Email string `json:"email"`
		} `json:"items"`
	}
	q := url.Values{}
	q.Set("filter", fmt.Sprintf(`email=%q`, email))
	q.Set("perPage", "1")
	if err := h.pbAdmin.ListRecords(ctx, "_superusers", q, &page); err != nil {
		if pocketbase.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return len(page.Items) > 0, nil
}

func pbFileURL(baseURL, collectionID, recordID, filename string) string {
	if filename == "" || collectionID == "" || recordID == "" {
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/api/files/" + collectionID + "/" + recordID + "/" + filename
}
