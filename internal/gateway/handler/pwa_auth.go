package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
)

const pwaAuthTimeout = 5 * time.Second

type pwaUserAuth struct {
	Email  string
	UserID string
}

func pwaAuthFromRequest(ctx context.Context, rt http.RoundTripper, r *http.Request, issuer string) (pwaUserAuth, int, string) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return pwaUserAuth{}, http.StatusUnauthorized, "Unauthorized: No auth header"
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return pwaUserAuth{}, http.StatusBadRequest, "Missing issuer"
	}
	ctx, cancel := context.WithTimeout(ctx, pwaAuthTimeout)
	defer cancel()
	auth, err := pbUserAuth.Validate(ctx, issuer, authHeader, rt)
	if err != nil {
		status, msg := authErrFromValidate(err)
		return pwaUserAuth{}, status, msg
	}
	return pwaUserAuth{Email: auth.Email, UserID: auth.UserID}, 0, ""
}

func pwaAuthEmailMatch(auth pwaUserAuth, email string) (int, string) {
	if email == "" {
		return http.StatusBadRequest, "Missing email"
	}
	if !strings.EqualFold(auth.Email, email) {
		return http.StatusForbidden, "Unauthorized: Email mismatch"
	}
	return 0, ""
}

func (h *PWAHandler) isSuperuserEmail(ctx context.Context, email string) (bool, error) {
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

func readJSONBody(r *http.Request, dest any) error {
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, dest)
}
