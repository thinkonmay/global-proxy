package persona

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RybbitConfig struct {
	URL        string
	APIKey     string
	SiteDomain string
	HTTP       *http.Client
}

type Rybbit struct {
	baseURL    string
	apiKey     string
	siteID     string
	siteDomain string
	http       *http.Client
}

func NewRybbit(cfg RybbitConfig) (*Rybbit, error) {
	if cfg.URL == "" || cfg.APIKey == "" || cfg.SiteDomain == "" {
		return nil, fmt.Errorf("rybbit url, api key, and site domain required")
	}
	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	r := &Rybbit{
		baseURL:    strings.TrimRight(cfg.URL, "/"),
		apiKey:     cfg.APIKey,
		siteDomain: strings.TrimSpace(cfg.SiteDomain),
		http:       httpClient,
	}
	siteID, err := r.resolveSiteID(context.Background())
	if err != nil {
		return nil, err
	}
	r.siteID = siteID
	return r, nil
}

func (r *Rybbit) resolveSiteID(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/api/sites", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	resp, err := r.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("rybbit sites status %d: %s", resp.StatusCode, body)
	}
	var payload struct {
		Data []struct {
			SiteID string `json:"site_id"`
			Domain string `json:"domain"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	for _, site := range payload.Data {
		if site.Domain == r.siteDomain {
			return site.SiteID, nil
		}
	}
	return "", fmt.Errorf("rybbit site not found for domain %q", r.siteDomain)
}

func (r *Rybbit) FetchSessionYAML(ctx context.Context, pbUserID string) (string, error) {
	sessions, err := r.listSessions(ctx, pbUserID)
	if err != nil {
		return "", err
	}
	if len(sessions) == 0 {
		return "[]", nil
	}

	type simplifiedEvent struct {
		Name  string `yaml:"name"`
		Count int    `yaml:"count"`
	}
	type simplifiedSession struct {
		Language string            `yaml:"language"`
		Device   string            `yaml:"device"`
		Browser  string            `yaml:"browser"`
		OS       string            `yaml:"os"`
		Start    string            `yaml:"start"`
		Duration string            `yaml:"duration"`
		Events   []simplifiedEvent `yaml:"events"`
	}

	out := make([]simplifiedSession, 0, len(sessions))
	for _, s := range sessions {
		events := make([]simplifiedEvent, 0, len(s.Events))
		for name, count := range s.Events {
			events = append(events, simplifiedEvent{Name: name, Count: count})
		}
		out = append(out, simplifiedSession{
			Language: s.Language,
			Device:   s.DeviceType,
			Browser:  s.Browser,
			OS:       s.OS,
			Start:    s.Start.Format(time.DateTime),
			Duration: s.Duration.String(),
			Events:   events,
		})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

type sessionRow struct {
	SessionID       string
	Language        string
	DeviceType      string
	Browser         string
	OperatingSystem string
	SessionStart    string
	SessionEnd      string
}

type sessionDetail struct {
	Language   string
	DeviceType string
	Browser    string
	OS         string
	Start      time.Time
	Duration   time.Duration
	Events     map[string]int
}

func (r *Rybbit) listSessions(ctx context.Context, pbUserID string) ([]sessionDetail, error) {
	u := fmt.Sprintf("%s/api/sites/%s/sessions?user_id=%s", r.baseURL, r.siteID, pbUserID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rybbit sessions status %d: %s", resp.StatusCode, body)
	}
	var payload struct {
		Data []sessionRow `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	details := make([]sessionDetail, 0, len(payload.Data))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, row := range payload.Data {
		wg.Add(1)
		go func(row sessionRow) {
			defer wg.Done()
			detail, ok := r.fetchSession(ctx, row)
			if !ok {
				return
			}
			mu.Lock()
			details = append(details, detail)
			mu.Unlock()
		}(row)
	}
	wg.Wait()
	return details, nil
}

func (r *Rybbit) fetchSession(ctx context.Context, row sessionRow) (sessionDetail, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/sites/%s/sessions/%s", r.baseURL, r.siteID, row.SessionID), nil)
	if err != nil {
		return sessionDetail{}, false
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	resp, err := r.http.Do(req)
	if err != nil {
		return sessionDetail{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return sessionDetail{}, false
	}
	var payload struct {
		Data struct {
			Events []struct {
				EventName string         `json:"event_name"`
				Props     map[string]any `json:"props"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return sessionDetail{}, false
	}
	start, err := time.Parse(time.DateTime, row.SessionStart)
	if err != nil {
		return sessionDetail{}, false
	}
	end, err := time.Parse(time.DateTime, row.SessionEnd)
	if err != nil {
		end = start
	}
	events := map[string]int{}
	for _, ev := range payload.Data.Events {
		if ev.EventName == "" {
			continue
		}
		if p, ok := ev.Props["content"]; ok && p == "closed" {
			continue
		}
		events[ev.EventName]++
	}
	if len(events) == 0 {
		return sessionDetail{}, false
	}
	return sessionDetail{
		Language:   row.Language,
		DeviceType: row.DeviceType,
		Browser:    row.Browser,
		OS:         row.OperatingSystem,
		Start:      start,
		Duration:   end.Sub(start),
		Events:     events,
	}, true
}
