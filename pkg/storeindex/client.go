package storeindex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultIndex = "catalog-stores"

const defaultTimeout = 5 * time.Second

// Document is the Elasticsearch catalog store record (full Steam metadata lives here).
type Document struct {
	ID                int64          `json:"id"`
	Name              string         `json:"name,omitempty"`
	CodeName          string         `json:"code_name,omitempty"`
	Type              string         `json:"type,omitempty"`
	Genres            []string       `json:"genres,omitempty"`
	HeaderImage       string         `json:"header_image,omitempty"`
	ShortDescription  string         `json:"short_description,omitempty"`
	DetailedDescription string       `json:"detailed_description,omitempty"`
	Queue             int64          `json:"queue,omitempty"`
	Benchmarks        map[string]any `json:"benchmarks,omitempty"`
	MetadataLocale    map[string]any `json:"metadata_locale,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	UpdatedAt         time.Time      `json:"updated_at,omitempty"`
}

// SearchHit matches the legacy search_stores RPC row shape for API compatibility.
type SearchHit struct {
	ID                   int64          `json:"id"`
	Name                 string         `json:"name"`
	CodeName             string         `json:"code_name"`
	Publishers           any            `json:"publishers"`
	SupportInfo          any            `json:"support_info"`
	ShortDescription     string         `json:"short_description"`
	DetailedDescription  string         `json:"detailed_description"`
	HeaderImage          string         `json:"header_image"`
	PCRequirements       any            `json:"pc_requirements"`
	Screenshots          any            `json:"screenshots"`
	Genres               any            `json:"genres"`
	Type                 string         `json:"type"`
	Queue                int64          `json:"queue"`
	Benchmarks           map[string]any `json:"benchmarks,omitempty"`
	MetadataLocale       map[string]any `json:"metadata_locale,omitempty"`
	Rank                 float64        `json:"rank"`
}

// Client indexes and searches catalog store documents in Elasticsearch.
type Client struct {
	esURL string
	index string
	http  *http.Client
}

func NewClient(esURL, index string) *Client {
	index = strings.TrimSpace(index)
	if index == "" {
		index = defaultIndex
	}
	return &Client{
		esURL: strings.TrimRight(strings.TrimSpace(esURL), "/"),
		index: index,
		http:  &http.Client{Timeout: defaultTimeout},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.esURL != ""
}

func (c *Client) Index(ctx context.Context, doc Document) error {
	if !c.Enabled() {
		return nil
	}
	if doc.ID <= 0 {
		return fmt.Errorf("invalid store id")
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/%s/_doc/%d", c.esURL, c.index, doc.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("elasticsearch index status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *Client) Get(ctx context.Context, id int64) (*Document, error) {
	if !c.Enabled() {
		return nil, nil
	}
	url := fmt.Sprintf("%s/%s/_doc/%d", c.esURL, c.index, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("elasticsearch get status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var payload struct {
		Source Document `json:"_source"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Source.ID == 0 {
		payload.Source.ID = id
	}
	return &payload.Source, nil
}

func (c *Client) Search(ctx context.Context, query string, limit int) ([]SearchHit, error) {
	if !c.Enabled() {
		return nil, nil
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}

	var body map[string]any
	if isNumericQuery(query) {
		id, _ := strconv.ParseInt(query, 10, 64)
		body = map[string]any{
			"query": map[string]any{"term": map[string]any{"id": id}},
			"size":  limit,
		}
		// Preserve legacy id lookup rank for API compatibility.
		hits, err := c.searchRequest(ctx, body)
		if err != nil {
			return nil, err
		}
		for i := range hits {
			hits[i].Rank = 2.0
		}
		return hits, nil
	} else {
		body = map[string]any{
			"query": map[string]any{
				"multi_match": map[string]any{
					"query":  query,
					"fields": []string{"name^3", "short_description^2", "detailed_description", "genres"},
					"type":   "best_fields",
				},
			},
			"size": limit,
		}
	}
	return c.searchRequest(ctx, body)
}

func (c *Client) SearchBatch(ctx context.Context, queries []string) ([]SearchHit, error) {
	if !c.Enabled() {
		return nil, nil
	}
	out := make([]SearchHit, 0, len(queries))
	seen := make(map[int64]struct{}, len(queries))
	for _, q := range queries {
		hits, err := c.Search(ctx, q, 1)
		if err != nil {
			return nil, err
		}
		if len(hits) == 0 {
			continue
		}
		h := hits[0]
		if _, ok := seen[h.ID]; ok {
			continue
		}
		seen[h.ID] = struct{}{}
		out = append(out, h)
	}
	return out, nil
}

func (c *Client) searchRequest(ctx context.Context, body map[string]any) ([]SearchHit, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.esURL+"/"+c.index+"/_search", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("elasticsearch search status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var result struct {
		Hits struct {
			Hits []struct {
				Score  float64  `json:"_score"`
				Source Document `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	out := make([]SearchHit, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		out = append(out, documentToSearchHit(hit.Source, hit.Score))
	}
	return out, nil
}

func DocumentFromSteam(appID int64, name string, genres []string, metadata map[string]any) Document {
	doc := Document{
		ID:       appID,
		Name:     name,
		Type:     "STEAM",
		Genres:   genres,
		Metadata: metadata,
	}
	if metadata == nil {
		return doc
	}
	if v, ok := metadata["header_image"].(string); ok {
		doc.HeaderImage = v
	}
	if v, ok := metadata["short_description"].(string); ok {
		doc.ShortDescription = v
	}
	if v, ok := metadata["detailed_description"].(string); ok {
		doc.DetailedDescription = v
	}
	return doc
}

func documentToSearchHit(doc Document, score float64) SearchHit {
	rank := score
	if rank <= 0 {
		rank = 1
	}
	meta := doc.Metadata
	hit := SearchHit{
		ID:                  doc.ID,
		Name:                doc.Name,
		CodeName:            doc.CodeName,
		ShortDescription:    doc.ShortDescription,
		DetailedDescription: doc.DetailedDescription,
		HeaderImage:         doc.HeaderImage,
		Type:                doc.Type,
		Queue:               doc.Queue,
		Benchmarks:          doc.Benchmarks,
		MetadataLocale:      doc.MetadataLocale,
		Rank:                rank,
		Genres:              genresToJSON(doc.Genres),
	}
	if meta != nil {
		hit.Publishers = meta["publishers"]
		hit.SupportInfo = meta["support_info"]
		hit.PCRequirements = meta["pc_requirements"]
		hit.Screenshots = meta["screenshots"]
		if hit.ShortDescription == "" {
			if v, ok := meta["short_description"].(string); ok {
				hit.ShortDescription = v
			}
		}
		if hit.DetailedDescription == "" {
			if v, ok := meta["detailed_description"].(string); ok {
				hit.DetailedDescription = v
			}
		}
		if hit.HeaderImage == "" {
			if v, ok := meta["header_image"].(string); ok {
				hit.HeaderImage = v
			}
		}
	}
	return hit
}

func genresToJSON(genres []string) any {
	if len(genres) == 0 {
		return []any{}
	}
	out := make([]any, len(genres))
	for i, g := range genres {
		out[i] = g
	}
	return out
}

func isNumericQuery(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
