package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
)

type pbListPage struct {
	Items      []json.RawMessage `json:"items"`
	TotalPages int               `json:"totalPages"`
}

// AppAccessUsage row from node PocketBase app_access collection.
type AppAccessUsage struct {
	Usage int64
	Email string
}

// BucketUsage row from node PocketBase buckets collection.
type BucketUsage struct {
	SizeMB     int64
	BucketName string
	Email      string
}

// LLMUsage row from node PocketBase llmModels collection.
type LLMUsage struct {
	Usage int64
	Email string
}

func ListAppAccessUsage(ctx context.Context, pb *pocketbase.Client) ([]AppAccessUsage, error) {
	return listUsage(ctx, pb, "app_access", "usage,expand.user.email", "(usage>0)", func(item map[string]any) (AppAccessUsage, bool) {
		usage, _ := item["usage"].(float64)
		if usage <= 0 {
			return AppAccessUsage{}, false
		}
		email := expandUserEmail(item)
		if email == "" {
			return AppAccessUsage{}, false
		}
		return AppAccessUsage{Usage: int64(usage), Email: email}, true
	})
}

func ListBucketUsage(ctx context.Context, pb *pocketbase.Client) ([]BucketUsage, error) {
	return listUsage(ctx, pb, "buckets", "size,bucket_name,expand.user.email", "(size>0)", func(item map[string]any) (BucketUsage, bool) {
		size, _ := item["size"].(float64)
		if size <= 0 {
			return BucketUsage{}, false
		}
		name, _ := item["bucket_name"].(string)
		email := expandUserEmail(item)
		if email == "" || name == "" {
			return BucketUsage{}, false
		}
		return BucketUsage{
			SizeMB:     int64(size) / 1024 / 1024,
			BucketName: name,
			Email:      email,
		}, true
	})
}

func ListLLMUsage(ctx context.Context, pb *pocketbase.Client) ([]LLMUsage, error) {
	return listUsage(ctx, pb, "llmModels", "usage,expand.user.email", "(usage>0)", func(item map[string]any) (LLMUsage, bool) {
		usage, _ := item["usage"].(float64)
		if usage <= 0 {
			return LLMUsage{}, false
		}
		email := expandUserEmail(item)
		if email == "" {
			return LLMUsage{}, false
		}
		return LLMUsage{Usage: int64(usage), Email: email}, true
	})
}

func listUsage[T any](
	ctx context.Context,
	pb *pocketbase.Client,
	collection, fields, filter string,
	mapRow func(map[string]any) (T, bool),
) ([]T, error) {
	out := make([]T, 0)
	page := 1
	for {
		q := url.Values{}
		q.Set("fields", fields)
		q.Set("expand", "user")
		q.Set("perPage", "500")
		q.Set("filter", filter)
		q.Set("page", strconv.Itoa(page))
		var resp pbListPage
		if err := pb.ListRecords(ctx, collection, q, &resp); err != nil {
			return nil, fmt.Errorf("%s: %w", collection, err)
		}
		for _, raw := range resp.Items {
			var item map[string]any
			if err := json.Unmarshal(raw, &item); err != nil {
				continue
			}
			if row, ok := mapRow(item); ok {
				out = append(out, row)
			}
		}
		totalPages := resp.TotalPages
		if totalPages <= 0 {
			totalPages = 1
		}
		if page >= totalPages {
			break
		}
		page++
	}
	return out, nil
}

func expandUserEmail(item map[string]any) string {
	expand, _ := item["expand"].(map[string]any)
	if expand == nil {
		return ""
	}
	user, _ := expand["user"].(map[string]any)
	if user == nil {
		return ""
	}
	email, _ := user["email"].(string)
	return email
}
