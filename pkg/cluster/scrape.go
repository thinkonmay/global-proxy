package cluster

import (
	"context"
)

// AppAccessUsage row from global Postgres addon usage RPCs.
type AppAccessUsage struct {
	Usage  int64
	Email  string
	Domain string
}

// BucketUsage row from global Postgres bucket usage RPCs.
type BucketUsage struct {
	SizeMB     int64
	BucketName string
	Email      string
	Domain     string
}

// LLMUsage row from global Postgres infra.user_llm_access.
type LLMUsage struct {
	Usage  int64
	Email  string
	Domain string
}

func ListAppAccessUsage(ctx context.Context, pr interface {
	RPC(ctx context.Context, name string, args any, dest any) error
}) ([]AppAccessUsage, error) {
	var rows []struct {
		Email  string `json:"email"`
		Usage  int64  `json:"usage"`
		Domain string `json:"domain"`
	}
	if err := pr.RPC(ctx, "list_addon_app_access_usage_v1", nil, &rows); err != nil {
		return nil, err
	}
	out := make([]AppAccessUsage, 0, len(rows))
	for _, row := range rows {
		out = append(out, AppAccessUsage{
			Usage:  row.Usage,
			Email:  row.Email,
			Domain: row.Domain,
		})
	}
	return out, nil
}

func ListBucketUsage(ctx context.Context, pr interface {
	RPC(ctx context.Context, name string, args any, dest any) error
}) ([]BucketUsage, error) {
	var rows []struct {
		Email      string `json:"email"`
		BucketName string `json:"bucket_name"`
		SizeBytes  int64  `json:"size_bytes"`
		Domain     string `json:"domain"`
	}
	if err := pr.RPC(ctx, "list_addon_bucket_usage_v1", nil, &rows); err != nil {
		return nil, err
	}
	out := make([]BucketUsage, 0, len(rows))
	for _, row := range rows {
		if row.SizeBytes <= 0 {
			continue
		}
		out = append(out, BucketUsage{
			SizeMB:     row.SizeBytes / 1024 / 1024,
			BucketName: row.BucketName,
			Email:      row.Email,
			Domain:     row.Domain,
		})
	}
	return out, nil
}

func ListLLMUsage(ctx context.Context, pr interface {
	RPC(ctx context.Context, name string, args any, dest any) error
}) ([]LLMUsage, error) {
	var rows []struct {
		Email  string `json:"email"`
		Usage  int64  `json:"usage"`
		Domain string `json:"domain"`
	}
	if err := pr.RPC(ctx, "list_addon_llm_usage_v1", nil, &rows); err != nil {
		return nil, err
	}
	out := make([]LLMUsage, 0, len(rows))
	for _, row := range rows {
		out = append(out, LLMUsage{
			Usage:  row.Usage,
			Email:  row.Email,
			Domain: row.Domain,
		})
	}
	return out, nil
}
