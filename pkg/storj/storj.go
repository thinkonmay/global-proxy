package storj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	aconf "github.com/aws/aws-sdk-go-v2/config"
	awscred "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"storj.io/uplink"
	"storj.io/uplink/edge"
)

var edgeConfig = edge.Config{
	AuthServiceAddress: "auth.storjshare.io:7777",
}

// Object mirrors node PocketBase file list entries.
type Object struct {
	Key     string  `json:"key"`
	Created *string `json:"created,omitempty"`
	Size    *int64  `json:"size,omitempty"`
}

// Client wraps a Storj uplink project for user bucket operations.
type Client struct {
	expiration time.Duration
	access     *uplink.Access
	project    *uplink.Project
	ctx        context.Context
}

func New(accessGrant string, expiration time.Duration) (*Client, error) {
	if strings.TrimSpace(accessGrant) == "" {
		return nil, fmt.Errorf("storj access grant required")
	}
	if expiration <= 0 {
		expiration = 24 * time.Hour
	}
	ctx := context.Background()
	access, err := uplink.ParseAccess(accessGrant)
	if err != nil {
		return nil, fmt.Errorf("parse storj access: %w", err)
	}
	project, err := uplink.OpenProject(ctx, access)
	if err != nil {
		return nil, fmt.Errorf("open storj project: %w", err)
	}
	return &Client{
		expiration: expiration,
		access:     access,
		project:    project,
		ctx:        ctx,
	}, nil
}

func (c *Client) Close() {
	if c != nil && c.project != nil {
		c.project.Close()
	}
}

func (c *Client) CreateBucket(bucketName string) error {
	if _, err := c.project.StatBucket(c.ctx, bucketName); err == nil {
		return nil
	}
	_, err := c.project.EnsureBucket(c.ctx, bucketName)
	return err
}

func (c *Client) ListObjects(bucketName, path string) ([]Object, error) {
	result := make([]Object, 0)
	objs := c.project.ListObjects(c.ctx, bucketName, &uplink.ListObjectsOptions{
		Prefix:    path,
		Recursive: false,
		System:    true,
	})
	if err := objs.Err(); err != nil {
		return nil, err
	}
	for objs.Next() {
		obj := objs.Item()
		if obj == nil {
			continue
		}
		row := Object{Key: obj.Key}
		if !obj.IsPrefix {
			t := obj.System.Created.Format(time.RFC3339)
			row.Created = &t
			size := obj.System.ContentLength
			row.Size = &size
		}
		result = append(result, row)
	}
	return result, nil
}

func (c *Client) DownloadableURL(bucketName, objectName string, duration time.Duration) (string, error) {
	if objectName == "" || strings.HasSuffix(objectName, "/") {
		return "", fmt.Errorf("invalid object name")
	}
	if duration <= 0 {
		duration = 15 * time.Minute
	}
	restrictedAccess, err := c.access.Share(uplink.Permission{
		NotAfter:      time.Now().Add(duration),
		AllowDownload: true,
		AllowList:     true,
	}, uplink.SharePrefix{Bucket: bucketName, Prefix: objectName})
	if err != nil {
		return "", err
	}
	credentials, err := edgeConfig.RegisterAccess(c.ctx, restrictedAccess, &edge.RegisterAccessOptions{Public: true})
	if err != nil {
		return "", err
	}
	return edge.JoinShareURL("https://link.storjshare.io",
		credentials.AccessKeyID,
		bucketName,
		objectName,
		&edge.ShareURLOptions{Raw: true},
	)
}

func (c *Client) UploadableURL(bucketName, objectName string, duration time.Duration) (string, error) {
	if objectName == "" || strings.HasSuffix(objectName, "/") {
		return "", fmt.Errorf("invalid object name")
	}
	if duration <= 0 {
		duration = 15 * time.Minute
	}
	if duration > 24*time.Hour {
		duration = 24 * time.Hour
	}
	restrictedAccess, err := c.access.Share(uplink.Permission{
		NotAfter:    time.Now().Add(duration),
		AllowUpload: true,
	}, uplink.SharePrefix{Bucket: bucketName, Prefix: objectName})
	if err != nil {
		return "", err
	}
	credentials, err := edgeConfig.RegisterAccess(c.ctx, restrictedAccess, &edge.RegisterAccessOptions{Public: false})
	if err != nil {
		return "", err
	}
	cfg, err := aconf.LoadDefaultConfig(c.ctx,
		aconf.WithCredentialsProvider(awscred.NewStaticCredentialsProvider(credentials.AccessKeyID, credentials.SecretKey, "")),
		aconf.WithRegion("us-east-1"),
	)
	if err != nil {
		return "", err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(credentials.Endpoint)
		o.UsePathStyle = true
	})
	presignClient := s3.NewPresignClient(client)
	req, err := presignClient.PresignPutObject(c.ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}, s3.WithPresignExpires(duration))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (c *Client) BucketSize(bucketName string) (int64, error) {
	objs := c.project.ListObjects(c.ctx, bucketName, &uplink.ListObjectsOptions{
		Recursive: true,
		System:    true,
	})
	if err := objs.Err(); err != nil {
		return 0, err
	}
	var sum int64
	for objs.Next() {
		obj := objs.Item()
		if obj != nil && !obj.IsPrefix {
			sum += obj.System.ContentLength
		}
	}
	return sum, nil
}
