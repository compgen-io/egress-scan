// Package approved loads the set of approved IB-IDs that egress IDs are compared
// against. Sources, in precedence order: an explicit IDs file, a directory of
// approved dataset files, an optional S3 prefix (approved-datasets bucket), and
// the APPROVED_IB_IDS environment variable.
//
// S3 is off by default and only engages when a bucket is configured, so the
// common path stays dependency-light and offline.
package approved

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/compgen-io/egress-scan/internal/idmatch"
)

// Source describes where approved IDs came from, surfaced in the output.
type Source struct {
	Kind  string // "ids_file", "approved_dir", "approved_datasets_s3", "env_list", "none"
	Count int
}

// S3API is the subset of the S3 client used here, so tests can stub it.
type S3API interface {
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Options configures the approved-ID load.
type Options struct {
	IDsFile        string // flat text file of approved IDs
	Dir            string // directory of approved dataset files
	S3Bucket       string // approved-datasets bucket (enables S3 when set)
	S3Prefix       string // key prefix to scan
	S3             S3API  // nil unless S3 is configured
	MaxObjects     int    // cap on S3 objects scanned
	MaxObjectBytes int64  // per-object size cap
}

// Load gathers approved IDs from the highest-precedence configured source.
func Load(ctx context.Context, m *idmatch.Matcher, o Options) (map[string]struct{}, Source, error) {
	switch {
	case o.IDsFile != "":
		ids, err := loadFromFile(m, o.IDsFile)
		return ids, Source{Kind: "ids_file", Count: len(ids)}, err

	case o.Dir != "":
		ids, err := loadFromDir(m, o.Dir)
		return ids, Source{Kind: "approved_dir", Count: len(ids)}, err

	case o.S3Bucket != "" && o.S3 != nil:
		ids, err := LoadFromS3(ctx, m, o.S3, o.S3Bucket, o.S3Prefix, o.MaxObjects, o.MaxObjectBytes)
		if err != nil {
			return nil, Source{}, err
		}
		if len(ids) > 0 {
			return ids, Source{Kind: "approved_datasets_s3", Count: len(ids)}, nil
		}
		// Empty S3 result falls back to the env list, matching risk_scoring.py.
		ids = loadFromEnv(m)
		return ids, Source{Kind: "env_list", Count: len(ids)}, nil

	default:
		ids := loadFromEnv(m)
		kind := "env_list"
		if len(ids) == 0 {
			kind = "none"
		}
		return ids, Source{Kind: kind, Count: len(ids)}, nil
	}
}

func loadFromFile(m *idmatch.Matcher, path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{})
	for id := range m.IBIDs(string(data)) {
		ids[id] = struct{}{}
	}
	// Also fold in normalised per-line tokens (covers a bare one-ID-per-line list).
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for id := range m.IBIDs(line) {
			ids[id] = struct{}{}
		}
	}
	return ids, nil
}

func loadFromDir(m *idmatch.Matcher, dir string) (map[string]struct{}, error) {
	ids := make(map[string]struct{})
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // best effort; skip unreadable files
		}
		for id := range m.IBIDs(string(data)) {
			ids[id] = struct{}{}
		}
		return nil
	})
	return ids, err
}

func loadFromEnv(m *idmatch.Matcher) map[string]struct{} {
	ids := make(map[string]struct{})
	raw := strings.TrimSpace(os.Getenv("APPROVED_IB_IDS"))
	if raw == "" {
		return ids
	}
	for _, tok := range strings.Split(raw, ",") {
		for id := range m.IBIDs(tok) {
			ids[id] = struct{}{}
		}
	}
	return ids
}

// LoadFromS3 lists the bucket/prefix and scans text-like objects for IB-IDs,
// honouring object-count and per-object size caps. Mirrors the approved-dataset
// scan in risk_scoring.py.
func LoadFromS3(ctx context.Context, m *idmatch.Matcher, client S3API, bucket, prefix string, maxObjects int, maxObjectBytes int64) (map[string]struct{}, error) {
	if maxObjects <= 0 {
		maxObjects = 500
	}
	if maxObjectBytes <= 0 {
		maxObjectBytes = 5 * 1024 * 1024
	}

	ids := make(map[string]struct{})
	scanned := 0
	var token *string

	for {
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, err
		}
		for _, obj := range out.Contents {
			if scanned >= maxObjects {
				return ids, nil
			}
			key := aws.ToString(obj.Key)
			if !isTextKey(key) || aws.ToInt64(obj.Size) > maxObjectBytes {
				continue
			}
			body, err := getObject(ctx, client, bucket, key, maxObjectBytes)
			if err != nil {
				continue // best effort; skip unreadable objects
			}
			for id := range m.IBIDs(string(body)) {
				ids[id] = struct{}{}
			}
			scanned++
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		token = out.NextContinuationToken
	}
	return ids, nil
}

func getObject(ctx context.Context, client S3API, bucket, key string, max int64) ([]byte, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(out.Body, max)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// isTextKey decides whether an S3 key is worth decoding as text, by extension.
func isTextKey(key string) bool {
	switch strings.ToLower(filepath.Ext(key)) {
	case ".csv", ".tsv", ".txt", ".json", ".ipynb", ".html", ".xml",
		".py", ".r", ".rmd", ".tab":
		return true
	}
	return false
}
