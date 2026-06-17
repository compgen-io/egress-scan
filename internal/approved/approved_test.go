package approved

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/compgen-io/egress-scan/internal/idmatch"
)

// stubS3 returns canned objects across two list pages and serves their bodies.
type stubS3 struct {
	objects map[string]string // key -> body
	pages   [][]string        // keys per ListObjectsV2 page
	calls   int
}

func (s *stubS3) ListObjectsV2(_ context.Context, _ *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	page := s.pages[s.calls]
	s.calls++
	var contents []s3types.Object
	for _, k := range page {
		contents = append(contents, s3types.Object{Key: aws.String(k), Size: aws.Int64(int64(len(s.objects[k])))})
	}
	truncated := s.calls < len(s.pages)
	out := &s3.ListObjectsV2Output{Contents: contents, IsTruncated: aws.Bool(truncated)}
	if truncated {
		out.NextContinuationToken = aws.String("next")
	}
	return out, nil
}

func (s *stubS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(s.objects[aws.ToString(in.Key)]))}, nil
}

func TestLoadFromS3(t *testing.T) {
	m, err := idmatch.New("")
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubS3{
		objects: map[string]string{
			"approved/a.csv":   "id\nIB-1001\nIB-1002\n",
			"approved/b.txt":   "subject IB_1003", // underscore normalises
			"approved/img.png": "binary IB-9999",  // non-text key: must be skipped
			"approved/c.json":  `{"id":"IB-1004"}`,
		},
		pages: [][]string{
			{"approved/a.csv", "approved/img.png"},
			{"approved/b.txt", "approved/c.json"},
		},
	}

	ids, err := LoadFromS3(context.Background(), m, stub, "bucket", "approved/", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"IB-1001", "IB-1002", "IB-1003", "IB-1004"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("expected %s from S3; got %v", want, ids)
		}
	}
	if _, ok := ids["IB-9999"]; ok {
		t.Errorf("non-text key (.png) should be skipped, but IB-9999 was found")
	}
	if stub.calls != 2 {
		t.Errorf("expected pagination across 2 pages; got %d list calls", stub.calls)
	}
}

func TestLoadPrecedenceFileOverEnv(t *testing.T) {
	m, _ := idmatch.New("")
	t.Setenv("APPROVED_IB_IDS", "IB-9000")

	dir := t.TempDir()
	f := dir + "/ids.txt"
	if err := os.WriteFile(f, []byte("IB-1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ids, src, err := Load(context.Background(), m, Options{IDsFile: f})
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != "ids_file" {
		t.Errorf("expected ids_file source; got %q", src.Kind)
	}
	if _, ok := ids["IB-1234"]; !ok {
		t.Errorf("expected IB-1234 from file; got %v", ids)
	}
	if _, ok := ids["IB-9000"]; ok {
		t.Errorf("env must not be consulted when a file is given")
	}
}
