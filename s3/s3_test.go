package s3

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Endpoint: "https://s3.example.test", Region: "us-east-1", Bucket: "examplebucket", PathStyle: true,
		AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
}

// TestSign_MatchesIndependentlyComputedSignature checks sign's output
// against a signature independently computed with openssl (the SigV4
// key-derivation chain and canonical request run by hand, not by this
// package) for a fixed request and clock, so a transcription bug in the
// canonical-request construction or key derivation cannot pass silently.
func TestSign_MatchesIndependentlyComputedSignature(t *testing.T) {
	client, err := NewClient(testConfig(), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	now, err := time.Parse("20060102T150405Z", "20130524T000000Z")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("no range", func(t *testing.T) {
		endpoint, _ := url.Parse(client.config.Endpoint)
		endpoint.Path = "/examplebucket/test.txt"
		request, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		client.sign(request, now, emptySHA256)
		want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, " +
			"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
			"Signature=2439098f0c88983cc33a28b2c90db99c9bff27c076c0052dea768076228cbfd3"
		if got := request.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		if got := request.Header.Get("X-Amz-Content-Sha256"); got != emptySHA256 {
			t.Errorf("X-Amz-Content-Sha256 = %q, want %q", got, emptySHA256)
		}
	})

	t.Run("with range", func(t *testing.T) {
		endpoint, _ := url.Parse(client.config.Endpoint)
		endpoint.Path = "/examplebucket/test.txt"
		request, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Range", "bytes=0-99")
		client.sign(request, now, emptySHA256)
		want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, " +
			"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
			"Signature=3607c7fb07a5ad9718b8fd00a9478317ce3c16dc19d72649b5baf5deb8766e70"
		if got := request.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
	})
}

func TestNewClient_Validation(t *testing.T) {
	base := testConfig()
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing endpoint", func(c *Config) { c.Endpoint = "" }},
		{"missing region", func(c *Config) { c.Region = "" }},
		{"missing bucket", func(c *Config) { c.Bucket = "" }},
		{"missing access key", func(c *Config) { c.AccessKeyID = "" }},
		{"missing secret key", func(c *Config) { c.SecretAccessKey = "" }},
		{"virtual-hosted style rejected", func(c *Config) { c.PathStyle = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := base
			tc.mutate(&config)
			if _, err := NewClient(config, nil); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestClient_Bucket(t *testing.T) {
	client, err := NewClient(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Bucket(); got != "examplebucket" {
		t.Errorf("Bucket() = %q, want %q", got, "examplebucket")
	}
}

func TestClient_Get_StreamsBodyAndForwardsRange(t *testing.T) {
	var gotPath, gotRange, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRange, gotAuth = r.URL.Path, r.Header.Get("Range"), r.Header.Get("Authorization")
		w.Header().Set("Content-Range", "bytes 0-3/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("clip"))
	}))
	defer server.Close()

	config := testConfig()
	config.Endpoint = server.URL
	client, err := NewClient(config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(context.Background(), "channel/video/clip.mp4", "bytes=0-3")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	if gotPath != "/examplebucket/channel/video/clip.mp4" {
		t.Errorf("upstream path = %q, want %q", gotPath, "/examplebucket/channel/video/clip.mp4")
	}
	if gotRange != "bytes=0-3" {
		t.Errorf("upstream Range = %q, want %q", gotRange, "bytes=0-3")
	}
	if gotAuth == "" {
		t.Error("upstream request was not signed")
	}
	if response.StatusCode != http.StatusPartialContent {
		t.Errorf("StatusCode = %d, want %d", response.StatusCode, http.StatusPartialContent)
	}
	if string(body) != "clip" {
		t.Errorf("body = %q, want %q", body, "clip")
	}
}

func TestClient_Get_NonOKStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	config := testConfig()
	config.Endpoint = server.URL
	client, err := NewClient(config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), "channel/video/clip.mp4", ""); err == nil {
		t.Fatal("want error for a 403 response, got nil")
	}
}

func TestClient_Get_RejectsAbsoluteKey(t *testing.T) {
	client, err := NewClient(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), "/channel/video/clip.mp4", ""); err == nil {
		t.Fatal("want error for a leading-slash key, got nil")
	}
}

func TestClient_List_ParsesResultsAndPagesByStartAfter(t *testing.T) {
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
	<IsTruncated>true</IsTruncated>
	<Contents><Key>inputs/quarry/one.mp4</Key><LastModified>2026-08-01T00:00:00.000Z</LastModified><Size>100</Size></Contents>
	<Contents><Key>inputs/quarry/two.mp4</Key><LastModified>2026-08-02T00:00:00.000Z</LastModified><Size>200</Size></Contents>
</ListBucketResult>`)
	}))
	defer server.Close()

	config := testConfig()
	config.Endpoint = server.URL
	client, err := NewClient(config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.List(context.Background(), "inputs/quarry/", "", 500)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotQuery.Get("list-type") != "2" || gotQuery.Get("prefix") != "inputs/quarry/" || gotQuery.Get("max-keys") != "500" || gotQuery.Get("start-after") != "" {
		t.Fatalf("upstream query = %v", gotQuery)
	}
	if len(result.Objects) != 2 || result.Objects[0].Key != "inputs/quarry/one.mp4" || result.Objects[0].Size != 100 ||
		result.Objects[1].Key != "inputs/quarry/two.mp4" || result.Objects[1].Size != 200 {
		t.Fatalf("List() objects = %+v", result.Objects)
	}
	wantModified := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if !result.Objects[0].LastModified.Equal(wantModified) {
		t.Fatalf("LastModified = %v, want %v", result.Objects[0].LastModified, wantModified)
	}
	if !result.IsTruncated || result.NextStartAfter != "inputs/quarry/two.mp4" {
		t.Fatalf("IsTruncated/NextStartAfter = %v/%q, want true/%q", result.IsTruncated, result.NextStartAfter, "inputs/quarry/two.mp4")
	}

	if _, err := client.List(context.Background(), "inputs/quarry/", result.NextStartAfter, 500); err != nil {
		t.Fatalf("List() page 2: %v", err)
	}
	if gotQuery.Get("start-after") != "inputs/quarry/two.mp4" {
		t.Fatalf("page 2 start-after = %q", gotQuery.Get("start-after"))
	}
}

func TestClient_List_RejectsEmptyPrefixAndBadMaxKeys(t *testing.T) {
	client, err := NewClient(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(context.Background(), "", "", 500); err == nil {
		t.Fatal("want error for an empty prefix, got nil")
	}
	if _, err := client.List(context.Background(), "/inputs/quarry/", "", 500); err == nil {
		t.Fatal("want error for a leading-slash prefix, got nil")
	}
	if _, err := client.List(context.Background(), "inputs/quarry/", "", 0); err == nil {
		t.Fatal("want error for max-keys 0, got nil")
	}
	if _, err := client.List(context.Background(), "inputs/quarry/", "", 1001); err == nil {
		t.Fatal("want error for max-keys 1001, got nil")
	}
}

func TestClient_Delete_SignsAndTreatsNotFoundAsSuccess(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(status)
	}))
	defer server.Close()

	config := testConfig()
	config.Endpoint = server.URL
	client, err := NewClient(config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(context.Background(), "inputs/quarry/one.mp4"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/examplebucket/inputs/quarry/one.mp4" || gotAuth == "" {
		t.Fatalf("upstream request = %s %s (auth set: %v)", gotMethod, gotPath, gotAuth != "")
	}

	status = http.StatusNotFound
	if err := client.Delete(context.Background(), "inputs/quarry/already-gone.mp4"); err != nil {
		t.Fatalf("Delete() of an already-absent key = %v, want nil (idempotent)", err)
	}

	status = http.StatusForbidden
	if err := client.Delete(context.Background(), "inputs/quarry/one.mp4"); err == nil {
		t.Fatal("Delete() with a 403 response returned nil error")
	}
}

func TestClient_Delete_RejectsAbsoluteKey(t *testing.T) {
	client, err := NewClient(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(context.Background(), "/inputs/quarry/one.mp4"); err == nil {
		t.Fatal("want error for a leading-slash key, got nil")
	}
}

func TestClient_Put_SignsUploadsBodyAndContentType(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotContentType, gotSignedHeaders string
	var gotBody []byte
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth, gotContentType = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotSignedHeaders = r.Header.Get("X-Amz-Content-Sha256")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	defer server.Close()

	config := testConfig()
	config.Endpoint = server.URL
	client, err := NewClient(config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"candidates":[]}`)
	if err := client.Put(context.Background(), "outputs/quarry/candidates/mission-1.json", payload, "application/json"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/examplebucket/outputs/quarry/candidates/mission-1.json" || gotAuth == "" {
		t.Fatalf("upstream request = %s %s (auth set: %v)", gotMethod, gotPath, gotAuth != "")
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("uploaded body = %q, want %q", gotBody, payload)
	}
	if gotSignedHeaders != hashHex(string(payload)) {
		t.Fatalf("X-Amz-Content-Sha256 = %q, want the real payload hash", gotSignedHeaders)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("Authorization = %q, want content-type among the signed headers", gotAuth)
	}

	status = http.StatusForbidden
	if err := client.Put(context.Background(), "outputs/quarry/candidates/mission-1.json", payload, "application/json"); err == nil {
		t.Fatal("Put() with a 403 response returned nil error")
	}
}

func TestClient_Put_RejectsAbsoluteKeyAndEmptyContentType(t *testing.T) {
	client, err := NewClient(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Put(context.Background(), "/outputs/quarry/candidates/mission-1.json", []byte("{}"), "application/json"); err == nil {
		t.Fatal("want error for a leading-slash key, got nil")
	}
	if err := client.Put(context.Background(), "outputs/quarry/candidates/mission-1.json", []byte("{}"), ""); err == nil {
		t.Fatal("want error for an empty content type, got nil")
	}
}
