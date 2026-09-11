// Package s3 is a dependency-free SigV4 client for one S3-compatible,
// path-style bucket: no SDK, no vendor lock-in beyond the standard
// library. Get streams a response body directly (e.g. serving a
// <video> tag's Range requests through an app server without ever
// holding the whole file in memory or handing the browser a credential
// of its own); List and Delete support prefix-scoped operator cleanup;
// Put uploads a small in-memory payload (SigV4 header auth signs the
// exact payload hash up front, so it needs the complete body anyway).
// Extracted from fulcrum-labs/quarry's store package (its first
// consumer, still an in-memory-object-only client — no multipart);
// fulcrum-labs/foundry's capabilityplane/object.go is a fuller
// ArtifactStore-shaped client with multipart upload that this package
// does not yet cover — extend this package rather than building a
// second one if that need arrives here too.
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Config names the read-only bucket this client streams from and the
// credentials it signs requests with.
type Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	PathStyle       bool
	AccessKeyID     string
	SecretAccessKey string
}

// Client issues SigV4-signed GET requests against one configured bucket.
type Client struct {
	config Config
	http   *http.Client
}

// NewClient validates config and captures the HTTP client requests are
// issued through; a nil httpClient defaults to http.DefaultClient.
func NewClient(config Config, httpClient *http.Client) (*Client, error) {
	if config.Endpoint == "" || config.Region == "" || config.Bucket == "" ||
		config.AccessKeyID == "" || config.SecretAccessKey == "" {
		return nil, errors.New("store client requires endpoint, region, bucket, and credentials")
	}
	if !config.PathStyle {
		return nil, errors.New("store client requires path-style addressing")
	}
	if _, err := url.Parse(config.Endpoint); err != nil {
		return nil, fmt.Errorf("store endpoint: %w", err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{config: config, http: httpClient}, nil
}

// Bucket returns the bucket this client is configured for, so a caller
// holding an independently-sourced object reference can refuse to fetch a
// key whose reference names a different bucket.
func (c *Client) Bucket() string { return c.config.Bucket }

// Get issues a signed GET for key (a bucket-relative path with no leading
// slash), forwarding rangeHeader — the caller's own incoming Range header
// value, or "" for none — upstream unmodified so Range requests (video
// seeking) pass through untouched. The caller must close the returned
// response's body; on a non-2xx response Get itself closes the body and
// returns an error instead.
func (c *Client) Get(ctx context.Context, key, rangeHeader string) (*http.Response, error) {
	if strings.TrimSpace(key) == "" || strings.HasPrefix(key, "/") {
		return nil, errors.New("store key must be a non-empty bucket-relative path")
	}
	endpoint, err := url.Parse(c.config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("store endpoint: %w", err)
	}
	endpoint.Path = "/" + c.config.Bucket + "/" + key
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}
	c.sign(request, time.Now().UTC(), emptySHA256)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		return nil, fmt.Errorf("store GET %s: %s: %s", key, response.Status, string(body))
	}
	return response, nil
}

// ObjectSummary is one object a List call found.
type ObjectSummary struct {
	Key          string
	LastModified time.Time
	Size         int64
}

// ListResult is one page of a List call. A caller that needs every object
// under prefix pages by passing NextStartAfter back in as startAfter until
// IsTruncated is false.
type ListResult struct {
	Objects        []ObjectSummary
	IsTruncated    bool
	NextStartAfter string
}

type listBucketResultXML struct {
	IsTruncated bool `xml:"IsTruncated"`
	Contents    []struct {
		Key          string    `xml:"Key"`
		LastModified time.Time `xml:"LastModified"`
		Size         int64     `xml:"Size"`
	} `xml:"Contents"`
}

// List issues a signed ListObjectsV2 GET, returning up to maxKeys objects
// whose key starts with prefix (bucket-relative, no leading slash) and
// sorts after startAfter ("" for the first page). prefix is required — this
// never lists the whole bucket root, matching the same
// operate-under-one-prefix discipline Get already enforces on reads.
func (c *Client) List(ctx context.Context, prefix, startAfter string, maxKeys int) (ListResult, error) {
	if strings.TrimSpace(prefix) == "" || strings.HasPrefix(prefix, "/") {
		return ListResult{}, errors.New("store list prefix must be a non-empty bucket-relative path")
	}
	if maxKeys < 1 || maxKeys > 1000 {
		return ListResult{}, errors.New("store list max keys must be between 1 and 1000")
	}
	endpoint, err := url.Parse(c.config.Endpoint)
	if err != nil {
		return ListResult{}, fmt.Errorf("store endpoint: %w", err)
	}
	endpoint.Path = "/" + c.config.Bucket
	query := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {strconv.Itoa(maxKeys)}}
	if startAfter != "" {
		query.Set("start-after", startAfter)
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return ListResult{}, err
	}
	c.sign(request, time.Now().UTC(), emptySHA256)
	response, err := c.http.Do(request)
	if err != nil {
		return ListResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return ListResult{}, err
	}
	if response.StatusCode != http.StatusOK {
		return ListResult{}, fmt.Errorf("store LIST %s: %s: %s", prefix, response.Status, string(body))
	}
	var parsed listBucketResultXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return ListResult{}, fmt.Errorf("store LIST %s: malformed response: %w", prefix, err)
	}
	result := ListResult{IsTruncated: parsed.IsTruncated, Objects: make([]ObjectSummary, len(parsed.Contents))}
	for i, entry := range parsed.Contents {
		result.Objects[i] = ObjectSummary{Key: entry.Key, LastModified: entry.LastModified, Size: entry.Size}
	}
	if result.IsTruncated && len(result.Objects) > 0 {
		result.NextStartAfter = result.Objects[len(result.Objects)-1].Key
	}
	return result, nil
}

// Delete issues a signed DELETE for key (a bucket-relative path with no
// leading slash). S3-compatible DELETE is idempotent — deleting an
// already-absent key still returns 204/404 as success, not an error.
func (c *Client) Delete(ctx context.Context, key string) error {
	if strings.TrimSpace(key) == "" || strings.HasPrefix(key, "/") {
		return errors.New("store key must be a non-empty bucket-relative path")
	}
	endpoint, err := url.Parse(c.config.Endpoint)
	if err != nil {
		return fmt.Errorf("store endpoint: %w", err)
	}
	endpoint.Path = "/" + c.config.Bucket + "/" + key
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return err
	}
	c.sign(request, time.Now().UTC(), emptySHA256)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("store DELETE %s: %s: %s", key, response.Status, string(body))
	}
	return nil
}

// Put issues a signed PUT for key (a bucket-relative path with no leading
// slash), uploading body in full under contentType. Q4.1 is Put's only
// caller today (the selection candidates receipt), always a small JSON
// document, so — unlike Get's streamed response — Put takes the whole
// body in memory rather than an io.Reader: SigV4 header-authenticated
// requests must sign the exact payload hash up front, which needs the
// complete body anyway.
func (c *Client) Put(ctx context.Context, key string, body []byte, contentType string) error {
	if strings.TrimSpace(key) == "" || strings.HasPrefix(key, "/") {
		return errors.New("store key must be a non-empty bucket-relative path")
	}
	if strings.TrimSpace(contentType) == "" {
		return errors.New("store put requires a content type")
	}
	endpoint, err := url.Parse(c.config.Endpoint)
	if err != nil {
		return fmt.Errorf("store endpoint: %w", err)
	}
	endpoint.Path = "/" + c.config.Bucket + "/" + key
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.ContentLength = int64(len(body))
	request.Header.Set("Content-Type", contentType)
	c.sign(request, time.Now().UTC(), hashHex(string(body)))
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("store PUT %s: %s: %s", key, response.Status, string(respBody))
	}
	return nil
}

// sign implements AWS Signature Version 4 for a header-authenticated (not
// presigned-URL) request: GET (with or without Range, with or without a
// query string), DELETE, or PUT (payloadHash is the request body's own
// SHA256, or emptySHA256 for GET/DELETE/LIST's bodyless requests).
func (c *Client) sign(request *http.Request, now time.Time, payloadHash string) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)

	headerNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if request.Header.Get("Range") != "" {
		headerNames = append(headerNames, "range")
	}
	if request.Header.Get("Content-Type") != "" {
		headerNames = append(headerNames, "content-type")
	}
	sort.Strings(headerNames)
	signedHeaders := strings.Join(headerNames, ";")
	var canonicalHeaders strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		value := request.Header.Get(name)
		if name == "host" {
			value = request.URL.Host
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteByte('\n')
	}

	// request.URL.RawQuery is only ever set here via url.Values.Encode(),
	// which already sorts by key and percent-encodes each pair — exactly
	// the canonical query string SigV4 requires.
	canonicalRequest := strings.Join([]string{
		request.Method,
		request.URL.EscapedPath(),
		request.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.config.Region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hashHex(canonicalRequest),
	}, "\n")

	key := signingKey(c.config.SecretAccessKey, dateStamp, c.config.Region)
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	request.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.config.AccessKeyID, scope, signedHeaders, signature))
}

func signingKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
