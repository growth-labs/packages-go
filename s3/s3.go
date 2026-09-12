// Package s3 is a dependency-free AWS SigV4 client for one S3-compatible
// bucket (path-style or virtual-hosted addressing, AWS S3 and Cloudflare
// R2 alike): no SDK, no vendor lock-in beyond the standard library.
//
//   - Get streams a response body directly (e.g. serving a <video> tag's
//     Range requests through an app server without ever holding the whole
//     file in memory or handing the browser a credential of its own).
//   - List and Delete are prefix/key-scoped, for operator-driven cleanup.
//   - Put uploads a small, fully-buffered payload in one request (SigV4
//     header auth signs the exact payload hash up front, so a small
//     payload needs the complete body in memory anyway).
//   - PutStream uploads a larger, streamed payload, automatically using
//     real S3 multipart upload above Config.MultipartThreshold so a single
//     dropped connection only costs the current part, not the whole
//     object; Inspect reads an object back and reports its identity
//     (SHA-256, byte count) so a caller can verify a publish landed
//     byte-for-byte.
//
// Extracted from fulcrum-labs/foundry's capabilityplane/object.go and
// multipart.go — its ObjectStore, the fuller of this signing engine's two
// prior implementations (session-token support, virtual-hosted addressing,
// multipart upload, and the RFC 3986 sub-delimiter escaping fix S3/MinIO
// canonical URIs require) — generalized to a plain bucket-relative key API
// so a second consumer never needs foundry's own opaque object:// reference
// resolution or its wider ArtifactStore/capability-dispatch domain model.
// fulcrum-labs/quarry's simpler, first-extracted store package (path-style
// only, no multipart, no session token) is the second real consumer,
// replacing its own local implementation with this one. foundry's own
// adoption — replacing capabilityplane/object.go's copy with this package —
// is tracked as its own follow-up in that repo.
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
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

var emptySHA256 = mustHashHex(nil)

func mustHashHex(b []byte) string {
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

// Config names the bucket this client signs requests against and the
// credentials it signs with. PathStyle selects addressing
// (https://endpoint/bucket/key) over virtual-hosted
// (https://bucket.endpoint/key); AccessKeyID/SecretAccessKey are always
// required, SessionToken only for temporary credentials.
type Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	PathStyle       bool
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func (c Config) validate() error {
	endpoint, err := url.Parse(c.Endpoint)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && loopbackHost(endpoint.Hostname()))) ||
		endpoint.Host == "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("s3: endpoint must be an https (or loopback http) URL with no credentials, query, fragment, or path")
	}
	if c.Region == "" || !validBucket(c.Bucket) {
		return errors.New("s3: region and a valid bucket name are required")
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("s3: access key ID and secret access key are required")
	}
	return nil
}

func loopbackHost(host string) bool {
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func validBucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 || strings.HasPrefix(bucket, "-") || strings.HasSuffix(bucket, "-") {
		return false
	}
	for _, char := range bucket {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

// Client issues SigV4-signed requests against one configured bucket.
type Client struct {
	config Config
	http   *http.Client
}

// NewClient validates config and captures the HTTP client requests are
// issued through; a nil httpClient defaults to http.DefaultClient.
func NewClient(config Config, httpClient *http.Client) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
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

func validKey(key string) bool {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return false
	}
	for _, part := range strings.Split(key, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Get issues a signed GET for key (a bucket-relative path with no leading
// slash), forwarding rangeHeader — the caller's own incoming Range header
// value, or "" for none — upstream unmodified so Range requests (video
// seeking) pass through untouched. The caller must close the returned
// response's body; on a non-2xx response Get itself closes the body and
// returns an error instead.
func (c *Client) Get(ctx context.Context, key, rangeHeader string) (*http.Response, error) {
	if !validKey(key) {
		return nil, errors.New("s3: key must be a non-empty bucket-relative path")
	}
	request, err := c.signedRequest(ctx, http.MethodGet, key, nil, emptySHA256, nil, 0)
	if err != nil {
		return nil, err
	}
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		return nil, fmt.Errorf("s3: GET %s: %s: %s", key, response.Status, string(body))
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
// sorts after startAfter ("" for the first page). prefix is required —
// this never lists the whole bucket root.
func (c *Client) List(ctx context.Context, prefix, startAfter string, maxKeys int) (ListResult, error) {
	if strings.TrimSpace(prefix) == "" || strings.HasPrefix(prefix, "/") {
		return ListResult{}, errors.New("s3: list prefix must be a non-empty bucket-relative path")
	}
	if maxKeys < 1 || maxKeys > 1000 {
		return ListResult{}, errors.New("s3: list max keys must be between 1 and 1000")
	}
	query := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {strconv.Itoa(maxKeys)}}
	if startAfter != "" {
		query.Set("start-after", startAfter)
	}
	request, err := c.signedRequest(ctx, http.MethodGet, "", query, emptySHA256, nil, 0)
	if err != nil {
		return ListResult{}, err
	}
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
		return ListResult{}, fmt.Errorf("s3: LIST %s: %s: %s", prefix, response.Status, string(body))
	}
	var parsed listBucketResultXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return ListResult{}, fmt.Errorf("s3: LIST %s: malformed response: %w", prefix, err)
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
	if !validKey(key) {
		return errors.New("s3: key must be a non-empty bucket-relative path")
	}
	request, err := c.signedRequest(ctx, http.MethodDelete, key, nil, emptySHA256, nil, 0)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("s3: DELETE %s: %s: %s", key, response.Status, string(body))
	}
	return nil
}

// Put issues a signed PUT for key (a bucket-relative path with no leading
// slash), uploading body in full under contentType. Put takes the whole
// body in memory rather than an io.Reader — the intended use is a small,
// already-in-memory document (a JSON receipt, a manifest); PutStream is
// for large streamed payloads.
func (c *Client) Put(ctx context.Context, key string, body []byte, contentType string) error {
	if !validKey(key) {
		return errors.New("s3: key must be a non-empty bucket-relative path")
	}
	if strings.TrimSpace(contentType) == "" {
		return errors.New("s3: put requires a content type")
	}
	request, err := c.signedRequestWithContentType(ctx, http.MethodPut, key, nil, mustHashHex(body), bytes.NewReader(body), int64(len(body)), contentType)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("s3: PUT %s: %s: %s", key, response.Status, string(respBody))
	}
	return nil
}

// Identity is one object's read-back identity: its content hash and byte
// count, as actually stored — never assumed from what a caller intended
// to upload.
type Identity struct {
	SHA256 string
	Bytes  int64
}

// Inspect fetches key back and hashes it, so a caller can verify a prior
// Put/PutStream landed byte-for-byte rather than trusting the upload
// response alone.
func (c *Client) Inspect(ctx context.Context, key string) (Identity, error) {
	response, err := c.Get(ctx, key, "")
	if err != nil {
		return Identity{}, err
	}
	defer response.Body.Close()
	digest := sha256.New()
	bytesRead, err := io.Copy(digest, response.Body)
	if err != nil {
		return Identity{}, fmt.Errorf("s3: inspect %s: %w", key, err)
	}
	if bytesRead < 1 {
		return Identity{}, fmt.Errorf("s3: inspect %s: object is empty", key)
	}
	return Identity{SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: bytesRead}, nil
}

func (c *Client) signedRequest(ctx context.Context, method, key string, query url.Values, payloadSHA string, body io.Reader, bytes int64) (*http.Request, error) {
	return c.signedRequestWithContentType(ctx, method, key, query, payloadSHA, body, bytes, "")
}

// signedRequestWithContentType is signedRequest's counterpart for Put:
// Content-Type must be set on the request BEFORE signing, since sign
// includes it among the signed headers whenever it is present.
func (c *Client) signedRequestWithContentType(ctx context.Context, method, key string, query url.Values, payloadSHA string, body io.Reader, bytes int64, contentType string) (*http.Request, error) {
	location := c.objectURL(key)
	location.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, location.String(), body)
	if err != nil {
		return nil, err
	}
	request.ContentLength = bytes
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	c.sign(request, time.Now().UTC(), payloadSHA)
	return request, nil
}

// objectURL resolves a bucket-relative key (or "" for a bucket-root
// request such as List) against Config, honoring PathStyle vs.
// virtual-hosted addressing.
func (c *Client) objectURL(key string) *url.URL {
	endpoint, _ := url.Parse(c.config.Endpoint)
	if c.config.PathStyle {
		endpoint.Path = path.Join("/", endpoint.Path, c.config.Bucket, key)
	} else {
		endpoint.Host = c.config.Bucket + "." + endpoint.Host
		endpoint.Path = "/" + key
	}
	// SigV4's canonical URI is the RFC 3986 escaping of every path
	// segment, where ':' and the other sub-delims are NOT safe. Go's
	// EscapedPath leaves ':' raw, so a key such as
	// "podcast/ingest/podcast-source:<sha>" was signed with a raw ':'
	// while S3/MinIO canonicalise it as "%3A" — every request for such a
	// key failed with SignatureDoesNotMatch (403). Pin the escaped form
	// on the wire and in the signature by setting RawPath.
	endpoint.RawPath = escapePathSegments(endpoint.Path)
	return endpoint
}

func escapePathSegments(p string) string {
	segments := strings.Split(p, "/")
	for i, segment := range segments {
		segments[i] = rfc3986Escape(segment)
	}
	return strings.Join(segments, "/")
}

func rfc3986Escape(value string) string {
	escaped := url.QueryEscape(value)
	return strings.ReplaceAll(escaped, "+", "%20")
}

// sign signs request in place with AWS SigV4 (the scheme both AWS S3 and
// Cloudflare R2's S3-compatible API accept).
func (c *Client) sign(request *http.Request, now time.Time, payloadSHA string) {
	amzDate, date := now.Format("20060102T150405Z"), now.Format("20060102")
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadSHA)
	if c.config.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", c.config.SessionToken)
	}

	headerNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if c.config.SessionToken != "" {
		headerNames = append(headerNames, "x-amz-security-token")
	}
	if request.Header.Get("Range") != "" {
		headerNames = append(headerNames, "range")
	}
	if request.Header.Get("Content-Type") != "" {
		headerNames = append(headerNames, "content-type")
	}
	sort.Strings(headerNames)
	signedHeaders := strings.Join(headerNames, ";")
	var canonicalHeaders strings.Builder
	for _, name := range headerNames {
		value := request.Header.Get(name)
		if name == "host" {
			value = request.URL.Host
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteByte('\n')
	}

	canonicalRequest := strings.Join([]string{
		request.Method,
		request.URL.EscapedPath(),
		canonicalQueryString(request.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payloadSHA,
	}, "\n")

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", date, c.config.Region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		mustHashHex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA(hmacSHA(hmacSHA(hmacSHA([]byte("AWS4"+c.config.SecretAccessKey), date), c.config.Region), "s3"), "aws4_request")
	signature := hex.EncodeToString(hmacSHA(signingKey, stringToSign))

	request.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.config.AccessKeyID, scope, signedHeaders, signature))
}

// canonicalQueryString builds AWS SigV4's canonical query string: every
// parameter's key and value percent-encoded per RFC 3986 (space as %20,
// never Go url.Values.Encode's +), sorted by key, joined "key=value&...".
func canonicalQueryString(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(values))
	for _, key := range keys {
		for _, value := range values[key] {
			parts = append(parts, rfc3986Escape(key)+"="+rfc3986Escape(value))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA(key []byte, values ...string) []byte {
	mac := hmac.New(sha256.New, key)
	for _, value := range values {
		_, _ = mac.Write([]byte(value))
	}
	return mac.Sum(nil)
}
