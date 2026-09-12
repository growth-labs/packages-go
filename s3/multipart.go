package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MultipartThreshold is the object size above which PutStream uses S3
// multipart upload instead of one PUT. Below it, a single connection drop
// is cheap to retry whole; above it, the point of multipart is that a
// drop only costs the current part, not the whole (potentially very
// large) object.
var MultipartThreshold int64 = 8 << 20 // 8 MiB

// multipartPartSize is deliberately well above S3's 5 MiB minimum part
// size (every part but the last must meet it) while staying small enough
// that a single dropped part is genuinely cheap to retry over a slow link.
var multipartPartSize int64 = 8 << 20 // 8 MiB

const maxMultipartParts = 10000 // S3's own hard limit.

// multipartPartRetries paces retrying ONE part, not the whole object:
// immediate, then two backoff attempts.
var multipartPartRetries = []time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second}

type multipartUploadResult struct {
	InitiateXMLName xml.Name `xml:"InitiateMultipartUploadResult"`
	UploadID        string   `xml:"UploadId"`
}

type completeMultipartUploadRequest struct {
	XMLName xml.Name             `xml:"CompleteMultipartUpload"`
	Parts   []completedMultipart `xml:"Part"`
}

type completedMultipart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// PutStream uploads size bytes read from body to key, using real S3
// multipart upload (CreateMultipartUpload, per-part PUT with a bounded
// retry so a dropped connection only costs the current part,
// CompleteMultipartUpload) whenever size exceeds MultipartThreshold, or a
// single PUT otherwise. Any unrecoverable failure aborts the multipart
// upload server-side before returning, so a failed PutStream never
// leaves an orphaned incomplete upload consuming storage. After a
// successful upload, PutStream reads the object back and verifies its
// hash and size match sha256Hex/size exactly — an upload whose written
// bytes differ from what the caller intended is a failure, not a
// silent partial success.
func (c *Client) PutStream(ctx context.Context, key string, body io.Reader, size int64, sha256Hex string) error {
	if !validKey(key) {
		return errors.New("s3: key must be a non-empty bucket-relative path")
	}
	if size < 1 {
		return errors.New("s3: put stream requires a positive byte count")
	}
	if len(sha256Hex) != sha256.Size*2 {
		return errors.New("s3: put stream requires the exact sha256 of body")
	}
	if size <= MultipartThreshold {
		content, err := io.ReadAll(io.LimitReader(body, size+1))
		if err != nil {
			return fmt.Errorf("s3: read put stream body: %w", err)
		}
		if int64(len(content)) != size {
			return errors.New("s3: put stream body did not match the declared size")
		}
		if err := c.Put(ctx, key, content, "application/octet-stream"); err != nil {
			return err
		}
	} else if err := c.putMultipart(ctx, key, body, size); err != nil {
		return err
	}
	verified, err := c.Inspect(ctx, key)
	if err != nil || verified.SHA256 != sha256Hex || verified.Bytes != size {
		return errors.New("s3: put stream object identity differs after upload")
	}
	return nil
}

func (c *Client) putMultipart(ctx context.Context, key string, body io.Reader, totalBytes int64) error {
	uploadID, err := c.createMultipartUpload(ctx, key)
	if err != nil {
		return fmt.Errorf("s3: create multipart upload: %w", err)
	}
	parts, uploadErr := c.uploadParts(ctx, key, uploadID, body, totalBytes)
	if uploadErr != nil {
		if abortErr := c.abortMultipartUpload(ctx, key, uploadID); abortErr != nil {
			return errors.Join(uploadErr, fmt.Errorf("s3: abort multipart upload after failed part: %w", abortErr))
		}
		return uploadErr
	}
	if err := c.completeMultipartUpload(ctx, key, uploadID, parts); err != nil {
		if abortErr := c.abortMultipartUpload(ctx, key, uploadID); abortErr != nil {
			return errors.Join(err, fmt.Errorf("s3: abort multipart upload after failed complete: %w", abortErr))
		}
		return fmt.Errorf("s3: complete multipart upload: %w", err)
	}
	return nil
}

func (c *Client) createMultipartUpload(ctx context.Context, key string) (string, error) {
	request, err := c.signedRequest(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, emptySHA256, nil, 0)
	if err != nil {
		return "", err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("s3: create multipart upload returned status %d", response.StatusCode)
	}
	var result multipartUploadResult
	if err := xml.Unmarshal(body, &result); err != nil || result.UploadID == "" {
		return "", errors.New("s3: create multipart upload response is invalid")
	}
	return result.UploadID, nil
}

// uploadParts uploads every multipartPartSize chunk read from body,
// retrying only the current part (never the whole object) on a
// transient failure. Reads each part fully into memory before sending so
// a retry resends the identical bytes without needing to re-read body
// from a stale offset.
func (c *Client) uploadParts(ctx context.Context, key, uploadID string, body io.Reader, totalBytes int64) ([]completedMultipart, error) {
	partCount := (totalBytes + multipartPartSize - 1) / multipartPartSize
	if partCount > maxMultipartParts {
		return nil, fmt.Errorf("s3: multipart upload requires %d parts, over the %d limit", partCount, maxMultipartParts)
	}
	parts := make([]completedMultipart, 0, partCount)
	buffer := make([]byte, multipartPartSize)
	for partNumber := 1; ; partNumber++ {
		read, readErr := io.ReadFull(body, buffer)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return nil, fmt.Errorf("s3: read multipart part %d: %w", partNumber, readErr)
		}
		if read == 0 {
			break
		}
		etag, err := c.uploadPartWithRetry(ctx, key, uploadID, partNumber, buffer[:read])
		if err != nil {
			return nil, fmt.Errorf("s3: upload multipart part %d: %w", partNumber, err)
		}
		parts = append(parts, completedMultipart{PartNumber: partNumber, ETag: etag})
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	if len(parts) == 0 {
		return nil, errors.New("s3: multipart upload produced no parts")
	}
	return parts, nil
}

func (c *Client) uploadPartWithRetry(ctx context.Context, key, uploadID string, partNumber int, content []byte) (string, error) {
	payloadSHA := mustHashHex(content)
	var lastErr error
	for attempt, delay := range multipartPartRetries {
		if attempt > 0 {
			jitter := time.Duration(rand.Int63n(int64(time.Second)))
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(delay + jitter):
			}
		}
		etag, err := c.uploadPart(ctx, key, uploadID, partNumber, content, payloadSHA)
		if err == nil {
			return etag, nil
		}
		lastErr = err
		if !isTransientMultipartError(err) {
			return "", err
		}
	}
	return "", lastErr
}

func (c *Client) uploadPart(ctx context.Context, key, uploadID string, partNumber int, content []byte, payloadSHA string) (string, error) {
	query := url.Values{"partNumber": {fmt.Sprint(partNumber)}, "uploadId": {uploadID}}
	request, err := c.signedRequest(ctx, http.MethodPut, key, query, payloadSHA, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return "", err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("s3: put multipart part returned status %d", response.StatusCode)
	}
	etag := response.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("s3: put multipart part response is missing an ETag")
	}
	return etag, nil
}

func (c *Client) completeMultipartUpload(ctx context.Context, key, uploadID string, parts []completedMultipart) error {
	body, err := xml.Marshal(completeMultipartUploadRequest{Parts: parts})
	if err != nil {
		return err
	}
	request, err := c.signedRequest(ctx, http.MethodPost, key, url.Values{"uploadId": {uploadID}}, mustHashHex(body), bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("s3: complete multipart upload returned status %d", response.StatusCode)
	}
	return nil
}

func (c *Client) abortMultipartUpload(ctx context.Context, key, uploadID string) error {
	request, err := c.signedRequest(ctx, http.MethodDelete, key, url.Values{"uploadId": {uploadID}}, emptySHA256, nil, 0)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("s3: abort multipart upload returned status %d", response.StatusCode)
	}
	return nil
}

// isTransientMultipartError mirrors runners that retry a stale/reset
// connection but never a real rejection (bad credentials, a 4xx) — that
// will only fail identically again.
func isTransientMultipartError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "EOF")
}
