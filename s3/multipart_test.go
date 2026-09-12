package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeMultipartServer implements just enough of S3's multipart protocol
// (CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
// AbortMultipartUpload) plus plain GET for PutStream's final Inspect
// verification, with a hook to fail specific part uploads on their first
// N attempts — the exact shape needed to prove per-part retry without
// restarting the whole object.
type fakeMultipartServer struct {
	mu             sync.Mutex
	objects        map[string][]byte
	parts          map[string]map[int][]byte // uploadID -> partNumber -> content
	uploadCounter  int
	aborted        []string
	completed      []string
	failPartsUntil map[int]int // partNumber -> attempt count that must be reached before succeeding
	partAttempts   map[int]int
	failStatus     int // if non-zero, this HTTP status instead of a transient close
}

func newFakeMultipartServer() *fakeMultipartServer {
	return &fakeMultipartServer{
		objects:        map[string][]byte{},
		parts:          map[string]map[int][]byte{},
		failPartsUntil: map[int]int{},
		partAttempts:   map[int]int{},
	}
}

func (f *fakeMultipartServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		query := r.URL.Query()
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && query.Has("uploads"):
			f.uploadCounter++
			uploadID := fmt.Sprintf("upload-%d", f.uploadCounter)
			f.parts[uploadID] = map[int][]byte{}
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, uploadID)
		case r.Method == http.MethodPut && query.Get("uploadId") != "" && query.Get("partNumber") != "":
			var partNumber int
			fmt.Sscanf(query.Get("partNumber"), "%d", &partNumber)
			f.partAttempts[partNumber]++
			if f.partAttempts[partNumber] <= f.failPartsUntil[partNumber] {
				if f.failStatus != 0 {
					http.Error(w, "injected failure", f.failStatus)
					return
				}
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "cannot hijack", http.StatusInternalServerError)
					return
				}
				conn, _, err := hijacker.Hijack()
				if err != nil {
					http.Error(w, "hijack failed", http.StatusInternalServerError)
					return
				}
				_ = conn.Close()
				return
			}
			content, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			uploadID := query.Get("uploadId")
			f.parts[uploadID][partNumber] = content
			w.Header().Set("ETag", fmt.Sprintf("\"etag-%s-%d\"", uploadID, partNumber))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && query.Get("uploadId") != "":
			uploadID := query.Get("uploadId")
			parts, ok := f.parts[uploadID]
			if !ok {
				http.Error(w, "unknown upload", http.StatusNotFound)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			var request completeMultipartUploadRequest
			if err := xml.Unmarshal(body, &request); err != nil {
				http.Error(w, "bad xml", http.StatusBadRequest)
				return
			}
			var assembled []byte
			for _, part := range request.Parts {
				content, ok := parts[part.PartNumber]
				if !ok {
					http.Error(w, "missing part", http.StatusBadRequest)
					return
				}
				assembled = append(assembled, content...)
			}
			f.objects[r.URL.Path] = assembled
			f.completed = append(f.completed, uploadID)
			delete(f.parts, uploadID)
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult></CompleteMultipartUploadResult>`)
		case r.Method == http.MethodDelete && query.Get("uploadId") != "":
			uploadID := query.Get("uploadId")
			f.aborted = append(f.aborted, uploadID)
			delete(f.parts, uploadID)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			content, ok := f.objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(content)
		default:
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
		}
	}
}

func testMultipartClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	config := testConfig()
	config.Endpoint = server.URL
	client, err := NewClient(config, server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func withMultipartTuning(t *testing.T, threshold, partSize int64, retries []time.Duration) {
	t.Helper()
	originalThreshold, originalPartSize, originalRetries := MultipartThreshold, multipartPartSize, multipartPartRetries
	t.Cleanup(func() { MultipartThreshold, multipartPartSize, multipartPartRetries = originalThreshold, originalPartSize, originalRetries })
	MultipartThreshold, multipartPartSize, multipartPartRetries = threshold, partSize, retries
}

// TestPutStreamUsesMultipartAboveThresholdAndRetriesOnlyTheDroppedPart is
// the regression proof for the relay-drop uploads that kept discarding
// whole completed renders on foundry (2026-09-08, ported here since this
// package now owns that signing/multipart engine): an object above
// MultipartThreshold uploads via real CreateMultipartUpload/UploadPart/
// CompleteMultipartUpload, and a part whose connection drops on its
// first attempt is retried in place — other parts are uploaded exactly
// once, not re-sent.
func TestPutStreamUsesMultipartAboveThresholdAndRetriesOnlyTheDroppedPart(t *testing.T) {
	withMultipartTuning(t, 1, 10, []time.Duration{0, time.Millisecond, time.Millisecond})

	fake := newFakeMultipartServer()
	fake.failPartsUntil[2] = 1 // part 2's first attempt drops; the retry must succeed
	server := httptest.NewServer(fake.handler())
	defer server.Close()
	client := testMultipartClient(t, server)

	content := []byte("0123456789ABCDEFGHIJ0123456789ABCDEFGHIJ01234") // 46 bytes -> 5 parts of 10, last of 6
	digest := sha256.Sum256(content)
	sha := hex.EncodeToString(digest[:])

	if err := client.PutStream(context.Background(), "outputs/clip.mp4", bytes.NewReader(content), int64(len(content)), sha); err != nil {
		t.Fatalf("PutStream() error = %v", err)
	}
	if fake.partAttempts[2] != 2 {
		t.Fatalf("part 2 attempts = %d, want exactly 2 (one drop, one success)", fake.partAttempts[2])
	}
	for part, attempts := range fake.partAttempts {
		if part != 2 && attempts != 1 {
			t.Fatalf("part %d attempts = %d, want exactly 1 (no unnecessary re-sends)", part, attempts)
		}
	}
	if len(fake.completed) != 1 || len(fake.aborted) != 0 {
		t.Fatalf("completed = %v, aborted = %v, want exactly one completed multipart upload and no aborts", fake.completed, fake.aborted)
	}
	if string(fake.objects["/examplebucket/outputs/clip.mp4"]) != string(content) {
		t.Fatalf("assembled object = %q, want %q", fake.objects["/examplebucket/outputs/clip.mp4"], content)
	}
}

// TestPutStreamAbortsMultipartUploadOnUnrecoverablePartFailure proves a
// non-transient part failure (a real rejection, not a dropped
// connection) is not retried and cleans up the incomplete upload
// server-side instead of leaking it.
func TestPutStreamAbortsMultipartUploadOnUnrecoverablePartFailure(t *testing.T) {
	withMultipartTuning(t, 1, 10, []time.Duration{0, time.Millisecond, time.Millisecond})

	fake := newFakeMultipartServer()
	fake.failPartsUntil[2] = 99 // never recovers within the retry budget
	fake.failStatus = http.StatusForbidden
	server := httptest.NewServer(fake.handler())
	defer server.Close()
	client := testMultipartClient(t, server)

	content := []byte("0123456789ABCDEFGHIJ01234")
	digest := sha256.Sum256(content)
	sha := hex.EncodeToString(digest[:])

	err := client.PutStream(context.Background(), "outputs/clip.mp4", bytes.NewReader(content), int64(len(content)), sha)
	if err == nil {
		t.Fatal("PutStream() = nil error, want the permanent 403 part failure surfaced")
	}
	if fake.partAttempts[2] != 1 {
		t.Fatalf("part 2 attempts = %d, want exactly 1 (a 403 is not transient, must not retry)", fake.partAttempts[2])
	}
	if len(fake.aborted) != 1 || len(fake.completed) != 0 {
		t.Fatalf("aborted = %v, completed = %v, want exactly one aborted upload and no completions", fake.aborted, fake.completed)
	}
}

// TestPutStreamStaysSinglePUTBelowMultipartThreshold proves the plain
// single-PUT path is used for small objects — multipart's per-part
// overhead (create/complete round trips) is only worth it above the
// threshold.
func TestPutStreamStaysSinglePUTBelowMultipartThreshold(t *testing.T) {
	var sawMultipartQuery bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Has("uploads") || r.URL.Query().Get("uploadId") != "" {
			sawMultipartQuery = true
		}
		switch r.Method {
		case http.MethodPut:
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			fmt.Fprint(w, "tiny content")
		default:
			http.Error(w, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	client := testMultipartClient(t, server)

	content := []byte("tiny content")
	digest := sha256.Sum256(content)
	sha := hex.EncodeToString(digest[:])

	if err := client.PutStream(context.Background(), "outputs/small.json", bytes.NewReader(content), int64(len(content)), sha); err != nil {
		t.Fatalf("PutStream() error = %v", err)
	}
	if sawMultipartQuery {
		t.Fatal("PutStream() used the multipart protocol for an object under MultipartThreshold")
	}
}

func TestPutStreamRejectsMismatchedIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			fmt.Fprint(w, "actually different content")
		}
	}))
	defer server.Close()
	client := testMultipartClient(t, server)

	content := []byte("intended content")
	digest := sha256.Sum256(content)
	sha := hex.EncodeToString(digest[:])
	if err := client.PutStream(context.Background(), "outputs/mismatch.json", bytes.NewReader(content), int64(len(content)), sha); err == nil {
		t.Fatal("PutStream() succeeded despite the read-back not matching the declared identity")
	}
}
