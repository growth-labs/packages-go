package fulcrumprojects

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config configures a Client. Token is a pre-provisioned device credential
// (an opaque bearer, at least 32 bytes) paired to the member the client
// writes as; the client never mints one.
type Config struct {
	BaseURL    string
	Token      string
	ClientID   string
	UserAgent  string
	HTTPClient *http.Client
}

// Client speaks /api/v2.
type Client struct {
	baseURL   string
	token     string
	clientID  string
	userAgent string
	http      *http.Client
}

const (
	maxResponseBytes = 64 << 20
	defaultTimeout   = 60 * time.Second
)

// New validates the config. The token is kept in the client and never
// appears in an error, a log or fmt output.
func New(config Config) (*Client, error) {
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname()))) || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errorf(CodeInvalidConfig, 0, "base URL must be an https URL (http only on loopback)")
	}
	if len(config.Token) < 32 || strings.TrimSpace(config.Token) != config.Token {
		return nil, errorf(CodeInvalidConfig, 0, "device token must be at least 32 bytes with no surrounding whitespace")
	}
	if config.ClientID == "" || len(config.ClientID) > 240 {
		return nil, errorf(CodeInvalidConfig, 0, "client id must be 1..240 bytes")
	}
	if config.UserAgent == "" {
		config.UserAgent = "fulcrumprojects-go/0"
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{baseURL: strings.TrimRight(parsed.String(), "/"), token: config.Token, clientID: config.ClientID, userAgent: config.UserAgent, http: client}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1"
}

// ClientID is the writer name every batch carries.
func (c *Client) ClientID() string { return c.clientID }

// String redacts the credential.
func (c *Client) String() string { return "fulcrumprojects.Client{" + c.baseURL + "}" }

// GoString redacts the credential.
func (c *Client) GoString() string { return c.String() }

// Snapshot reads the full state. date is optional (YYYY-MM-DD, default
// today UTC on the server).
func (c *Client) Snapshot(ctx context.Context, date string) (Snapshot, error) {
	query := url.Values{}
	if date != "" {
		query.Set("date", date)
	}
	var snapshot Snapshot
	if err := c.do(ctx, http.MethodGet, "/api/v2/snapshot", query, nil, &snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// Changes reads the change feed after cursor since under epoch. Pages are
// capped at 500 rows; call again with the returned Cursor until it stops
// advancing.
func (c *Client) Changes(ctx context.Context, since, epoch int64) (Changes, error) {
	if since < 0 || epoch < 0 {
		return Changes{}, errorf(CodeInvalidRequest, 0, "since and epoch must be non-negative")
	}
	query := url.Values{"since": {strconv.FormatInt(since, 10)}, "epoch": {strconv.FormatInt(epoch, 10)}}
	var changes Changes
	if err := c.do(ctx, http.MethodGet, "/api/v2/changes", query, nil, &changes); err != nil {
		return Changes{}, err
	}
	return changes, nil
}

// Mutate posts one batch under epoch. A stale epoch is CodeEpochMismatch
// (409 sync_epoch_mismatch); the caller refreshes and retries with fresh
// mutation ids (see Retry).
func (c *Client) Mutate(ctx context.Context, epoch int64, mutations []Mutation) (Results, error) {
	if len(mutations) == 0 || len(mutations) > MaxBatchMutations {
		return Results{}, errorf(CodeInvalidRequest, 0, "a batch carries 1..%d mutations", MaxBatchMutations)
	}
	for i, mutation := range mutations {
		if mutation.MutationID == "" || len(mutation.MutationID) > 240 || mutation.Kind == "" || len(mutation.Kind) > 240 || mutation.Target == "" || len(mutation.Target) > 240 || mutation.BaseVersion < 0 || len(mutation.Payload) == 0 || !json.Valid(mutation.Payload) {
			return Results{}, errorf(CodeInvalidRequest, 0, "mutation %d is incomplete", i)
		}
	}
	batch := Batch{Epoch: epoch, ClientID: c.clientID, Mutations: mutations}
	body, err := json.Marshal(batch)
	if err != nil {
		return Results{}, errorf(CodeInvalidRequest, 0, "encode batch: %v", err)
	}
	var results Results
	if err := c.do(ctx, http.MethodPost, "/api/v2/mutations", nil, body, &results); err != nil {
		return Results{}, err
	}
	if len(results.Results) != len(mutations) {
		return Results{}, errorf(CodeUnexpectedResponse, http.StatusOK, "results count %d differs from mutations %d", len(results.Results), len(mutations))
	}
	for i, result := range results.Results {
		if result.MutationID != mutations[i].MutationID {
			return Results{}, errorf(CodeUnexpectedResponse, http.StatusOK, "result %d answers %q, not %q", i, result.MutationID, mutations[i].MutationID)
		}
	}
	return results, nil
}

// Me echoes the authenticated member id (member:<id>).
func (c *Client) Me(ctx context.Context) (string, error) {
	var me struct {
		MemberID string `json:"memberId"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v2/me", nil, nil, &me); err != nil {
		return "", err
	}
	return me.MemberID, nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte, target any) error {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return errorf(CodeInvalidRequest, 0, "build request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return errorf(CodeTransportUnavailable, 0, "%s %s: transport failed", method, path)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes {
		return errorf(CodeTransportUnavailable, response.StatusCode, "%s %s: answer unreadable or oversized", method, path)
	}
	if response.StatusCode != http.StatusOK {
		return apiError(response.StatusCode, payload)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return errorf(CodeUnexpectedResponse, response.StatusCode, "%s %s: answer is not the expected JSON", method, path)
	}
	return nil
}

// apiError maps the server's {"error": "<token>"} body to a Code.
func apiError(status int, payload []byte) error {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(payload, &body)
	token := body.Error
	if token == "" {
		token = "status_" + strconv.Itoa(status)
	}
	var code Code
	switch {
	case token == "sync_epoch_mismatch" || token == "resnapshot_required":
		code = CodeEpochMismatch
	case status == http.StatusConflict:
		code = CodeConflict
	case status == http.StatusBadRequest:
		code = CodeInvalidRequest
	case status == http.StatusUnauthorized || (status == http.StatusNotFound && token == "not_found"):
		// A device token that expired answers 404 not_found on this API.
		code = CodeUnauthorized
	case status == http.StatusForbidden:
		code = CodeForbidden
	case status == http.StatusTooManyRequests:
		code = CodeRateLimited
	case status >= 500:
		code = CodeTransportUnavailable
	default:
		code = CodeUnexpectedResponse
	}
	return &Error{Code: code, Status: status, Err: errors.New(token)}
}

// Retry runs build under the epoch from a fresh snapshot, and on
// CodeEpochMismatch re-snapshots and runs it exactly once more. build must
// mint fresh mutation ids on every call.
func (c *Client) Retry(ctx context.Context, build func(snapshot Snapshot) ([]Mutation, error)) (Snapshot, Results, error) {
	snapshot, err := c.Snapshot(ctx, "")
	if err != nil {
		return Snapshot{}, Results{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		mutations, err := build(snapshot)
		if err != nil {
			return snapshot, Results{}, err
		}
		results, err := c.Mutate(ctx, snapshot.Epoch, mutations)
		if err == nil {
			return snapshot, results, nil
		}
		if !IsCode(err, CodeEpochMismatch) || attempt == 1 {
			return snapshot, Results{}, err
		}
		if snapshot, err = c.Snapshot(ctx, ""); err != nil {
			return Snapshot{}, Results{}, err
		}
	}
	return snapshot, Results{}, errorf(CodeEpochMismatch, http.StatusConflict, "epoch moved twice")
}

// Applied returns the applied result's entity for one mutation id, or a
// typed error naming the outcome.
func (r Results) Applied(mutationID string) (json.RawMessage, error) {
	for _, result := range r.Results {
		if result.MutationID != mutationID {
			continue
		}
		switch result.Status {
		case StatusApplied, StatusAnswered:
			return result.Entity, nil
		case StatusDuplicate:
			if result.OriginalResult != nil && result.OriginalResult.Status == StatusApplied {
				return result.OriginalResult.Entity, nil
			}
			return nil, errorf(CodeConflict, http.StatusOK, "mutation %s: duplicate of a non-applied result", mutationID)
		case StatusConflict:
			return nil, errorf(CodeConflict, http.StatusOK, "mutation %s: conflict: %s", mutationID, result.Message)
		case StatusRetryable:
			return nil, errorf(CodeTransportUnavailable, http.StatusOK, "mutation %s: retryable: %s", mutationID, result.Message)
		default:
			return nil, errorf(CodeInvalidRequest, http.StatusOK, "mutation %s: %s: %s", mutationID, result.Status, result.Message)
		}
	}
	return nil, errorf(CodeUnexpectedResponse, http.StatusOK, "mutation %s has no result", mutationID)
}

// mustJSON encodes a payload the builders control.
func mustJSON(value any) json.RawMessage {
	body, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("fulcrumprojects: encode payload: %v", err))
	}
	return body
}
