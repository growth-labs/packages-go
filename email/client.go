// Package email sends transactional mail for Go services over Fastmail's
// JMAP API (RFC 8620/8621). One Client sends one plain-text message per
// Send call -- session discovery, then Email/set to compose a draft plus
// EmailSubmission/set to send it -- and can afterwards prove that an exact
// message reached the account's Sent mailbox.
//
// The package holds no durable state: budget accounting, retry policy and
// recipient lists belong to the caller, which has the database connection
// this package deliberately does not. The bearer token is read from a
// mode-0600 file by LoadTokenFile; no value is ever compiled in.
package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// jmapCoreCapability, jmapMailCapability, and jmapSubmissionCapability are the
// three JMAP capability URNs this client declares on every request -- the
// minimum needed to discover a mailbox, compose a message, and submit it.
const (
	jmapCoreCapability       = "urn:ietf:params:jmap:core"
	jmapMailCapability       = "urn:ietf:params:jmap:mail"
	jmapSubmissionCapability = "urn:ietf:params:jmap:submission"
)

// identityDomain is the estate's sending domain. The Fastmail account behind
// the shared token also holds the operator's own personal identity
// (grizzle.work) -- estate mail must go out under the Fulcrum identity,
// never the operator's, so identity selection is a hard requirement, not a
// "pick the first one" default.
const identityDomain = "@fulcrum-labs.com"

// Client sends one plain-text email per Send call via Fastmail's JMAP API:
// session discovery, then Email/set to compose a draft plus
// EmailSubmission/set to send it (with onSuccessUpdateEmail moving it out of
// Drafts into Sent once delivery succeeds), batched into two HTTP requests
// total.
type Client struct {
	token      string
	httpClient *http.Client
	sessionURL string
}

// New validates the token up front, so a misconfiguration is a boot-time
// error rather than a silent no-op on the first real send.
func New(token string, httpClient *http.Client) (*Client, error) {
	if token == "" {
		return nil, errors.New("fastmail token is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{token: token, httpClient: httpClient, sessionURL: "https://api.fastmail.com/jmap/session"}, nil
}

type jmapSession struct {
	APIURL          string            `json:"apiUrl"`
	PrimaryAccounts map[string]string `json:"primaryAccounts"`
}

// jmapRequest and jmapResponse model just enough of the JMAP request/response
// envelope (RFC 8620 section 3.3/3.4) for this client's calls. A method call
// is the 3-element array [name, arguments, id]; represented here as []any so
// arbitrary argument shapes can be sent without a named type per call.
type jmapRequest struct {
	Using       []string `json:"using"`
	MethodCalls [][]any  `json:"methodCalls"`
}

type jmapResponse struct {
	MethodResponses []json.RawMessage `json:"methodResponses"`
}

// Send composes and submits one email, returning the RFC 5322 Message-ID it
// assigned (client-generated, not server-assigned) so a caller can
// independently confirm real delivery afterward via Email/query -- the
// EmailSubmission object itself is dropped by Fastmail once final, so it is
// not a usable delivery signal (see VerifyDelivered).
func (c *Client) Send(ctx context.Context, to []string, subject, body string) (string, error) {
	id, err := generateMessageID()
	if err != nil {
		return "", Unsubmitted(err)
	}
	return c.SendWithMessageID(ctx, to, subject, body, id)
}

// SendWithMessageID preserves caller identity across durable attempts. Message-ID
// is correlation evidence, not a server-supported deduplication key.
func (c *Client) SendWithMessageID(ctx context.Context, to []string, subject, body, messageID string) (_ string, sendErr error) {
	submitted := false
	defer func() {
		if sendErr != nil && !submitted {
			sendErr = Unsubmitted(sendErr)
		}
	}()
	if messageID == "" || strings.ContainsAny(messageID, "\r\n<>") {
		return "", errors.New("fastmail: invalid Message-ID")
	}
	if len(to) == 0 || subject == "" || body == "" {
		return "", errors.New("fastmail: to, subject, and body are all required")
	}

	session, err := c.fetchSession(ctx)
	if err != nil {
		return "", err
	}
	accountID := session.PrimaryAccounts[jmapMailCapability]
	if accountID == "" {
		return "", errors.New("fastmail: session has no primary mail account")
	}

	identityID, fromEmail, draftsMailboxID, sentMailboxID, err := c.fetchIdentityAndMailboxes(ctx, session.APIURL, accountID)
	if err != nil {
		return "", err
	}

	toAddresses := make([]map[string]string, len(to))
	for i, address := range to {
		toAddresses[i] = map[string]string{"email": address}
	}
	emailSet := map[string]any{
		"accountId": accountID,
		"create": map[string]any{
			"outgoingEmail": map[string]any{
				"mailboxIds": map[string]bool{draftsMailboxID: true},
				"keywords":   map[string]bool{"$draft": true},
				"messageId":  []string{messageID},
				"from":       []map[string]string{{"email": fromEmail}},
				"to":         toAddresses,
				"subject":    subject,
				"bodyValues": map[string]any{"body": map[string]string{"value": body, "charset": "utf-8"}},
				"textBody":   []map[string]string{{"partId": "body", "type": "text/plain"}},
			},
		},
	}
	// onSuccessUpdateEmail applies only once the submission it is keyed to
	// (by "#<creationId>") actually succeeds: move the message out of
	// Drafts into Sent and mark it read, so a steady stream of messages does
	// not pile up as unread drafts forever.
	submissionSet := map[string]any{
		"accountId": accountID,
		"create": map[string]any{
			"outgoingSubmission": map[string]string{"identityId": identityID, "emailId": "#outgoingEmail"},
		},
		"onSuccessUpdateEmail": map[string]any{
			"#outgoingSubmission": map[string]any{
				"mailboxIds/" + draftsMailboxID: nil,
				"mailboxIds/" + sentMailboxID:   true,
				"keywords/$draft":               nil,
				"keywords/$seen":                true,
			},
		},
	}
	submitted = true
	responses, err := c.call(ctx, session.APIURL,
		[]any{"Email/set", emailSet, "e1"},
		[]any{"EmailSubmission/set", submissionSet, "s1"},
	)
	if err != nil {
		return "", err
	}
	draftErr := requireCreated(responses, "e1", "Email/set", "outgoingEmail")
	submissionErr := requireCreated(responses, "s1", "EmailSubmission/set", "outgoingSubmission")
	// Each method in a JMAP batch runs independently (RFC 8620 section 3.6).
	// A draft rejection cannot prove what happened to the actual submission.
	if submissionErr != nil {
		if IsUnsubmitted(submissionErr) && IsUnsubmitted(draftErr) && IsRateLimited(draftErr) {
			return "", draftErr
		}
		return "", submissionErr
	}
	if draftErr != nil {
		return "", errors.New("fastmail: draft result conflicts with accepted submission")
	}
	return messageID, nil
}

// VerifyDelivered polls Email/query for a message carrying messageID,
// returning true once it is found -- the check a probe uses instead of
// EmailSubmission/get, which Fastmail drops shortly after a submission
// completes and so cannot serve as a delivery signal. Polls every 5 seconds
// until timeout elapses or ctx is cancelled.
func (c *Client) VerifyDelivered(ctx context.Context, messageID string, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		found, err := c.FindSentByMessageID(ctx, messageID)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// FindSentByMessageID proves an exact message is in Sent and is not a draft.
// This proves sender-side acceptance, not downstream delivery or receipt.
func (c *Client) FindSentByMessageID(ctx context.Context, messageID string) (bool, error) {
	session, err := c.fetchSession(ctx)
	if err != nil {
		return false, err
	}
	accountID := session.PrimaryAccounts[jmapMailCapability]
	if accountID == "" {
		return false, errors.New("fastmail: session has no primary mail account")
	}
	_, _, _, sentID, err := c.fetchIdentityAndMailboxes(ctx, session.APIURL, accountID)
	if err != nil {
		return false, err
	}
	responses, err := c.call(ctx, session.APIURL,
		[]any{"Email/query", map[string]any{
			"accountId": accountID,
			"filter":    map[string]any{"inMailbox": sentID, "header": []string{"Message-ID", messageID}},
			"limit":     20,
		}, "q1"},
		[]any{"Email/get", map[string]any{
			"accountId":  accountID,
			"#ids":       map[string]any{"resultOf": "q1", "name": "Email/query", "path": "/ids"},
			"properties": []string{"messageId", "mailboxIds", "keywords"},
		}, "g1"},
	)
	if err != nil {
		return false, err
	}
	var result struct {
		List []struct {
			MessageID  []string        `json:"messageId"`
			MailboxIDs map[string]bool `json:"mailboxIds"`
			Keywords   map[string]bool `json:"keywords"`
		} `json:"list"`
	}
	if err := unmarshalMethodResult(responses, "g1", "Email/get", &result); err != nil {
		return false, err
	}
	for _, message := range result.List {
		for _, id := range message.MessageID {
			if id == messageID && message.MailboxIDs[sentID] && !message.Keywords["$draft"] {
				return true, nil
			}
		}
	}
	return false, nil
}

// fetchIdentityAndMailboxes resolves the sending identity under the estate's
// own domain (never the operator's personal identity, which shares this
// same Fastmail account) plus the account's Drafts and Sent mailboxes.
func (c *Client) fetchIdentityAndMailboxes(ctx context.Context, apiURL, accountID string) (identityID, fromEmail, draftsMailboxID, sentMailboxID string, err error) {
	responses, err := c.call(ctx, apiURL,
		[]any{"Identity/get", map[string]any{"accountId": accountID}, "identity"},
		[]any{"Mailbox/get", map[string]any{"accountId": accountID}, "mailboxes"},
	)
	if err != nil {
		return "", "", "", "", err
	}

	var identityResult struct {
		List []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"list"`
	}
	if err := unmarshalMethodResult(responses, "identity", "Identity/get", &identityResult); err != nil {
		return "", "", "", "", err
	}
	var identity *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	for i := range identityResult.List {
		if strings.HasSuffix(strings.ToLower(identityResult.List[i].Email), identityDomain) {
			identity = &identityResult.List[i]
			break
		}
	}
	if identity == nil {
		return "", "", "", "", fmt.Errorf("fastmail: account has no identity under %s", identityDomain)
	}

	var mailboxResult struct {
		List []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"list"`
	}
	if err := unmarshalMethodResult(responses, "mailboxes", "Mailbox/get", &mailboxResult); err != nil {
		return "", "", "", "", err
	}
	for _, mailbox := range mailboxResult.List {
		switch mailbox.Role {
		case "drafts":
			draftsMailboxID = mailbox.ID
		case "sent":
			sentMailboxID = mailbox.ID
		}
	}
	if draftsMailboxID == "" {
		return "", "", "", "", errors.New("fastmail: account has no Drafts mailbox")
	}
	if sentMailboxID == "" {
		return "", "", "", "", errors.New("fastmail: account has no Sent mailbox")
	}
	return identity.ID, identity.Email, draftsMailboxID, sentMailboxID, nil
}

// generateMessageID builds an RFC 5322 Message-ID under the estate's own
// domain so VerifyDelivered can look for exactly this value later, rather
// than trusting whatever id the server would otherwise assign.
func generateMessageID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s", hex.EncodeToString(raw), identityDomain), nil
}

func (c *Client) fetchSession(ctx context.Context) (jmapSession, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sessionURL, nil)
	if err != nil {
		return jmapSession{}, fmt.Errorf("fastmail: build session request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return jmapSession{}, fmt.Errorf("fastmail: session request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return jmapSession{}, &RateLimitError{StatusCode: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode != http.StatusOK {
		return jmapSession{}, fmt.Errorf("fastmail: session request returned http %d", resp.StatusCode)
	}
	var session jmapSession
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return jmapSession{}, fmt.Errorf("fastmail: decode session: %w", err)
	}
	if session.APIURL == "" {
		return jmapSession{}, errors.New("fastmail: session has no apiUrl")
	}
	return session, nil
}

// call sends one or more method calls as a single JMAP request and returns
// the raw method responses for the caller to pick apart by call id.
func (c *Client) call(ctx context.Context, apiURL string, methodCalls ...[]any) ([]json.RawMessage, error) {
	payload, err := json.Marshal(jmapRequest{
		Using:       []string{jmapCoreCapability, jmapMailCapability, jmapSubmissionCapability},
		MethodCalls: methodCalls,
	})
	if err != nil {
		return nil, fmt.Errorf("fastmail: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("fastmail: build API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fastmail: API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		// RFC 8620 section 3.6: an HTTP rate-limit error rejects the entire
		// request, unlike a method/record error within an accepted batch.
		return nil, Unsubmitted(&RateLimitError{StatusCode: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))})
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fastmail: API request returned http %d", resp.StatusCode)
	}
	var response jmapResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("fastmail: decode API response: %w", err)
	}
	return response.MethodResponses, nil
}

// unmarshalMethodResult finds the method response with the given call id,
// requires its method name to match (a JMAP error response substitutes
// "error" for the name), and decodes its arguments object into out.
func unmarshalMethodResult(responses []json.RawMessage, callID, wantName string, out any) error {
	var result json.RawMessage
	var resultName string
	for _, raw := range responses {
		var entry []json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			return fmt.Errorf("fastmail: malformed method response for %q", callID)
		}
		if len(entry) != 3 {
			return fmt.Errorf("fastmail: malformed method response for %q", callID)
		}
		var id string
		if err := json.Unmarshal(entry[2], &id); err != nil || id != callID {
			continue
		}
		var name string
		if err := json.Unmarshal(entry[0], &name); err != nil {
			return fmt.Errorf("fastmail: malformed method response for %q", callID)
		}
		// Submission/set can emit an implicit Email/set with the same call
		// id. Only the requested method or its error is its direct result.
		if name != wantName && name != "error" {
			continue
		}
		if result != nil {
			return fmt.Errorf("fastmail: duplicate method response for %q", callID)
		}
		result, resultName = entry[1], name
	}
	if resultName == "error" {
		var failure struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(result, &failure) == nil && failure.Type == "rateLimit" {
			return &RateLimitError{Method: wantName}
		}
		return fmt.Errorf("fastmail: %s call failed", wantName)
	}
	if result != nil {
		return json.Unmarshal(result, out)
	}
	return fmt.Errorf("fastmail: no response for call %q", callID)
}

// requireCreated checks a Foo/set response for the named creation id in its
// "created" map, surfacing "notCreated" (or any other rejection) as an error.
func requireCreated(responses []json.RawMessage, callID, methodName, creationID string) error {
	var result struct {
		Created    map[string]json.RawMessage `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := unmarshalMethodResult(responses, callID, methodName, &result); err != nil {
		if IsRateLimited(err) {
			return Unsubmitted(err)
		}
		return err
	}
	created, didCreate := result.Created[creationID]
	reason, rejected := result.NotCreated[creationID]
	if didCreate && rejected {
		return fmt.Errorf("fastmail: %s returned conflicting creation results", methodName)
	}
	if didCreate {
		var record struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(created, &record) != nil || record.ID == "" {
			return fmt.Errorf("fastmail: %s returned malformed creation result", methodName)
		}
		return nil
	}
	if rejected {
		var failure struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(reason, &failure) != nil || failure.Type == "" || failure.Type == "serverPartialFail" {
			return fmt.Errorf("fastmail: %s returned ambiguous creation failure", methodName)
		}
		if failure.Type == "rateLimit" {
			return Unsubmitted(&RateLimitError{Method: methodName})
		}
		return Unsubmitted(fmt.Errorf("fastmail: %s did not create %q", methodName, creationID))
	}
	return fmt.Errorf("fastmail: %s reported neither created nor notCreated for %q", methodName, creationID)
}
