// Package email sends transactional mail for Go services through
// Cloudflare's Email Sending REST API. One Client sends one plain-text
// message per Send call: it builds a minimal RFC 5322 message and posts it
// to POST /accounts/{account_id}/email/sending/send_raw as raw MIME.
// Cloudflare's response is the only delivery evidence there is -- unlike
// JMAP, there is no mailbox to poll afterward, so a Send call is either
// proven accepted or proven (or ambiguously) not.
//
// The package holds no durable state: budget accounting, retry policy and
// recipient lists belong to the caller, which has the database connection
// this package deliberately does not. The API token is read from a
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
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultAPIBase = "https://api.cloudflare.com/client/v4"

// Client sends one plain-text email per Send call via Cloudflare's Email
// Sending REST API. From must be an address on a domain already onboarded
// to Cloudflare Email Sending for AccountID (see the module README) --
// sending from any other domain fails loudly at request time with a
// sending_disabled provider error, never silently.
type Client struct {
	accountID  string
	apiToken   string
	from       string
	httpClient *http.Client
	apiBase    string
}

// Config is the Cloudflare Email Sending configuration one Client needs.
// AccountID and From are not secret; APIToken is -- load it with
// LoadTokenFile from a mode-0600 file rather than compiling it in.
type Config struct {
	// AccountID is the Cloudflare account id that owns the sending domain.
	AccountID string
	// APIToken is an Email Sending-scoped Cloudflare API token.
	APIToken string
	// From is the envelope and header From address, e.g.
	// "foundry-alerts@fulcrum-portal.com". Its domain must already be
	// onboarded to Cloudflare Email Sending on AccountID's account.
	From string
}

// New validates configuration up front, so a misconfiguration is a
// boot-time error rather than a silent no-op on the first real send.
func New(cfg Config, httpClient *http.Client) (*Client, error) {
	if cfg.AccountID == "" {
		return nil, errors.New("email: Cloudflare account id is required")
	}
	if cfg.APIToken == "" {
		return nil, errors.New("email: Cloudflare API token is required")
	}
	if cfg.From == "" || !strings.Contains(cfg.From, "@") || strings.ContainsAny(cfg.From, "\r\n") {
		return nil, errors.New("email: a valid from address is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		accountID:  cfg.AccountID,
		apiToken:   cfg.APIToken,
		from:       cfg.From,
		httpClient: httpClient,
		apiBase:    defaultAPIBase,
	}, nil
}

// Send composes and submits one email, returning the RFC 5322 Message-ID it
// assigned (client-generated, not server-assigned).
func (c *Client) Send(ctx context.Context, to []string, subject, body string) (string, error) {
	id, err := generateMessageID(c.from)
	if err != nil {
		return "", Unsubmitted(err)
	}
	return c.SendWithMessageID(ctx, to, subject, body, id)
}

// SendWithMessageID preserves caller identity across durable attempts.
// Message-ID is correlation evidence, not a server-supported deduplication
// key -- Cloudflare may rewrite the header it actually delivers, so a
// caller reconciling by Message-ID needs a bounded fallback (subject,
// sender/recipient, and a narrow time window), never an exact-match-only
// wait.
func (c *Client) SendWithMessageID(ctx context.Context, to []string, subject, body, messageID string) (string, error) {
	if messageID == "" || strings.ContainsAny(messageID, "\r\n<>") {
		return "", errors.New("email: invalid Message-ID")
	}
	if len(to) == 0 || subject == "" || body == "" {
		return "", errors.New("email: to, subject, and body are all required")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return "", errors.New("email: subject contains invalid characters")
	}
	for _, addr := range to {
		if addr == "" || strings.ContainsAny(addr, "\r\n") {
			return "", errors.New("email: recipient address is invalid")
		}
	}

	raw := buildRawMessage(c.from, to, subject, body, messageID)
	payload, err := json.Marshal(map[string]any{
		"from":         c.from,
		"recipients":   to,
		"mime_message": raw,
	})
	if err != nil {
		return "", fmt.Errorf("email: encode request: %w", err)
	}

	url := fmt.Sprintf("%s/accounts/%s/email/sending/send_raw", c.apiBase, c.accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("email: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// A dial/DNS failure sent no bytes: proven unsubmitted, safe to
		// retry. Anything after the request went out (including a timeout
		// mid-response) is ambiguous -- Cloudflare may already have
		// accepted it.
		if isUnsubmittedTransportError(err) {
			return "", Unsubmitted(fmt.Errorf("email: request failed: %w", err))
		}
		return "", fmt.Errorf("email: request failed: %w", err)
	}
	defer resp.Body.Close()

	// A real HTTP response -- whatever it says -- is Cloudflare's own
	// verdict on this request, so every path below is proven, not
	// ambiguous.
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", Unsubmitted(&RateLimitError{StatusCode: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))})
	}

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed cloudflareResponse
	_ = json.Unmarshal(rawBody, &parsed)

	if resp.StatusCode != http.StatusOK || !parsed.Success {
		message, code := firstCloudflareMessage(parsed)
		if message == "" {
			message = fmt.Sprintf("http %d", resp.StatusCode)
			if len(rawBody) > 0 {
				message = fmt.Sprintf("%s: %s", message, strings.TrimSpace(string(rawBody)))
			}
		}
		if code != "" {
			return "", Unsubmitted(fmt.Errorf("email: provider rejected send (%s): %s", code, message))
		}
		return "", Unsubmitted(fmt.Errorf("email: provider rejected send: %s", message))
	}

	return messageID, nil
}

// cloudflareResponse models just enough of Cloudflare's REST envelope
// (success/errors/messages) to surface the first provider-reported reason
// for a rejected send.
type cloudflareResponse struct {
	Success  bool                `json:"success"`
	Errors   []cloudflareMessage `json:"errors"`
	Messages []cloudflareMessage `json:"messages"`
}

type cloudflareMessage struct {
	Code    json.Number `json:"code"`
	Message string      `json:"message"`
}

func firstCloudflareMessage(r cloudflareResponse) (message, code string) {
	for _, entry := range r.Errors {
		return entry.Message, entry.Code.String()
	}
	for _, entry := range r.Messages {
		return entry.Message, entry.Code.String()
	}
	return "", ""
}

// isUnsubmittedTransportError reports whether err happened before any byte
// reached the transport: a dial-phase *net.OpError (connection refused,
// unreachable, timeout while connecting) or a DNS failure.
func isUnsubmittedTransportError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return false
}

// buildRawMessage builds a minimal RFC 5322 message for Cloudflare's
// send_raw endpoint: headers plus a plain-text body. Every value has
// already been checked for CR/LF (header injection); messageID is the
// caller's bare id, wrapped here in angle brackets as RFC 5322 requires.
func buildRawMessage(from string, to []string, subject, body, messageID string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Message-ID: <%s>\r\n", messageID)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// generateMessageID mints an RFC 5322 Message-ID under the from address's
// own domain, matching the estate convention of correlation ids that carry
// an owning domain rather than a random one.
func generateMessageID(from string) (string, error) {
	domain := from
	if i := strings.LastIndex(from, "@"); i >= 0 {
		domain = from[i+1:]
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s@%s", hex.EncodeToString(raw), domain), nil
}
