package email

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{AccountID: "acct1", APIToken: "cf-token", From: "alerts@example.org"}
}

func TestNewRejectsMissingConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"empty account id": {APIToken: "t", From: "a@b.com"},
		"empty api token":  {AccountID: "a", From: "a@b.com"},
		"empty from":       {AccountID: "a", APIToken: "t"},
		"from without @":   {AccountID: "a", APIToken: "t", From: "not-an-address"},
		"from with CRLF":   {AccountID: "a", APIToken: "t", From: "a@b.com\r\nBcc: x@y.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg, nil); err == nil {
				t.Fatalf("New accepted invalid config %+v", cfg)
			}
		})
	}
}

// fakeCloudflareServer serves one endpoint, POST
// /accounts/{account}/email/sending/send_raw, and records what it received
// so a test can assert on the exact request shape a real Client sends.
type fakeCloudflareServer struct {
	server       *httptest.Server
	gotAuth      string
	gotPath      string
	gotBody      map[string]any
	status       int
	retryAfter   string
	responseBody string
	success      bool
}

func newFakeCloudflareServer(t *testing.T) *fakeCloudflareServer {
	t.Helper()
	fake := &fakeCloudflareServer{success: true}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.gotAuth = r.Header.Get("Authorization")
		fake.gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&fake.gotBody)

		if fake.status != 0 {
			if fake.retryAfter != "" {
				w.Header().Set("Retry-After", fake.retryAfter)
			}
			w.WriteHeader(fake.status)
			if fake.responseBody != "" {
				_, _ = w.Write([]byte(fake.responseBody))
			}
			return
		}
		if fake.responseBody != "" {
			_, _ = w.Write([]byte(fake.responseBody))
			return
		}
		result := map[string]any{"message_id": "cf-assigned-id"}
		if fake.success {
			// Default happy path: every requested recipient is accepted.
			// Tests that need a bounce or a mixed outcome set responseBody
			// explicitly instead of relying on this default.
			recipients, _ := fake.gotBody["recipients"].([]any)
			result["queued"] = recipients
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": fake.success, "result": result})
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeCloudflareServer) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(validConfig(), f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.apiBase = f.server.URL
	return c
}

func TestSendPostsRawMimeToSendRawEndpoint(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	client := fake.client(t)

	messageID, err := client.Send(context.Background(),
		[]string{"someone@example.net", "alias@pushover.example"}, "example publish test", "body text")
	if err != nil {
		t.Fatal(err)
	}
	if messageID == "" {
		t.Fatal("Send returned an empty Message-ID")
	}
	if fake.gotAuth != "Bearer cf-token" {
		t.Fatalf("Authorization = %q, want Bearer cf-token", fake.gotAuth)
	}
	if fake.gotPath != "/accounts/acct1/email/sending/send_raw" {
		t.Fatalf("path = %q", fake.gotPath)
	}
	if fake.gotBody["from"] != "alerts@example.org" {
		t.Fatalf("from = %v, want the configured sending address, never a caller-supplied one", fake.gotBody["from"])
	}
	recipients, ok := fake.gotBody["recipients"].([]any)
	if !ok || len(recipients) != 2 || recipients[0] != "someone@example.net" {
		t.Fatalf("recipients = %+v", fake.gotBody["recipients"])
	}
	raw, ok := fake.gotBody["mime_message"].(string)
	if !ok || !strings.Contains(raw, "Subject: example publish test") {
		t.Fatalf("mime_message missing subject: %q", raw)
	}
	if !strings.Contains(raw, "From: alerts@example.org") {
		t.Fatalf("mime_message missing From header: %q", raw)
	}
	if !strings.Contains(raw, "Message-ID: <"+messageID+">") {
		t.Fatalf("mime_message Message-ID does not match returned id: %q", raw)
	}
	if !strings.HasSuffix(raw, "body text") {
		t.Fatalf("mime_message missing body: %q", raw)
	}
}

func TestSendRejectsEmptyArguments(t *testing.T) {
	client, err := New(validConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), nil, "s", "b"); err == nil {
		t.Fatal("Send accepted no recipients")
	}
	if _, err := client.Send(context.Background(), []string{"a@b.com"}, "", "b"); err == nil {
		t.Fatal("Send accepted an empty subject")
	}
	if _, err := client.Send(context.Background(), []string{"a@b.com"}, "s", ""); err == nil {
		t.Fatal("Send accepted an empty body")
	}
}

func TestSendWithMessageIDRejectsHeaderInjection(t *testing.T) {
	client, err := New(validConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, messageID := range []string{"", "id\r\nBcc: someone@example.com", "<id@example.net>"} {
		if _, err := client.SendWithMessageID(context.Background(), []string{"a@b.com"}, "s", "b", messageID); err == nil {
			t.Fatalf("SendWithMessageID accepted Message-ID %q", messageID)
		}
	}
}

func TestSendRejectsInjectionInSubjectAndRecipients(t *testing.T) {
	client, err := New(validConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), []string{"a@b.com"}, "s\r\nBcc: x@y.com", "b"); err == nil {
		t.Fatal("Send accepted a subject carrying CRLF")
	}
	if _, err := client.Send(context.Background(), []string{"a@b.com\r\nBcc: x@y.com"}, "s", "b"); err == nil {
		t.Fatal("Send accepted a recipient carrying CRLF")
	}
}

// A provider error must be surfaced loudly -- never swallowed into a bare
// success -- and classified as proven-unsubmitted, since Cloudflare's
// send_raw response is a single synchronous verdict.
func TestSendSurfacesProviderErrorLoudly(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	fake.responseBody = `{"success":false,"errors":[{"code":10203,"message":"sending_disabled: domain not onboarded"}]}`
	client := fake.client(t)

	_, err := client.Send(context.Background(), []string{"a@b.com"}, "t", "m")
	if err == nil {
		t.Fatal("Send swallowed a provider-reported failure")
	}
	if !strings.Contains(err.Error(), "sending_disabled") {
		t.Fatalf("error = %v, want the provider's reason surfaced", err)
	}
	if !strings.Contains(err.Error(), "10203") {
		t.Fatalf("error = %v, want the provider's error code surfaced", err)
	}
	if !IsUnsubmitted(err) {
		t.Fatal("a provider-rejected send must be proven unsubmitted")
	}
}

// A 5xx is Cloudflare's gateway failing, not its application logic
// answering: the request may already have been accepted upstream before
// the gateway lost the response. This must never be classified as proven
// unsubmitted, no matter what the (if any) body says -- reviewer finding
// PG-37-2.
func TestSendSurfacesGatewayErrorAsAmbiguous(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"no body", ""},
		{"non-JSON body", "upstream failure"},
		{"well-formed rejection body", `{"success":false,"errors":[{"code":1000,"message":"internal error"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeCloudflareServer(t)
			fake.status = http.StatusBadGateway
			fake.responseBody = tc.body
			client := fake.client(t)

			_, err := client.Send(context.Background(), []string{"a@b.com"}, "t", "m")
			if err == nil {
				t.Fatal("Send swallowed a 502 gateway response")
			}
			if !strings.Contains(err.Error(), "502") {
				t.Fatalf("error = %v, want the HTTP status surfaced", err)
			}
			if IsUnsubmitted(err) {
				t.Fatal("a gateway failure must stay ambiguous, never proven unsubmitted")
			}
		})
	}
}

// A truncated or malformed body proves nothing either way: it is not
// evidence the transport rejected the send, so it must not be classified
// as proven unsubmitted (reviewer finding PG-37-2). The existing HTTP-500
// test previously pinned the opposite, unsafe classification.
func TestSendSurfacesMalformedBodyAsAmbiguous(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"malformed JSON, HTTP 200", http.StatusOK, `{"success":true, "result": {`},
		{"non-JSON body, HTTP 500", http.StatusInternalServerError, "upstream failure"},
		{"empty body, HTTP 400", http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeCloudflareServer(t)
			fake.status = tc.status
			fake.responseBody = tc.body
			client := fake.client(t)

			_, err := client.Send(context.Background(), []string{"a@b.com"}, "t", "m")
			if err == nil {
				t.Fatal("Send swallowed a malformed/unreadable response")
			}
			if IsUnsubmitted(err) {
				t.Fatal("a malformed or truncated response must stay ambiguous, never proven unsubmitted")
			}
		})
	}
}

// Reviewer finding PG-37-1: Cloudflare can report success:true overall
// while one or more requested recipients bounced or were otherwise never
// accepted. That must never look like a plain success, and a mixed
// outcome must never be classified as safe to blanket-resend (it would
// duplicate mail the accepted recipients already have).
func TestSendReturnsRecipientErrorForABounce(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	fake.responseBody = `{"success":true,"result":{"delivered":[],"queued":[],"permanent_bounces":["page-fixture@example.org"],"message_id":"cf-id"}}`
	client := fake.client(t)

	_, err := client.Send(context.Background(), []string{"page-fixture@example.org"}, "example publish test", "body")
	if err == nil {
		t.Fatal("Send reported success for a permanently bounced recipient")
	}
	var recipientErr *RecipientError
	if !errors.As(err, &recipientErr) {
		t.Fatalf("error = %v, want a *RecipientError", err)
	}
	if len(recipientErr.Bounced) != 1 || recipientErr.Bounced[0] != "page-fixture@example.org" {
		t.Fatalf("Bounced = %v", recipientErr.Bounced)
	}
	if IsUnsubmitted(err) {
		t.Fatal("a bounce must never be classified as safe to blanket-resend")
	}
}

func TestSendReturnsRecipientErrorWhenARecipientIsUnaccountedFor(t *testing.T) {
	// Cloudflare's documented response schema has no separate "suppressed"
	// field -- a suppression-list rejection (or any other outcome the
	// schema does not name) surfaces as a requested recipient absent from
	// every list. Treat that the same as a bounce: never silently fine.
	fake := newFakeCloudflareServer(t)
	fake.responseBody = `{"success":true,"result":{"delivered":[],"queued":[],"permanent_bounces":[],"message_id":"cf-id"}}`
	client := fake.client(t)

	_, err := client.Send(context.Background(), []string{"suppressed@example.org"}, "t", "m")
	if err == nil {
		t.Fatal("Send reported success for a recipient absent from every result list")
	}
	var recipientErr *RecipientError
	if !errors.As(err, &recipientErr) {
		t.Fatalf("error = %v, want a *RecipientError", err)
	}
	if len(recipientErr.Unaccepted) != 1 || recipientErr.Unaccepted[0] != "suppressed@example.org" {
		t.Fatalf("Unaccepted = %v", recipientErr.Unaccepted)
	}
	if IsUnsubmitted(err) {
		t.Fatal("an unaccounted-for recipient must never be classified as safe to blanket-resend")
	}
}

func TestSendReturnsRecipientErrorForAMixedOutcome(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	fake.responseBody = `{"success":true,"result":{"delivered":["ok@example.org"],"queued":[],"permanent_bounces":["bad@example.org"],"message_id":"cf-id"}}`
	client := fake.client(t)

	_, err := client.Send(context.Background(), []string{"ok@example.org", "bad@example.org"}, "t", "m")
	var recipientErr *RecipientError
	if !errors.As(err, &recipientErr) {
		t.Fatalf("error = %v, want a *RecipientError", err)
	}
	if len(recipientErr.Bounced) != 1 || recipientErr.Bounced[0] != "bad@example.org" {
		t.Fatalf("Bounced = %v, want only the bounced address, not the delivered one", recipientErr.Bounced)
	}
	if IsUnsubmitted(err) {
		t.Fatal("a mixed outcome must never look safe to blanket-resend the whole recipient list")
	}
}

func TestSendSucceedsWhenEveryRecipientIsDeliveredOrQueued(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	fake.responseBody = `{"success":true,"result":{"delivered":["a@example.org"],"queued":["b@example.org"],"permanent_bounces":[],"message_id":"cf-id"}}`
	client := fake.client(t)

	if _, err := client.Send(context.Background(), []string{"a@example.org", "b@example.org"}, "t", "m"); err != nil {
		t.Fatalf("Send failed for two fully accepted recipients: %v", err)
	}
}

func TestSendFailsOnDialError(t *testing.T) {
	client, err := New(validConfig(), &http.Client{Timeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	client.apiBase = "http://127.0.0.1:1"

	_, err = client.Send(context.Background(), []string{"a@b.com"}, "t", "m")
	if err == nil {
		t.Fatal("Send succeeded despite an unreachable endpoint")
	}
	if !IsUnsubmitted(err) {
		t.Fatal("a dial-phase failure must be proven unsubmitted, safe to retry")
	}
}

func TestSendRateLimitEvidence(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	fake.status = http.StatusTooManyRequests
	fake.retryAfter = "60"
	client := fake.client(t)

	_, err := client.Send(context.Background(), []string{"a@b.com"}, "t", "m")
	if err == nil {
		t.Fatal("expected failure")
	}
	if !IsRateLimited(err) || !IsUnsubmitted(err) {
		t.Fatalf("limited=%v safe=%v, want both true: %v", IsRateLimited(err), IsUnsubmitted(err), err)
	}
	var evidence *RateLimitError
	if !errors.As(err, &evidence) {
		t.Fatal("typed evidence lost through wrappers")
	}
	if evidence.StatusCode != http.StatusTooManyRequests || evidence.RetryAfter != time.Minute {
		t.Fatalf("unexpected metadata: %+v", evidence)
	}
}

func TestUnsubmittedIsNilSafe(t *testing.T) {
	if Unsubmitted(nil) != nil {
		t.Fatal("Unsubmitted(nil) must stay nil so callers can wrap unconditionally")
	}
	if IsUnsubmitted(nil) {
		t.Fatal("IsUnsubmitted(nil) must be false")
	}
}

func TestRateLimitRequiresTypedEvidence(t *testing.T) {
	if IsRateLimited(nil) || IsRateLimited(Unsubmitted(errors.New("rate limited"))) {
		t.Fatal("human text is not evidence")
	}
	cause := errors.New("cause")
	if !errors.Is(Unsubmitted(cause), cause) {
		t.Fatal("Unsubmitted lost wrapped cause")
	}
}

func TestGenerateMessageIDUsesFromDomain(t *testing.T) {
	id, err := generateMessageID("alerts@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(id, "@example.org") {
		t.Fatalf("id = %q, want it under the from address's own domain", id)
	}
	if strings.ContainsAny(id, "<>\r\n") {
		t.Fatalf("id = %q, must not itself carry angle brackets or CRLF", id)
	}
}
