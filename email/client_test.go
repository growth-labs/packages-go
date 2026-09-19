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
	return Config{AccountID: "acct1", APIToken: "cf-token", From: "alerts@fulcrum-portal.com"}
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
		_ = json.NewEncoder(w).Encode(map[string]any{"success": fake.success})
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
		[]string{"grant@fulcrum-labs.com", "alias@pushover.example"}, "foundry publish test", "body text")
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
	if fake.gotBody["from"] != "alerts@fulcrum-portal.com" {
		t.Fatalf("from = %v, want the configured sending address, never a caller-supplied one", fake.gotBody["from"])
	}
	recipients, ok := fake.gotBody["recipients"].([]any)
	if !ok || len(recipients) != 2 || recipients[0] != "grant@fulcrum-labs.com" {
		t.Fatalf("recipients = %+v", fake.gotBody["recipients"])
	}
	raw, ok := fake.gotBody["mime_message"].(string)
	if !ok || !strings.Contains(raw, "Subject: foundry publish test") {
		t.Fatalf("mime_message missing subject: %q", raw)
	}
	if !strings.Contains(raw, "From: alerts@fulcrum-portal.com") {
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
	for _, messageID := range []string{"", "id\r\nBcc: someone@example.com", "<id@fulcrum-labs.com>"} {
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

func TestSendSurfacesHTTPErrorWithNoJSONBody(t *testing.T) {
	fake := newFakeCloudflareServer(t)
	fake.status = http.StatusInternalServerError
	fake.responseBody = "upstream failure"
	client := fake.client(t)

	_, err := client.Send(context.Background(), []string{"a@b.com"}, "t", "m")
	if err == nil {
		t.Fatal("Send swallowed a non-2xx response with no JSON body")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want the HTTP status surfaced", err)
	}
	if !IsUnsubmitted(err) {
		t.Fatal("a rejected send must be proven unsubmitted")
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
	id, err := generateMessageID("alerts@fulcrum-portal.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(id, "@fulcrum-portal.com") {
		t.Fatalf("id = %q, want it under the from address's own domain", id)
	}
	if strings.ContainsAny(id, "<>\r\n") {
		t.Fatalf("id = %q, must not itself carry angle brackets or CRLF", id)
	}
}
