package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsEmptyToken(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Fatal("New accepted an empty token")
	}
}

// fakeJMAPServer serves both the session endpoint and the API endpoint at one
// httptest server, dispatching each API POST by which method name its first
// call carries -- the three batches Client makes, in order:
// (Identity/get, Mailbox/get), then (Email/set, EmailSubmission/set), then
// (Email/query, Email/get) for VerifyDelivered. Its fake account always holds
// the operator's own grizzle.work identity alongside the estate's
// fulcrum-labs.com one, so identity-selection tests can catch a client that
// picks the wrong one.
type fakeJMAPServer struct {
	server              *httptest.Server
	gotAuth             []string
	gotEmailSet         map[string]any
	gotSubmissionSet    map[string]any
	failSubmit          bool
	rejectCreate        bool
	identityEmail       string
	omitFulcrumIdentity bool
	omitSentMailbox     bool
	sentMessageIDs      []string
	draftOnly           bool
	dropSubmitResponse  bool
	gotQuery            map[string]any
	sessionStatus       int
	discoveryStatus     int
	submitStatus        int
	retryAfter          string
	submitResponse      string
}

func newFakeJMAPServer(t *testing.T) *fakeJMAPServer {
	t.Helper()
	fake := &fakeJMAPServer{identityEmail: "alerts@fulcrum-labs.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jmap/session", func(w http.ResponseWriter, r *http.Request) {
		if fake.sessionStatus != 0 {
			w.Header().Set("Retry-After", fake.retryAfter)
			w.WriteHeader(fake.sessionStatus)
			return
		}
		fake.gotAuth = append(fake.gotAuth, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiUrl":          fake.server.URL + "/jmap/api",
			"primaryAccounts": map[string]string{jmapMailCapability: "acct1"},
		})
	})
	mux.HandleFunc("/jmap/api", func(w http.ResponseWriter, r *http.Request) {
		fake.gotAuth = append(fake.gotAuth, r.Header.Get("Authorization"))
		var req jmapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		firstName, _ := req.MethodCalls[0][0].(string)
		switch firstName {
		case "Identity/get":
			if fake.discoveryStatus != 0 {
				w.Header().Set("Retry-After", fake.retryAfter)
				w.WriteHeader(fake.discoveryStatus)
				return
			}
			identities := []any{
				map[string]any{"id": "identity-personal", "email": "grant@grizzle.work"},
			}
			if !fake.omitFulcrumIdentity {
				identities = append(identities, map[string]any{"id": "identity1", "email": fake.identityEmail})
			}
			mailboxes := []any{
				map[string]any{"id": "drafts1", "role": "drafts"},
				map[string]any{"id": "inbox1", "role": "inbox"},
			}
			if !fake.omitSentMailbox {
				mailboxes = append(mailboxes, map[string]any{"id": "sent1", "role": "sent"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"methodResponses": []any{
					[]any{"Identity/get", map[string]any{"list": identities}, "identity"},
					[]any{"Mailbox/get", map[string]any{"list": mailboxes}, "mailboxes"},
				},
			})
		case "Email/set":
			if fake.submitStatus != 0 {
				w.Header().Set("Retry-After", fake.retryAfter)
				w.WriteHeader(fake.submitStatus)
				return
			}
			if fake.submitResponse != "" {
				_, _ = w.Write([]byte(fake.submitResponse))
				return
			}
			if fake.dropSubmitResponse {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
				} else {
					_ = conn.Close()
				}
				return
			}
			var emailSet map[string]any
			raw, _ := json.Marshal(req.MethodCalls[0][1])
			_ = json.Unmarshal(raw, &emailSet)
			fake.gotEmailSet = emailSet
			var submissionSet map[string]any
			raw2, _ := json.Marshal(req.MethodCalls[1][1])
			_ = json.Unmarshal(raw2, &submissionSet)
			fake.gotSubmissionSet = submissionSet

			emailResult := map[string]any{"created": map[string]any{"outgoingEmail": map[string]any{"id": "email1"}}}
			if fake.rejectCreate {
				emailResult = map[string]any{"notCreated": map[string]any{"outgoingEmail": map[string]any{"type": "invalidProperties"}}}
			} else if create, ok := emailSet["create"].(map[string]any); ok {
				if outgoing, ok := create["outgoingEmail"].(map[string]any); ok {
					if ids, ok := outgoing["messageId"].([]any); ok {
						for _, id := range ids {
							if s, ok := id.(string); ok {
								fake.sentMessageIDs = append(fake.sentMessageIDs, s)
							}
						}
					}
				}
			}
			submissionResult := map[string]any{"created": map[string]any{"outgoingSubmission": map[string]any{"id": "sub1"}}}
			if fake.rejectCreate {
				submissionResult = map[string]any{"notCreated": map[string]any{"outgoingSubmission": map[string]any{"type": "invalidProperties"}}}
			} else if fake.failSubmit {
				submissionResult = map[string]any{"notCreated": map[string]any{"outgoingSubmission": map[string]any{"type": "forbidden"}}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"methodResponses": []any{
					[]any{"Email/set", emailResult, "e1"},
					[]any{"EmailSubmission/set", submissionResult, "s1"},
				},
			})
		case "Email/query":
			fake.gotQuery, _ = req.MethodCalls[0][1].(map[string]any)
			list := make([]any, len(fake.sentMessageIDs))
			for i, id := range fake.sentMessageIDs {
				list[i] = map[string]any{"messageId": []string{id}, "mailboxIds": map[string]bool{"sent1": !fake.draftOnly, "drafts1": fake.draftOnly}, "keywords": map[string]bool{"$draft": fake.draftOnly}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"methodResponses": []any{
					[]any{"Email/query", map[string]any{"ids": []string{}}, "q1"},
					[]any{"Email/get", map[string]any{"list": list}, "g1"},
				},
			})
		default:
			t.Errorf("unexpected first JMAP method call: %q", firstName)
		}
	})
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

// client returns a Client wired to this fake's session endpoint.
func (f *fakeJMAPServer) client(t *testing.T) *Client {
	t.Helper()
	c, err := New("fm-token", f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.sessionURL = f.server.URL + "/jmap/session"
	return c
}

func TestSendComposesAndSubmitsToAllRecipients(t *testing.T) {
	fake := newFakeJMAPServer(t)
	client := fake.client(t)

	messageID, err := client.Send(context.Background(),
		[]string{"grant@fulcrum-labs.com", "alias@pushover.example"}, "foundry publish test", "body text")
	if err != nil {
		t.Fatal(err)
	}
	if messageID == "" {
		t.Fatal("Send returned an empty Message-ID")
	}
	for _, auth := range fake.gotAuth {
		if auth != "Bearer fm-token" {
			t.Fatalf("Authorization = %q, want Bearer fm-token on every request", auth)
		}
	}
	create, ok := fake.gotEmailSet["create"].(map[string]any)
	if !ok {
		t.Fatalf("Email/set create = %+v", fake.gotEmailSet)
	}
	outgoing, ok := create["outgoingEmail"].(map[string]any)
	if !ok {
		t.Fatalf("Email/set create.outgoingEmail = %+v", create)
	}
	if outgoing["subject"] != "foundry publish test" {
		t.Fatalf("subject = %v", outgoing["subject"])
	}
	to, ok := outgoing["to"].([]any)
	if !ok || len(to) != 2 {
		t.Fatalf("to = %+v, want 2 recipients", outgoing["to"])
	}
	firstTo, _ := to[0].(map[string]any)
	if firstTo["email"] != "grant@fulcrum-labs.com" {
		t.Fatalf("to[0] = %+v", firstTo)
	}
	mailboxIDs, ok := outgoing["mailboxIds"].(map[string]any)
	if !ok || mailboxIDs["drafts1"] != true {
		t.Fatalf("mailboxIds = %+v, want the drafts mailbox id from Mailbox/get", outgoing["mailboxIds"])
	}
	from, ok := outgoing["from"].([]any)
	if !ok || len(from) != 1 {
		t.Fatalf("from = %+v, want exactly one From address", outgoing["from"])
	}
	fromAddr, _ := from[0].(map[string]any)
	if fromAddr["email"] != "alerts@fulcrum-labs.com" {
		t.Fatalf("from = %+v, want the fulcrum-labs.com identity, never the operator's grizzle.work one", fromAddr)
	}

	update, ok := fake.gotSubmissionSet["onSuccessUpdateEmail"].(map[string]any)
	if !ok {
		t.Fatalf("EmailSubmission/set missing onSuccessUpdateEmail: %+v", fake.gotSubmissionSet)
	}
	patch, ok := update["#outgoingSubmission"].(map[string]any)
	if !ok {
		t.Fatalf("onSuccessUpdateEmail missing the #outgoingSubmission patch: %+v", update)
	}
	if patch["mailboxIds/sent1"] != true {
		t.Fatalf("onSuccessUpdateEmail = %+v, want it to move the message into Sent", patch)
	}
	if val, exists := patch["mailboxIds/drafts1"]; !exists || val != nil {
		t.Fatalf("onSuccessUpdateEmail = %+v, want it to clear the Drafts mailbox", patch)
	}
	if patch["keywords/$seen"] != true {
		t.Fatalf("onSuccessUpdateEmail = %+v, want it to mark the message read", patch)
	}
	if val, exists := patch["keywords/$draft"]; !exists || val != nil {
		t.Fatalf("onSuccessUpdateEmail = %+v, want it to clear the $draft keyword", patch)
	}
}

func TestSendRejectsEmptyArguments(t *testing.T) {
	client, err := New("fm-token", nil)
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
	client, err := New("fm-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, messageID := range []string{"", "id\r\nBcc: someone@example.com", "<id@fulcrum-labs.com>"} {
		if _, err := client.SendWithMessageID(context.Background(), []string{"a@b.com"}, "s", "b", messageID); err == nil {
			t.Fatalf("SendWithMessageID accepted Message-ID %q", messageID)
		}
	}
}

func TestSendFailsWhenEmailSetRejectsTheDraft(t *testing.T) {
	fake := newFakeJMAPServer(t)
	fake.rejectCreate = true

	_, err := fake.client(t).Send(context.Background(), []string{"grant@fulcrum-labs.com"}, "t", "m")
	if err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("Send error = %v, want it to surface the Email/set rejection", err)
	}
}

func TestSendFailsWhenSubmissionIsRejected(t *testing.T) {
	fake := newFakeJMAPServer(t)
	fake.failSubmit = true

	_, err := fake.client(t).Send(context.Background(), []string{"grant@fulcrum-labs.com"}, "t", "m")
	if err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("Send error = %v, want it to surface the EmailSubmission/set rejection", err)
	}
}

func TestSendFailsWhenNoEstateIdentityExists(t *testing.T) {
	fake := newFakeJMAPServer(t)
	fake.omitFulcrumIdentity = true

	_, err := fake.client(t).Send(context.Background(), []string{"grant@fulcrum-labs.com"}, "t", "m")
	if err == nil || !strings.Contains(err.Error(), "fulcrum-labs.com") {
		t.Fatalf("Send error = %v, want it to refuse sending without a fulcrum-labs.com identity (never grizzle.work)", err)
	}
}

func TestSendFailsWhenNoSentMailboxExists(t *testing.T) {
	fake := newFakeJMAPServer(t)
	fake.omitSentMailbox = true

	_, err := fake.client(t).Send(context.Background(), []string{"grant@fulcrum-labs.com"}, "t", "m")
	if err == nil || !strings.Contains(err.Error(), "Sent mailbox") {
		t.Fatalf("Send error = %v, want it to refuse sending without a Sent mailbox", err)
	}
}

func TestSendFailsOnSessionHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := New("bad-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.sessionURL = server.URL

	if _, err := client.Send(context.Background(), []string{"a@b.com"}, "t", "m"); err == nil {
		t.Fatal("Send succeeded despite an unauthorized session response")
	}
}

func TestVerifyDeliveredFindsSentMessage(t *testing.T) {
	fake := newFakeJMAPServer(t)
	client := fake.client(t)

	messageID, err := client.Send(context.Background(), []string{"grant@fulcrum-labs.com"}, "t", "m")
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := client.VerifyDelivered(context.Background(), messageID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !delivered {
		t.Fatal("VerifyDelivered = false, want true for a Message-ID the fake mailbox actually holds")
	}
}

func TestVerifyDeliveredTimesOutWhenNotFound(t *testing.T) {
	fake := newFakeJMAPServer(t)

	delivered, err := fake.client(t).VerifyDelivered(context.Background(), "never-sent@fulcrum-labs.com", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if delivered {
		t.Fatal("VerifyDelivered = true for a Message-ID that was never sent")
	}
}

func TestSentProofRejectsDraftAndUsesExactFilter(t *testing.T) {
	fake := newFakeJMAPServer(t)
	fake.sentMessageIDs = []string{"stable@fulcrum-labs.com"}
	fake.draftOnly = true
	c := fake.client(t)

	found, err := c.FindSentByMessageID(context.Background(), "stable@fulcrum-labs.com")
	if err != nil || found {
		t.Fatalf("draft passed Sent proof: %v %v", found, err)
	}
	filter, ok := fake.gotQuery["filter"].(map[string]any)
	if !ok {
		t.Fatalf("Email/query carried no filter: %+v", fake.gotQuery)
	}
	header, ok := filter["header"].([]any)
	if !ok || filter["inMailbox"] != "sent1" || len(header) != 2 || header[0] != "Message-ID" || header[1] != "stable@fulcrum-labs.com" {
		t.Fatalf("unbounded query filter: %v", filter)
	}
	fake.draftOnly = false
	found, err = c.FindSentByMessageID(context.Background(), "stable@fulcrum-labs.com")
	if err != nil || !found {
		t.Fatalf("Sent message not found: %v %v", found, err)
	}
}

func TestSubmissionEvidenceDistinguishesRejectionFromLostResponse(t *testing.T) {
	for _, tc := range []struct {
		name               string
		reject, drop, safe bool
	}{{"rejected", true, false, true}, {"response lost", false, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeJMAPServer(t)
			fake.failSubmit = tc.reject
			fake.dropSubmitResponse = tc.drop
			_, err := fake.client(t).SendWithMessageID(context.Background(), []string{"test@example.com"}, "test", "test", "stable@fulcrum-labs.com")
			if err == nil || IsUnsubmitted(err) != tc.safe {
				t.Fatalf("submission certainty error=%v safe=%v", err, IsUnsubmitted(err))
			}
		})
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

// These fixtures exercise Send's real HTTP/JMAP boundary. Removing typed
// evidence or treating any draft rejection as safe must fail this test.
func TestSendRateLimitEvidence(t *testing.T) {
	const draftOK = `["Email/set",{"created":{"outgoingEmail":{"id":"e"}}},"e1"]`
	const draftLimited = `["Email/set",{"notCreated":{"outgoingEmail":{"type":"rateLimit"}}},"e1"]`
	const submitLimited = `["EmailSubmission/set",{"notCreated":{"outgoingSubmission":{"type":"rateLimit","description":"private provider text"}}},"s1"]`
	const submitInvalid = `["EmailSubmission/set",{"notCreated":{"outgoingSubmission":{"type":"invalidProperties"}}},"s1"]`
	const submitPartial = `["error",{"type":"serverPartialFail","description":"rateLimit 429"},"s1"]`
	const submitOK = `["EmailSubmission/set",{"created":{"outgoingSubmission":{"id":"s"}}},"s1"]`
	for _, tc := range []struct {
		name          string
		responses     string
		status        int
		phase         string
		limited, safe bool
		method        string
	}{
		{name: "session 429", status: 429, phase: "session", limited: true, safe: true},
		{name: "discovery 429", status: 429, phase: "discovery", limited: true, safe: true},
		{name: "submit 429", status: 429, limited: true, safe: true},
		{name: "submit 503", status: 503},
		{name: "submission creation limited", responses: draftOK + "," + submitLimited, limited: true, safe: true, method: "EmailSubmission/set"},
		{name: "submission method limited", responses: draftOK + `,["error",{"type":"rateLimit"},"s1"]`, limited: true, safe: true, method: "EmailSubmission/set"},
		{name: "draft limited submission rejected", responses: draftLimited + "," + submitInvalid, limited: true, safe: true, method: "Email/set"},
		{name: "draft limited missing submission", responses: draftLimited},
		{name: "draft limited partial submission", responses: draftLimited + "," + submitPartial},
		{name: "draft limited successful submission", responses: draftLimited + "," + submitOK},
		{name: "permanent validation", responses: draftOK + "," + submitInvalid, safe: true},
		{name: "partial submission", responses: draftOK + "," + submitPartial},
		{name: "malformed rate limit", responses: draftOK + `,["error",{"type":429},"s1"]`},
		{name: "contradictory submission", responses: draftOK + `,["EmailSubmission/set",{"created":{"outgoingSubmission":{"id":"s"}},"notCreated":{"outgoingSubmission":{"type":"rateLimit"}}},"s1"]`},
		{name: "duplicate submission", responses: draftOK + "," + submitLimited + "," + submitOK},
		{name: "extra tuple element", responses: draftOK + `,["error",{"type":"rateLimit"},"s1","extra"]`},
		{name: "malformed submission rejection", responses: draftOK + `,["EmailSubmission/set",{"notCreated":{"outgoingSubmission":null}},"s1"]`},
		{name: "partial record failure", responses: draftOK + `,["EmailSubmission/set",{"notCreated":{"outgoingSubmission":{"type":"serverPartialFail"}}},"s1"]`},
		{name: "lost response", phase: "lost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeJMAPServer(t)
			fake.retryAfter = "120"
			switch tc.phase {
			case "session":
				fake.sessionStatus = tc.status
			case "discovery":
				fake.discoveryStatus = tc.status
			case "lost":
				fake.dropSubmitResponse = true
			default:
				fake.submitStatus = tc.status
			}
			if tc.responses != "" {
				fake.submitResponse = `{"methodResponses":[` + tc.responses + `]}`
			}
			_, err := fake.client(t).SendWithMessageID(context.Background(), []string{"recipient@example.test"}, "subject", "body", "stable@example.test")
			if err == nil {
				t.Fatal("expected failure")
			}
			err = fmt.Errorf("caller context: %w", err)
			if IsRateLimited(err) != tc.limited || IsUnsubmitted(err) != tc.safe {
				t.Fatalf("limited=%v safe=%v, want %v %v: %v", IsRateLimited(err), IsUnsubmitted(err), tc.limited, tc.safe, err)
			}
			if strings.Contains(err.Error(), "private provider text") {
				t.Fatal("provider description leaked")
			}
			if tc.limited {
				var evidence *RateLimitError
				if !errors.As(err, &evidence) {
					t.Fatal("typed evidence lost through wrappers")
				}
				if evidence.StatusCode != tc.status || evidence.Method != tc.method {
					t.Fatalf("unexpected metadata: %+v", evidence)
				}
				if tc.status == 429 && evidence.RetryAfter != 120*time.Second {
					t.Fatalf("RetryAfter=%v", evidence.RetryAfter)
				}
			}
		})
	}
}

func TestRateLimitRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"", 0}, {"bogus", 0}, {"-1", 0}, {"1.5", 0}, {"0", 0}, {"60", time.Minute},
		{"999999999999999999999999999", 0}, {"86401", 24 * time.Hour},
		{"Sun, 06 Nov 1994 08:49:37 GMT", 0},
	} {
		t.Run(tc.header, func(t *testing.T) {
			fake := newFakeJMAPServer(t)
			fake.submitStatus, fake.retryAfter = 429, tc.header
			_, err := fake.client(t).Send(context.Background(), []string{"recipient@example.test"}, "subject", "body")
			var evidence *RateLimitError
			if !errors.As(err, &evidence) || evidence.RetryAfter != tc.want {
				t.Fatalf("error=%v evidence=%+v want=%v", err, evidence, tc.want)
			}
		})
	}
	t.Run("HTTP date", func(t *testing.T) {
		fake := newFakeJMAPServer(t)
		fake.submitStatus, fake.retryAfter = 429, time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
		_, err := fake.client(t).Send(context.Background(), []string{"recipient@example.test"}, "subject", "body")
		var evidence *RateLimitError
		if !errors.As(err, &evidence) || evidence.RetryAfter < 59*time.Minute || evidence.RetryAfter > time.Hour {
			t.Fatalf("unexpected date evidence: %v", err)
		}
	})
}

func TestRateLimitRequiresTypedEvidence(t *testing.T) {
	if IsRateLimited(nil) || IsRateLimited(Unsubmitted(errors.New("rateLimit http 429"))) {
		t.Fatal("human text is not evidence")
	}
	cause := errors.New("cause")
	if !errors.Is(Unsubmitted(cause), cause) {
		t.Fatal("Unsubmitted lost wrapped cause")
	}
}
