package email

import (
	"context"
	"encoding/json"
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
}

func newFakeJMAPServer(t *testing.T) *fakeJMAPServer {
	t.Helper()
	fake := &fakeJMAPServer{identityEmail: "alerts@fulcrum-labs.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jmap/session", func(w http.ResponseWriter, r *http.Request) {
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
			if fake.failSubmit {
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
