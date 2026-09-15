package fulcrumprojects

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// fixtureServer replays the recorded /api/v2 bodies under testdata (shapes
// per contracts/sync/*.schema.json of fulcrum-labs/fulcrum-projects) and
// enforces the workspace epoch the way the store does: a batch under a
// stale epoch is 409 sync_epoch_mismatch, a batch under the current epoch
// answers the recorded results with the caller's mutation ids echoed back.
type fixtureServer struct {
	t        *testing.T
	mu       sync.Mutex
	epoch    int64
	requests []recordedRequest
}

type recordedRequest struct {
	method, path, auth, agent, contentType string
	body                                   []byte
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) {
		t.Fatalf("fixture %s is not JSON", name)
	}
	return body
}

func (f *fixtureServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := readAll(r)
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{method: r.Method, path: r.URL.Path + "?" + r.URL.RawQuery, auth: r.Header.Get("Authorization"), agent: r.Header.Get("User-Agent"), contentType: r.Header.Get("Content-Type"), body: body})
	epoch := f.epoch
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/snapshot":
		if epoch == 8 {
			_, _ = w.Write(readFixture(f.t, "snapshot-epoch8.json"))
		} else {
			_, _ = w.Write(readFixture(f.t, "snapshot.json"))
		}
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/changes":
		if r.URL.Query().Get("epoch") != "7" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"sync_epoch_mismatch"}` + "\n"))
			return
		}
		_, _ = w.Write(readFixture(f.t, "changes.json"))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/mutations":
		var batch Batch
		if err := json.Unmarshal(body, &batch); err != nil || batch.ClientID == "" || len(batch.Mutations) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}` + "\n"))
			return
		}
		if batch.Epoch != epoch {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"sync_epoch_mismatch"}` + "\n"))
			return
		}
		var recorded Results
		_ = json.Unmarshal(readFixture(f.t, "mutation-results.json"), &recorded)
		for i := range recorded.Results {
			if i < len(batch.Mutations) {
				recorded.Results[i].MutationID = batch.Mutations[i].MutationID
			}
		}
		recorded.Results = recorded.Results[:len(batch.Mutations)]
		_ = json.NewEncoder(w).Encode(recorded)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}` + "\n"))
	}
}

func readAll(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	var buffer strings.Builder
	chunk := make([]byte, 4096)
	for {
		n, err := r.Body.Read(chunk)
		buffer.Write(chunk[:n])
		if err != nil {
			break
		}
	}
	return []byte(buffer.String()), nil
}

const testToken = "device-token-0123456789abcdef0123456789abcdef"

func newFixtureClient(t *testing.T) (*Client, *fixtureServer) {
	t.Helper()
	fixture := &fixtureServer{t: t, epoch: 7}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	client, err := New(Config{BaseURL: server.URL, Token: testToken, ClientID: "golemd@grant", UserAgent: "golemd-test/0"})
	if err != nil {
		t.Fatal(err)
	}
	return client, fixture
}

func TestSnapshotAndChangesRoundTripTheRecordedFixtures(t *testing.T) {
	client, fixture := newFixtureClient(t)
	ctx := context.Background()
	snapshot, err := client.Snapshot(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Epoch != 7 || snapshot.Cursor != 1234 || snapshot.Date != "2026-09-15" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	var tasks []ProjectTask
	if err := json.Unmarshal(snapshot.Data.ProjectTasks, &tasks); err != nil || len(tasks) != 1 || tasks[0].Status != StatusNext || *tasks[0].AssigneeMemberID != 3 || tasks[0].Version != 4 {
		t.Fatalf("project tasks=%+v err=%v", tasks, err)
	}
	var delegations []AssignedTask
	if err := json.Unmarshal(snapshot.Data.AssignedTasks, &delegations); err != nil || len(delegations) != 1 || delegations[0].AssigneeMemberID != 5 || delegations[0].Status != DelegationOpen {
		t.Fatalf("assigned tasks=%+v err=%v", delegations, err)
	}
	changes, err := client.Changes(ctx, snapshot.Cursor, snapshot.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if changes.Cursor != 1236 || len(changes.Changes) != 2 || changes.Changes[0].Op != OpUpsert || changes.Changes[0].Collection != "project_tasks" || changes.Changes[1].Op != OpDelete || changes.Changes[1].Entity != nil && string(changes.Changes[1].Entity) != "null" {
		t.Fatalf("changes=%+v", changes)
	}
	var moved ProjectTask
	if err := json.Unmarshal(changes.Changes[0].Entity, &moved); err != nil || moved.Status != StatusWaiting || moved.Version != 5 {
		t.Fatalf("changed task=%+v err=%v", moved, err)
	}
	if _, err := client.Changes(ctx, snapshot.Cursor, 6); !IsCode(err, CodeEpochMismatch) {
		t.Fatalf("stale changes epoch err=%v", err)
	}
	first := fixture.requests[0]
	if first.auth != "Bearer "+testToken || first.agent != "golemd-test/0" || !strings.HasPrefix(first.path, "/api/v2/snapshot?") {
		t.Fatalf("request=%+v", first)
	}
	if strings.Contains(client.String(), testToken) {
		t.Fatal("client must redact its token")
	}
}

func TestMutationsAreRetriedOnceWithAFreshSnapshotAndFreshIds(t *testing.T) {
	client, fixture := newFixtureClient(t)
	ctx := context.Background()
	snapshot, err := client.Snapshot(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// The workspace epoch moves under us (an admin import) between the
	// snapshot and the write.
	fixture.mu.Lock()
	fixture.epoch = 8
	fixture.mu.Unlock()
	assignee := int64(3)
	stale, err := ProjectTaskCreate("hosting", "Follow up with unpaid Growth Labs hosting customers", PriorityHigh, StatusNext, &assignee, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Mutate(ctx, snapshot.Epoch, []Mutation{stale}); !IsCode(err, CodeEpochMismatch) {
		t.Fatalf("stale epoch must be a typed mismatch: %v", err)
	}
	var ids []string
	fresh, results, err := client.Retry(ctx, func(current Snapshot) ([]Mutation, error) {
		task, err := ProjectTaskCreate("hosting", "Follow up with unpaid Growth Labs hosting customers", PriorityHigh, StatusNext, &assignee, nil)
		if err != nil {
			return nil, err
		}
		link, err := DailyLinkSchedule("project-task:42", "2026-09-19")
		if err != nil {
			return nil, err
		}
		ids = append(ids, task.MutationID)
		return []Mutation{task, link}, nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if fresh.Epoch != 8 || len(results.Results) != 2 {
		t.Fatalf("fresh=%+v results=%+v", fresh, results)
	}
	entity, err := results.Applied(results.Results[0].MutationID)
	if err != nil {
		t.Fatal(err)
	}
	var created ProjectTask
	if err := json.Unmarshal(entity, &created); err != nil || created.ID != "project-task:42" || *created.AssigneeMemberID != 3 || created.Status != StatusNext {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	// Exactly one stale attempt before the refresh, and the ids differ.
	posts := 0
	for _, request := range fixture.requests {
		if request.method == http.MethodPost {
			posts++
			if request.contentType != "application/json" || !strings.Contains(string(request.body), `"clientId":"golemd@grant"`) {
				t.Fatalf("batch request=%+v", request)
			}
		}
	}
	if posts != 2 || len(ids) != 1 || ids[0] == stale.MutationID {
		t.Fatalf("posts=%d ids=%v stale=%s", posts, ids, stale.MutationID)
	}
	for _, status := range []string{StatusSomeday, StatusScheduled} {
		m, err := ProjectTaskCreate("hosting", "later", PriorityMedium, status, nil, nil)
		if err != nil || !strings.Contains(string(m.Payload), `"status":"`+status+`"`) {
			t.Fatalf("%s must be admitted since the G-02 migration: %v", status, err)
		}
	}
	if _, err := ProjectTaskCreate("hosting", "later", PriorityMedium, "Later", nil, nil); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("an unknown status must still be refused: %v", err)
	}
}

func TestBuildersShapeTheGTDMapping(t *testing.T) {
	delegated, err := DelegationCreate(5, "Answer on the Fastmail migration", "", "2026-09-19", "", false)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	_ = json.Unmarshal(delegated.Payload, &payload)
	if delegated.Kind != KindDelegationCreate || !strings.HasPrefix(delegated.Target, "assignment:") || delegated.BaseVersion != 0 || payload["assignee"] != "5" || payload["priority"] != DelegationPriorityNormal || payload["requiresSummary"] != false || payload["dueDate"] != "2026-09-19" {
		t.Fatalf("delegation=%+v payload=%v", delegated, payload)
	}
	inbox, err := TodoCreate("inbox", "Call the accountant", "")
	if err != nil || inbox.Kind != KindTodoCreate || !strings.HasPrefix(inbox.Target, "todo-item:") {
		t.Fatalf("todo=%+v err=%v", inbox, err)
	}
	if _, err := TodoCreate("personal", "Dentist", ""); !IsCode(err, CodeInvalidRequest) {
		t.Fatalf("dated section without a date err=%v", err)
	}
	done, err := DelegationComplete("assignment:12", 1, "answered")
	if err != nil || done.BaseVersion != 1 || !strings.Contains(string(done.Payload), `"status":"done"`) {
		t.Fatalf("complete=%+v err=%v", done, err)
	}
	if _, err := TaskComplete("project-task:41", 0); !IsCode(err, CodeInvalidRequest) {
		t.Fatal("a version of 0 is not an update")
	}
	query := Query(KindQueryMyWorkList, nil)
	if query.BaseVersion != 0 || string(query.Payload) != "{}" {
		t.Fatalf("query=%+v", query)
	}
	if _, err := New(Config{BaseURL: "http://projects.example", Token: testToken, ClientID: "x"}); !IsCode(err, CodeInvalidConfig) {
		t.Fatal("plain http off loopback must be refused")
	}
	if _, err := New(Config{BaseURL: "https://projects.example", Token: "short", ClientID: "x"}); !IsCode(err, CodeInvalidConfig) {
		t.Fatal("a short token must be refused")
	}
}
