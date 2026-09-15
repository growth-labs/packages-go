package fulcrumprojects

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// Wire shapes of Fulcrum Projects /api/v2 (contracts/sync/*.schema.json in
// fulcrum-labs/fulcrum-projects). Field names are the server's; collections
// in a snapshot are camelCase, in a change row snake_case (Collection
// normalises the latter).

// Snapshot is GET /api/v2/snapshot.
type Snapshot struct {
	Epoch  int64        `json:"epoch"`
	Date   string       `json:"date"`
	Cursor int64        `json:"cursor"`
	Data   SnapshotData `json:"data"`
}

// SnapshotData carries every collection as raw rows; a consumer decodes the
// collections it reads (Members, Projects, ProjectTasks, ...) with the
// typed entities below.
type SnapshotData struct {
	Members                 json.RawMessage `json:"members"`
	Projects                json.RawMessage `json:"projects"`
	ProjectMembers          json.RawMessage `json:"projectMembers"`
	ProjectTasks            json.RawMessage `json:"projectTasks"`
	ProjectTaskComments     json.RawMessage `json:"projectTaskComments"`
	DailyProjectTaskLinks   json.RawMessage `json:"dailyProjectTaskLinks"`
	DailyTasks              json.RawMessage `json:"dailyTasks"`
	TodoItems               json.RawMessage `json:"todoItems"`
	DailyRoutines           json.RawMessage `json:"dailyRoutines"`
	DailyRoutineOccurrences json.RawMessage `json:"dailyRoutineOccurrences"`
	DailyRoutineWorking     json.RawMessage `json:"dailyRoutineWorking"`
	DailyRecordingPlans     json.RawMessage `json:"dailyRecordingPlans"`
	AssignedTasks           json.RawMessage `json:"assignedTasks"`
	AssignedTaskUpdates     json.RawMessage `json:"assignedTaskUpdates"`
	People                  json.RawMessage `json:"people,omitempty"`
	PersonEvents            json.RawMessage `json:"personEvents,omitempty"`
}

// Changes is GET /api/v2/changes?since=&epoch=.
type Changes struct {
	Epoch   int64    `json:"epoch"`
	Cursor  int64    `json:"cursor"`
	Changes []Change `json:"changes"`
}

// Change is one row of the change feed. Entity is the full public entity on
// an upsert and null on a delete.
type Change struct {
	Seq           int64           `json:"seq"`
	Collection    string          `json:"collection"`
	EntityID      string          `json:"entityId"`
	Op            string          `json:"op"`
	Entity        json.RawMessage `json:"entity"`
	ActorMemberID int64           `json:"actorMemberId"`
	At            string          `json:"at"`
}

// Change ops.
const (
	OpUpsert = "upsert"
	OpDelete = "delete"
)

// Batch is POST /api/v2/mutations. Epoch is the workspace visibility epoch
// the caller last saw; ClientID names the writer (1..240 chars).
type Batch struct {
	Epoch     int64      `json:"epoch"`
	ClientID  string     `json:"clientId"`
	Mutations []Mutation `json:"mutations"`
}

// MaxBatchMutations is the server's batch cap.
const MaxBatchMutations = 32

// Mutation is one intent. BaseVersion is 0 for every *.create kind (the
// client mints the target id) and the entity's current version otherwise.
type Mutation struct {
	MutationID  string          `json:"mutationId"`
	Kind        string          `json:"kind"`
	Target      string          `json:"target"`
	BaseVersion int64           `json:"baseVersion"`
	Payload     json.RawMessage `json:"payload"`
}

// Results is the mutations answer: one Result per Mutation, same order.
type Results struct {
	Results []Result `json:"results"`
}

// Result is the per-mutation outcome, a union on Status.
type Result struct {
	MutationID     string          `json:"mutationId"`
	Status         string          `json:"status"`
	Entity         json.RawMessage `json:"entity,omitempty"`
	Answer         *Answer         `json:"answer,omitempty"`
	ServerState    json.RawMessage `json:"serverState,omitempty"`
	LosingIntent   json.RawMessage `json:"losingIntent,omitempty"`
	Message        string          `json:"message,omitempty"`
	OriginalResult *Result         `json:"originalResult,omitempty"`
}

// Answer is a query kind's reply.
type Answer struct {
	Outcome string          `json:"outcome"`
	Value   json.RawMessage `json:"value"`
}

// Result statuses.
const (
	StatusApplied   = "applied"
	StatusAnswered  = "answered"
	StatusConflict  = "conflict"
	StatusDuplicate = "duplicate"
	StatusRejected  = "rejected"
	StatusRetryable = "retryable"
)

// Mutation kinds the Golem GTD mapping uses (spec §10.6).
const (
	KindTodoCreate             = "todo.create"
	KindDailyCreate            = "daily.create"
	KindTaskComplete           = "task.complete"
	KindTaskReopen             = "task.reopen"
	KindTaskUpdate             = "task.update"
	KindTaskMove               = "task.move"
	KindTaskReparent           = "task.reparent"
	KindTaskNoteCreate         = "task.note.create"
	KindDailyLinkSchedule      = "daily-link.schedule"
	KindDailyLinkUnschedule    = "daily-link.unschedule"
	KindProjectTaskCreate      = "project-task.create"
	KindProjectTaskUpdate      = "project-task.update"
	KindProjectTaskHandoff     = "project-task.handoff"
	KindProjectTaskComment     = "project-task.comment.create"
	KindDelegationCreate       = "delegation.create"
	KindDelegationUpdate       = "delegation.update"
	KindDelegationUpdateStatus = "delegation.update-status"
	KindDelegationComplete     = "delegation.complete"
	KindDelegationComment      = "delegation.comment"
	KindQueryMyWorkList        = "my-work.list"
	KindQueryOnDeckList        = "on-deck.list"
)

// Project-task statuses as the store admits them today. Someday and
// Scheduled are the G-02 additions (Golem ruling 7); they are declared so a
// consumer can name them, and the client refuses them until the store's
// schema carries them (see AdmitsStatus).
const (
	StatusNext      = "Next"
	StatusWaiting   = "Waiting"
	StatusDecision  = "Decision"
	StatusSetup     = "Setup"
	StatusBlocked   = "Blocked"
	StatusSomeday   = "Someday"
	StatusScheduled = "Scheduled"
)

// Project-task priorities and delegation priorities (two vocabularies).
const (
	PriorityCritical = "Critical"
	PriorityHigh     = "High"
	PriorityMedium   = "Medium"

	DelegationPriorityNormal = "normal"
	DelegationPriorityHigh   = "high"
	DelegationPriorityUrgent = "urgent"
)

// Delegation statuses.
const (
	DelegationOpen       = "open"
	DelegationInProgress = "in-progress"
	DelegationWaiting    = "waiting"
	DelegationDone       = "done"
)

// Typed entities for the collections the GTD mapping reads.

// Member is a workspace member; ids are integers on the wire.
type Member struct {
	ID          string `json:"id"` // member:<id>
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Active      bool   `json:"active"`
	Timezone    string `json:"timezone"`
	Version     int64  `json:"version"`
}

// Project is referenced by slug everywhere.
type Project struct {
	ID          string `json:"id"` // project:<slug>
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Summary     string `json:"summary"`
	Version     int64  `json:"version"`
	CompletedAt string `json:"completedAt"`
}

// ProjectTask is a project's next action, waiting item, decision, setup or
// blocked item (and, after the G-02 migration, a someday or scheduled one).
type ProjectTask struct {
	ID               string `json:"id"` // project-task:<id>
	ProjectSlug      string `json:"projectSlug"`
	Title            string `json:"title"`
	Priority         string `json:"priority"`
	Status           string `json:"status"`
	AssigneeMemberID *int64 `json:"assigneeMemberId"`
	ParentTaskID     *int64 `json:"parentTaskId"`
	CompletedAt      string `json:"completedAt"`
	SortOrder        int64  `json:"sortOrder"`
	Version          int64  `json:"version"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
}

// AssignedTask is a delegation (assignment:<id>) as either side sees it.
type AssignedTask struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	Details          string `json:"details"`
	DueDate          string `json:"dueDate"`
	Priority         string `json:"priority"`
	Status           string `json:"status"`
	AssigneeMemberID int64  `json:"assigneeMemberId"`
	AssignerMemberID int64  `json:"assignerMemberId"`
	RequiresSummary  bool   `json:"requiresSummary"`
	OriginKind       string `json:"originKind"`
	Version          int64  `json:"version"`
	CompletedAt      string `json:"completedAt"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
}

// TodoItem is an inbox/tasks/personal/health item (todo-item:<id>).
type TodoItem struct {
	ID          string `json:"id"`
	Section     string `json:"section"`
	TaskDate    string `json:"taskDate"`
	Title       string `json:"title"`
	CompletedAt string `json:"completedAt"`
	WorkStatus  string `json:"workStatus"`
	Version     int64  `json:"version"`
	UpdatedAt   string `json:"updatedAt"`
}

// DailyLink schedules a project task on a member's day
// (daily-link:<memberId>:<projectTaskId>).
type DailyLink struct {
	ID            string `json:"id"`
	ProjectTaskID int64  `json:"projectTaskId"`
	TaskDate      string `json:"taskDate"`
	Version       int64  `json:"version"`
	IsWorking     bool   `json:"isWorking"`
}

// NewMutationID mints a fresh v4 UUID. A retry that changes anything about
// a request, the epoch included, must carry a fresh id: the server folds the
// epoch into the idempotency hash and answers a reused id with
// mutation-id-collision.
func NewMutationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("fulcrumprojects: random source unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// AdmitsStatus reports whether a project-task status is one the store's
// schema carries today. Someday and Scheduled return false until the G-02
// migration lands in fulcrum-projects; a caller that needs them maps to
// Waiting or Blocked with a note, never silently to Next.
func AdmitsStatus(status string) bool {
	switch status {
	case StatusNext, StatusWaiting, StatusDecision, StatusSetup, StatusBlocked:
		return true
	}
	return false
}
