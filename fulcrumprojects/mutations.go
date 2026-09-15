package fulcrumprojects

import (
	"regexp"
	"strconv"
)

// Builders for the GTD mapping (spec golem-native-on-foundry §10.6). Each
// mints a fresh mutation id and, for a create, a client-side target id.

var (
	slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// ProjectTaskCreate builds project-task.create on project slug: a Next
// Action owned by assignee (member id), a Waiting/Blocked item, or a
// Someday/Scheduled one. A status the store does not admit is refused here
// rather than mapped silently.
func ProjectTaskCreate(slug, title, priority, status string, assigneeMemberID *int64, parentTaskID *int64) (Mutation, error) {
	if !slugPattern.MatchString(slug) || title == "" || len(title) > 240 {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "project task needs a slug and a title")
	}
	if priority != PriorityCritical && priority != PriorityHigh && priority != PriorityMedium {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "project task priority must be Critical, High or Medium")
	}
	if !AdmitsStatus(status) {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "project task status %q is not admitted by the store yet", status)
	}
	payload := map[string]any{"title": title, "priority": priority, "status": status}
	if assigneeMemberID != nil {
		payload["assigneeMemberId"] = *assigneeMemberID
	}
	if parentTaskID != nil {
		payload["parentTaskId"] = *parentTaskID
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindProjectTaskCreate, Target: "project:" + slug, BaseVersion: 0, Payload: mustJSON(payload)}, nil
}

// ProjectTaskUpdate builds project-task.update; fields nil are untouched.
func ProjectTaskUpdate(taskID string, version int64, title, priority, status *string, assigneeMemberID *int64) (Mutation, error) {
	if taskID == "" || version < 1 || (title == nil && priority == nil && status == nil && assigneeMemberID == nil) {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "project task update needs a target, a version and one field")
	}
	payload := map[string]any{}
	if title != nil {
		payload["title"] = *title
	}
	if priority != nil {
		payload["priority"] = *priority
	}
	if status != nil {
		if !AdmitsStatus(*status) {
			return Mutation{}, errorf(CodeInvalidRequest, 0, "project task status %q is not admitted by the store yet", *status)
		}
		payload["status"] = *status
	}
	if assigneeMemberID != nil {
		payload["assigneeMemberId"] = *assigneeMemberID
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindProjectTaskUpdate, Target: taskID, BaseVersion: version, Payload: mustJSON(payload)}, nil
}

// TaskComplete builds task.complete on any task kind.
func TaskComplete(taskID string, version int64) (Mutation, error) {
	if taskID == "" || version < 1 {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "task complete needs a target and a version")
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindTaskComplete, Target: taskID, BaseVersion: version, Payload: mustJSON(map[string]any{})}, nil
}

// TodoCreate builds todo.create in the inbox (the GTD capture step) or
// another section; date is required for personal and health.
func TodoCreate(section, title, date string) (Mutation, error) {
	if title == "" || len(title) > 240 {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "todo needs a title")
	}
	dated := section == "personal" || section == "health"
	if section != "inbox" && section != "tasks" && !dated {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "todo section must be inbox, tasks, personal or health")
	}
	if dated && !datePattern.MatchString(date) {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "a %s todo needs a YYYY-MM-DD date", section)
	}
	payload := map[string]any{"title": title, "section": section}
	if dated {
		payload["date"] = date
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindTodoCreate, Target: "todo-item:" + NewMutationID(), BaseVersion: 0, Payload: mustJSON(payload)}, nil
}

// DelegationCreate builds delegation.create: the Delegated state, owned by
// assignee, never by the owner. requiresSummary defaults true on the
// server; the GTD mapping sends it explicitly.
func DelegationCreate(assigneeMemberID int64, title, details, dueDate, priority string, requiresSummary bool) (Mutation, error) {
	if assigneeMemberID < 1 || title == "" || len(title) > 240 || len(details) > 4000 {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "delegation needs an assignee and a bounded title")
	}
	if dueDate != "" && !datePattern.MatchString(dueDate) {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "delegation due date must be YYYY-MM-DD")
	}
	if priority == "" {
		priority = DelegationPriorityNormal
	}
	if priority != DelegationPriorityNormal && priority != DelegationPriorityHigh && priority != DelegationPriorityUrgent {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "delegation priority must be normal, high or urgent")
	}
	payload := map[string]any{"title": title, "assignee": strconv.FormatInt(assigneeMemberID, 10), "priority": priority, "requiresSummary": requiresSummary}
	if details != "" {
		payload["details"] = details
	}
	if dueDate != "" {
		payload["dueDate"] = dueDate
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindDelegationCreate, Target: "assignment:" + NewMutationID(), BaseVersion: 0, Payload: mustJSON(payload)}, nil
}

// DelegationComplete builds delegation.complete with an optional summary.
func DelegationComplete(assignmentID string, version int64, summary string) (Mutation, error) {
	if assignmentID == "" || version < 1 {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "delegation complete needs a target and a version")
	}
	payload := map[string]any{"status": DelegationDone}
	if summary != "" {
		payload["summary"] = summary
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindDelegationComplete, Target: assignmentID, BaseVersion: version, Payload: mustJSON(payload)}, nil
}

// DailyLinkSchedule builds daily-link.schedule: put a project task on a
// day (a due or check date on any task; the Scheduled status is the state).
func DailyLinkSchedule(projectTaskID, date string) (Mutation, error) {
	if projectTaskID == "" || !datePattern.MatchString(date) {
		return Mutation{}, errorf(CodeInvalidRequest, 0, "daily link needs a project task and a YYYY-MM-DD date")
	}
	return Mutation{MutationID: NewMutationID(), Kind: KindDailyLinkSchedule, Target: projectTaskID, BaseVersion: 0, Payload: mustJSON(map[string]any{"date": date})}, nil
}

// Query builds a query kind (my-work.list, on-deck.list): answered, never
// persisted, never receipted.
func Query(kind string, payload any) Mutation {
	if payload == nil {
		payload = map[string]any{}
	}
	return Mutation{MutationID: NewMutationID(), Kind: kind, Target: "query:" + NewMutationID(), BaseVersion: 0, Payload: mustJSON(payload)}
}
