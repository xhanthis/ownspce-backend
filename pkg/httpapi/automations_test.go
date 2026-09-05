package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// daemonActor is a paired daemon: the plaintext token plus the id the mint
// returned. Daemon-plane requests carry a raw bearer rather than a user JWT, so
// they cannot go through harness.do.
type daemonActor struct {
	ID    string
	Token string
}

// pairDaemon mints a daemon token and reports the repos it can build, which is
// what makes its runs claimable.
func pairDaemon(t *testing.T, h *harness, a *actor, name string, repos ...string) *daemonActor {
	t.Helper()

	rec := h.do(http.MethodPost, "/v1/automations/daemons", a, map[string]any{"name": name})
	requireStatus(t, rec, http.StatusCreated)
	body := decodeBody(t, rec)

	token, _ := body["token"].(string)
	if token == "" {
		t.Fatalf("mint returned no token: %s", rec.Body.String())
	}
	daemon, _ := body["daemon"].(map[string]any)
	id, _ := daemon["id"].(string)

	d := &daemonActor{ID: id, Token: token}

	reported := make([]map[string]any, 0, len(repos))
	for _, repo := range repos {
		reported = append(reported, map[string]any{"fullName": repo, "defaultBranch": "main"})
	}
	requireStatus(t, daemonDo(t, h, d, http.MethodPost, "/v1/daemon/register", map[string]any{
		"name": name, "version": "1.0.0", "repos": reported,
	}), http.StatusOK)

	return d
}

// daemonDo issues a request on the daemon plane.
func daemonDo(t *testing.T, h *harness, d *daemonActor, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

// queueRun asks for a run on a task and returns the created run's id.
func queueRun(t *testing.T, h *harness, a *actor, pageID, taskID, repo string) string {
	t.Helper()
	rec := h.do(http.MethodPost, "/v1/automations/runs", a, map[string]any{
		"pageId": pageID, "taskId": taskID, "taskTitle": "Add a /hello endpoint",
		"instructions": "Return {\"ok\":true}.", "repo": repo, "baseBranch": "",
	})
	requireStatus(t, rec, http.StatusCreated)
	run, _ := decodeBody(t, rec)["run"].(map[string]any)
	id, _ := run["id"].(string)
	return id
}

// claimRun takes the next run for a daemon, failing when the queue is empty.
func claimRun(t *testing.T, h *harness, d *daemonActor) map[string]any {
	t.Helper()
	rec := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/claim", nil)
	requireStatus(t, rec, http.StatusOK)
	run, _ := decodeBody(t, rec)["run"].(map[string]any)
	return run
}

func TestAutomationHappyPathReachesPrReady(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")

	// Act
	claimed := claimRun(t, h, d)
	progress := daemonDo(t, h, d, http.MethodPatch, "/v1/daemon/runs/"+runID+"/progress", map[string]any{
		"phase": "coding", "progressLog": "→ Bash go test ./...", "tokensUsed": 100,
	})
	complete := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/"+runID+"/complete", map[string]any{
		"prUrl": "https://github.com/ownspce/backend/pull/1", "tokensUsed": 200,
	})

	// Assert
	if claimed["id"] != runID {
		t.Fatalf("claimed %v, want %s", claimed["id"], runID)
	}
	if claimed["branch"] == "" {
		t.Fatal("claim returned no branch")
	}
	requireStatus(t, progress, http.StatusOK)
	if accepted, _ := decodeBody(t, progress)["accepted"].(bool); !accepted {
		t.Fatal("progress was not accepted for the owning daemon")
	}
	requireStatus(t, complete, http.StatusOK)
	if status, _ := decodeBody(t, complete)["status"].(string); status != "pr_ready" {
		t.Fatalf("status = %s, want pr_ready", status)
	}
}

func TestAutomationDuplicateQueueConflicts(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")

	// Act
	rec := h.do(http.MethodPost, "/v1/automations/runs", a, map[string]any{
		"pageId": "pg_1", "taskId": "tsk_1", "taskTitle": "again",
		"instructions": "", "repo": "ownspce/backend", "baseBranch": "",
	})

	// Assert
	requireStatus(t, rec, http.StatusConflict)
	if code := errorCode(t, rec); code != "run_active" {
		t.Fatalf("code = %s, want run_active", code)
	}
}

func TestAutomationCancelMidRunRejectsComplete(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")
	claimRun(t, h, d)

	// Act
	requireStatus(t, h.do(http.MethodPost, "/v1/automations/runs/"+runID+"/cancel", a, nil), http.StatusOK)
	progress := daemonDo(t, h, d, http.MethodPatch, "/v1/daemon/runs/"+runID+"/progress", map[string]any{
		"phase": "coding", "progressLog": "still going", "tokensUsed": 0,
	})
	complete := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/"+runID+"/complete", map[string]any{
		"prUrl": "https://github.com/ownspce/backend/pull/2", "tokensUsed": 0,
	})

	// Assert
	requireStatus(t, progress, http.StatusOK)
	body := decodeBody(t, progress)
	if accepted, _ := body["accepted"].(bool); accepted {
		t.Fatal("progress was accepted after the run was canceled")
	}
	if status, _ := body["status"].(string); status != "canceled" {
		t.Fatalf("status = %s, want canceled", status)
	}
	requireStatus(t, complete, http.StatusConflict)
	if code := errorCode(t, complete); code != "run_conflict" {
		t.Fatalf("code = %s, want run_conflict", code)
	}
}

func TestAutomationFailRequeuesUntilParked(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")

	// Act & Assert
	for attempt := 1; attempt <= 3; attempt++ {
		claimRun(t, h, d)
		rec := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/"+runID+"/fail", map[string]any{
			"outcome": "error", "errorLog": "boom", "tokensUsed": 0,
		})
		requireStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)

		gotAttempts := int(body["attempts"].(float64))
		if gotAttempts != attempt {
			t.Fatalf("attempts = %d, want %d", gotAttempts, attempt)
		}
		want := "queued"
		if attempt == 3 {
			want = "failed"
		}
		if status, _ := body["status"].(string); status != want {
			t.Fatalf("attempt %d: status = %s, want %s", attempt, status, want)
		}
	}
}

func TestAutomationAuthFailureParksWithoutAttempt(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")
	claimRun(t, h, d)

	// Act
	rec := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/"+runID+"/fail", map[string]any{
		"outcome": "auth", "errorLog": "not logged in", "tokensUsed": 0,
	})

	// Assert
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if status, _ := body["status"].(string); status != "failed" {
		t.Fatalf("status = %s, want failed", status)
	}
	if attempts := int(body["attempts"].(float64)); attempts != 0 {
		t.Fatalf("attempts = %d, want 0 — an auth failure is not the code's fault", attempts)
	}
}

func TestAutomationReleaseRequeuesWithoutAttempt(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")
	claimRun(t, h, d)

	// Act
	rec := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/"+runID+"/release", map[string]any{
		"outcome": "quota", "errorLog": "usage limit", "tokensUsed": 0,
	})

	// Assert
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if status, _ := body["status"].(string); status != "queued" {
		t.Fatalf("status = %s, want queued", status)
	}
	if attempts := int(body["attempts"].(float64)); attempts != 0 {
		t.Fatalf("attempts = %d, want 0 — waiting out a quota is not a failure", attempts)
	}
}

func TestAutomationZombieRunIsReclaimed(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	dead := pairDaemon(t, h, a, "Dead Mac", "ownspce/backend")
	alive := pairDaemon(t, h, a, "Live Mac", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")
	claimRun(t, h, dead)

	if _, err := h.store.Pool().Exec(context.Background(),
		"UPDATE automation_runs SET heartbeat_at = now() - interval '20 minutes' WHERE id = $1", runID); err != nil {
		t.Fatalf("age heartbeat: %v", err)
	}

	// Act
	reclaimed := claimRun(t, h, alive)

	// Assert
	if reclaimed["id"] != runID {
		t.Fatalf("reclaimed %v, want %s", reclaimed["id"], runID)
	}
	if attempts := int(reclaimed["attempts"].(float64)); attempts != 1 {
		t.Fatalf("attempts = %d, want 1 — a silent daemon costs an attempt", attempts)
	}
}

func TestRevokedDaemonTokenLosesAccessImmediately(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")

	// Act
	requireStatus(t, h.do(http.MethodDelete, "/v1/automations/daemons/"+d.ID, a, nil), http.StatusNoContent)
	rec := daemonDo(t, h, d, http.MethodPost, "/v1/daemon/runs/claim", nil)

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestDaemonCannotClaimAnotherUsersRun(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	pairDaemon(t, h, owner, "Owner Mac", "ownspce/backend")
	intruder := pairDaemon(t, h, stranger, "Stranger Mac", "ownspce/backend")
	queueRun(t, h, owner, "pg_1", "tsk_1", "ownspce/backend")

	// Act
	rec := daemonDo(t, h, intruder, http.MethodPost, "/v1/daemon/runs/claim", nil)

	// Assert
	requireStatus(t, rec, http.StatusNoContent)
}

func TestDaemonOnlyClaimsRunsForReportedRepos(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	pairDaemon(t, h, a, "Builds backend", "ownspce/backend")
	other := pairDaemon(t, h, a, "Builds web", "ownspce/web")
	queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")

	// Act
	rec := daemonDo(t, h, other, http.MethodPost, "/v1/daemon/runs/claim", nil)

	// Assert
	requireStatus(t, rec, http.StatusNoContent)
}

func TestQueueRunRejectsUnconnectedRepo(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	pairDaemon(t, h, a, "MacBook", "ownspce/backend")

	// Act
	rec := h.do(http.MethodPost, "/v1/automations/runs", a, map[string]any{
		"pageId": "pg_1", "taskId": "tsk_1", "taskTitle": "t",
		"instructions": "", "repo": "someone/else", "baseBranch": "",
	})

	// Assert
	requireStatus(t, rec, http.StatusForbidden)
	if code := errorCode(t, rec); code != "repo_not_connected" {
		t.Fatalf("code = %s, want repo_not_connected", code)
	}
}

func TestGlobalRunListPaginatesNewestFirst(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	for i := 0; i < 3; i++ {
		queueRun(t, h, a, fmt.Sprintf("pg_%d", i%2), fmt.Sprintf("tsk_%d", i), "ownspce/backend")
	}

	// Act
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		path := "/v1/automations/runs?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		rec := h.do(http.MethodGet, path, a, nil)
		requireStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)

		runs, _ := body["runs"].([]any)
		for _, entry := range runs {
			run, _ := entry.(map[string]any)
			id, _ := run["id"].(string)
			if seen[id] {
				t.Fatalf("run %s appeared on two pages", id)
			}
			seen[id] = true
		}

		pages++
		next, ok := body["nextCursor"].(string)
		if !ok || next == "" {
			break
		}
		cursor = next
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}

	// Assert
	if len(seen) != 3 {
		t.Fatalf("saw %d runs across %d pages, want 3", len(seen), pages)
	}
}

func TestRunListOmitsHeavyColumns(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	pairDaemon(t, h, a, "MacBook", "ownspce/backend")
	runID := queueRun(t, h, a, "pg_1", "tsk_1", "ownspce/backend")

	// Act
	list := h.do(http.MethodGet, "/v1/automations/runs?pageId=pg_1", a, nil)
	single := h.do(http.MethodGet, "/v1/automations/runs/"+runID, a, nil)

	// Assert
	requireStatus(t, list, http.StatusOK)
	runs, _ := decodeBody(t, list)["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("listed %d runs, want 1", len(runs))
	}
	row, _ := runs[0].(map[string]any)
	if _, present := row["progressLog"]; present {
		t.Fatal("list rows must omit progressLog")
	}
	if _, present := row["instructions"]; present {
		t.Fatal("list rows must omit instructions")
	}

	requireStatus(t, single, http.StatusOK)
	run, _ := decodeBody(t, single)["run"].(map[string]any)
	if _, present := run["progressLog"]; !present {
		t.Fatal("the single-run read must include progressLog")
	}
}

func TestUserTokenIsRejectedOnDaemonPlane(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")

	// Act
	req := httptest.NewRequest(http.MethodPost, "/v1/daemon/runs/claim", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+a.Token)
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestDaemonTokenIsRejectedOnUserPlane(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("owner")
	d := pairDaemon(t, h, a, "MacBook", "ownspce/backend")

	// Act
	req := httptest.NewRequest(http.MethodGet, "/v1/automations/runs", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+d.Token)
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}
