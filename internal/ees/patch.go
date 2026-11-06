// Package ees - UPF Event Exposure Service (EES)
// patch.go: PATCH /nupf-ee/v1/ee-subscriptions/{id} (TS 29.564 5.2.2.2.3).
//
// Scope & constraints:
// - The body is a JSON Patch (application/json-patch+json, array(PatchItem)).
// - Only the fields 5.2.2.2.3 names can change: the events (eventList), the
//   event report options (eventReportingMode) and nfId. Other fields, which
//   select the target and the consumer, return 403 MODIFICATION_NOT_ALLOWED.
// - All items are applied or none is. Success is always 204; there is no 200
//   with a PatchResult of discarded items.

package ees

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
)

// patchablePaths are the subscription fields a PATCH may change.
var patchablePaths = []string{"/eventList", "/eventReportingMode", "/nfId"}

// handlePatchSubscription handles PATCH /nupf-ee/v1/ee-subscriptions/{id}
func (server *Server) handlePatchSubscription(w http.ResponseWriter, r *http.Request, id string) {
	server.patchMu.Lock()
	defer server.patchMu.Unlock()

	current, ok := server.subscriptionStore.GetSubscription(id)
	if !ok {
		server.writeProblem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND", "subscription not found")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json-patch+json" {
		server.writeProblem(w, http.StatusUnsupportedMediaType, "",
			"Content-Type must be application/json-patch+json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		server.writeProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "unreadable request body")
		return
	}
	patch, err := jsonpatch.DecodePatch(body)
	if err != nil || len(patch) == 0 {
		server.writeProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "body must be a non-empty JSON Patch array")
		return
	}
	for _, op := range patch {
		allowed, opErr := patchOperationAllowed(op)
		if opErr != nil {
			server.writeProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", opErr.Error())
			return
		}
		if !allowed {
			server.writeProblem(w, http.StatusForbidden, "MODIFICATION_NOT_ALLOWED",
				"only eventList, eventReportingMode and nfId can be modified")
			return
		}
	}

	document, err := json.Marshal(current.Resource)
	if err != nil {
		server.writeProblem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "cannot encode subscription")
		return
	}
	options := jsonpatch.NewApplyOptions()
	options.AccumulatedCopySizeLimit = 1 << 20
	patched, err := patch.ApplyWithOptions(document, options)
	if err != nil {
		server.writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST", "patch cannot be applied: "+err.Error())
		return
	}
	// The stored resource has only known fields, so an unknown field here came
	// from the patch. Reject it rather than accept a change that has no effect.
	var updated UpfEventSubscription
	decoder := json.NewDecoder(bytes.NewReader(patched))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&updated); err != nil {
		server.writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid subscription after patch: "+err.Error())
		return
	}

	candidate, err := server.validateAndMapRequest(createSubscriptionRequest{Subscription: updated})
	if err != nil {
		server.logger.Warnf("ees subscription patch rejected: id=%s: %v", id, err)
		server.writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	candidate.Source = current.Source // fixed when the subscription was created
	candidate.Resource = updated
	if err = server.subscriptionStore.ReplaceSubscription(current, candidate); err != nil {
		switch {
		case errors.Is(err, ErrSubscriptionNotFound):
			server.writeProblem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND", "subscription not found")
		case errors.Is(err, ErrInvalidSubscription):
			server.writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		default:
			server.writeProblem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		}
		return
	}
	server.logger.Infof("ees subscription modified: id=%s nfId=%s trigger=%s",
		id, updated.NfID, updated.EventReportingMode.Trigger)
	w.WriteHeader(http.StatusNoContent)
}

// patchOperationAllowed reports whether op changes only patchable fields.
// "test" and the source of "copy" only read, so they may refer to any field.
func patchOperationAllowed(op jsonpatch.Operation) (bool, error) {
	path, err := op.Path()
	if err != nil {
		return false, errors.New("patch item has no path")
	}
	switch op.Kind() {
	case "test":
		return true, nil
	case "add", "remove", "replace", "copy":
		return isPatchablePath(path), nil
	case "move":
		from, fromErr := op.From()
		if fromErr != nil {
			return false, errors.New("move patch item has no from")
		}
		return isPatchablePath(path) && isPatchablePath(from), nil
	default:
		return false, errors.New("unknown patch operation: " + op.Kind())
	}
}

func isPatchablePath(path string) bool {
	for _, field := range patchablePaths {
		if path == field || strings.HasPrefix(path, field+"/") {
			return true
		}
	}
	return false
}

// writeProblem writes a TS 29.571 ProblemDetails body.
func (server *Server) writeProblem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Cause  string `json:"cause,omitempty"`
	}{http.StatusText(status), status, detail, cause}); err != nil {
		server.logger.Errorf("failed to encode problem details: %v", err)
	}
}
