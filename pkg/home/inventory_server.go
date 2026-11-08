package home

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	inventoryScanPath = "/v1/inventory/scan"
	// maxScanBytes fits a phone photo downsized by the app (about 1280 px, 70 % JPEG) with room to spare.
	maxScanBytes = 6 << 20
	// scanTimeout is how long one photo may take end to end; every other route keeps requestTimeout.
	scanTimeout      = 25 * time.Second
	maxItemName      = 80
	maxQuantityText  = 40
	maxStockAmount   = 1_000_000
	maxScanItems     = 40
	maxScanImageSize = 5 << 20
)

var scanMediaTypes = set("image/jpeg", "image/png", "image/webp", "image/gif")

var errScanUnavailable = apiError{status: http.StatusServiceUnavailable, Code: "scan_unavailable", Message: "photo scan is not set up on this server"}

// listInventory answers the Inventory screen: every item in stock and the recent moves behind the numbers.
func (s *Server) listInventory(w http.ResponseWriter, r *http.Request) {
	items, moves, err := s.store.Inventory(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "moves": moves})
}

type addStockBody struct {
	Name       string     `json:"name"`
	Qty        string     `json:"qty"`
	Reason     string     `json:"reason"`
	MealID     *uuid.UUID `json:"mealId"`
	Ingredient *int       `json:"ingredient"`
}

// addStock puts a bought amount into stock: {name, qty: "1 kg"}. With mealId and ingredient it marks one recipe
// line as bought, which happens once however many times it is sent.
// Handles: an amount the parser cannot read (400 naming it), an item kept in another unit (409), reason defaults to bought
func (s *Server) addStock(w http.ResponseWriter, r *http.Request) {
	var body addStockBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	name := strings.TrimSpace(body.Name)
	reason := body.Reason
	if reason == "" {
		reason = "bought"
	}
	quantity, ok := ParseQuantity(body.Qty)
	switch {
	case !textBetween(name, 1, maxItemName):
		writeError(w, r, badRequest(fmt.Sprintf("name must be 1 to %d characters", maxItemName)))
		return
	case !textBetween(body.Qty, 1, maxQuantityText) || !ok:
		writeError(w, r, badRequest("qty must be an amount like 200 g, 1 kg, 500 ml or 2 pcs"))
		return
	case quantity.Amount > maxStockAmount:
		writeError(w, r, badRequest("that amount is too large"))
		return
	case reason != "bought" && reason != "scanned":
		writeError(w, r, badRequest("reason must be bought or scanned"))
		return
	case (body.MealID == nil) != (body.Ingredient == nil):
		writeError(w, r, badRequest("mealId and ingredient go together"))
		return
	case body.Ingredient != nil && (*body.Ingredient < 0 || *body.Ingredient >= maxIngredients):
		writeError(w, r, badRequest(fmt.Sprintf("ingredient must be 0 to %d", maxIngredients-1)))
		return
	}
	item, err := s.store.AddStock(r.Context(), name, quantity, reason, body.MealID, body.Ingredient, actor(r).ID)
	if errors.Is(err, ErrUnitMismatch) {
		writeError(w, r, apiError{status: http.StatusConflict, Code: "unit_mismatch", Message: "that item is kept in a different unit; add it in that unit or correct the item first"})
		return
	}
	if isCode(err, "23503") {
		writeError(w, r, badRequest("that meal no longer exists"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type unbuyBody struct {
	MealID     uuid.UUID `json:"mealId"`
	Ingredient int       `json:"ingredient"`
}

// unbuyLine clears a recipe line ticked as bought and takes its amount back out of stock.
func (s *Server) unbuyLine(w http.ResponseWriter, r *http.Request) {
	var body unbuyBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	item, err := s.store.UnbuyLine(r.Context(), body.MealID, body.Ingredient)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type setStockBody struct {
	Name *string  `json:"name"`
	Unit *string  `json:"unit"`
	Qty  *float64 `json:"qty"`
}

// setStock corrects one item by hand: rename it, change its unit, or set what is really on the shelf.
func (s *Server) setStock(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	var body setStockBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if body.Name != nil {
		trimmed := strings.TrimSpace(*body.Name)
		body.Name = &trimmed
	}
	switch {
	case body.Name == nil && body.Unit == nil && body.Qty == nil:
		writeError(w, r, badRequest("nothing to change"))
		return
	case body.Name != nil && !textBetween(*body.Name, 1, maxItemName):
		writeError(w, r, badRequest(fmt.Sprintf("name must be 1 to %d characters", maxItemName)))
		return
	case !oneOfOrNil(body.Unit, inventoryUnits):
		writeError(w, r, badRequest("unit must be g, ml or pcs"))
		return
	case body.Qty != nil && (*body.Qty < 0 || *body.Qty > maxStockAmount || *body.Qty != *body.Qty):
		writeError(w, r, badRequest("qty must be 0 or more"))
		return
	}
	item, err := s.store.SetStock(r.Context(), id, InventoryPatch{Name: body.Name, Unit: body.Unit, Qty: body.Qty}, actor(r).ID)
	if errors.Is(err, ErrConflict) {
		writeError(w, r, apiError{status: http.StatusConflict, Code: "duplicate_item", Message: "another item already has that name"})
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) removeInventoryItem(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	if err := s.store.RemoveInventoryItem(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type scanBody struct {
	Image     string `json:"image"`
	MediaType string `json:"mediaType"`
}

// scanInventory reads a photo of groceries into suggested stock rows. Nothing is written: the app shows the rows for
// the member to edit and confirm, then sends each through addStock.
// Handles: no vision key on the server (503), a non-image or oversized upload (400), a reply the parser cannot
// read (the row is dropped), a refused or empty answer (502 with a plain message)
func (s *Server) scanInventory(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errScanUnavailable)
		return
	}
	var body scanBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if !scanMediaTypes[body.MediaType] {
		writeError(w, r, badRequest("mediaType must be image/jpeg, image/png, image/webp or image/gif"))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.Image)
	if err != nil || len(raw) == 0 || len(raw) > maxScanImageSize {
		writeError(w, r, badRequest("image must be base64 and at most 5 MB"))
		return
	}
	items, err := s.vision.ReadGroceries(r.Context(), body.Image, body.MediaType)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
