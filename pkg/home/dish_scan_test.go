package home

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dishPhotoReply = `{"name":"  misal   pav ","kcal":870,"proteinG":20,"carbsG":110,"fatG":32,"ingredients":[{"name":"moth beans","qty":"200 g"},{"name":"Pav","qty":"4 pcs"},{"name":"Farsan","qty":"a handful"}]}`

func TestReadDishNamesThePlateAndFillsTheNumbers(t *testing.T) {
	vision, prompt := fakeModel(t, dishPhotoReply, "end_turn")
	scan, err := vision.ReadDish(context.Background(), base64.StdEncoding.EncodeToString([]byte("jpeg bytes")), "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	if scan.Name != "Misal pav" || scan.Kcal != 870 || scan.ProteinG != 20 || scan.CarbsG != 110 || scan.FatG != 32 || scan.Serves != 2 {
		t.Fatalf("scan: %+v", scan)
	}
	if len(scan.Ingredients) != 2 || scan.Ingredients[0].Name != "Moth beans" || scan.Ingredients[1].Qty != "4 pcs" {
		t.Fatalf("ingredients should be the two countable rows, title-cased: %+v", scan.Ingredients)
	}
	if !strings.Contains(*prompt, "Name the dish") || !strings.Contains(*prompt, "ONE serving in the photo") {
		t.Fatalf("prompt did not ask for a named plate: %s", *prompt)
	}
}

func TestReadDishRefusesWhatIsNotADish(t *testing.T) {
	cases := map[string]struct{ reply, stop string }{
		"no food in the photo":    {`{"name":"","kcal":0,"proteinG":0,"carbsG":0,"fatG":0,"ingredients":[]}`, "end_turn"},
		"named but zero calories": {`{"name":"Empty plate","kcal":0,"proteinG":0,"carbsG":0,"fatG":0,"ingredients":[]}`, "end_turn"},
		"name too long":           {`{"name":"` + strings.Repeat("x", 81) + `","kcal":400,"proteinG":10,"carbsG":50,"fatG":12,"ingredients":[]}`, "end_turn"},
		"calories out of range":   {`{"name":"Thali","kcal":9000,"proteinG":10,"carbsG":50,"fatG":12,"ingredients":[]}`, "end_turn"},
		"not json":                {`looks like misal pav`, "end_turn"},
		"refusal":                 {`{}`, "refusal"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			vision, _ := fakeModel(t, tc.reply, tc.stop)
			if _, err := vision.ReadDish(context.Background(), "aGk=", "image/jpeg"); err != errScanFailed {
				t.Fatalf("expected scan_failed, got %v", err)
			}
		})
	}
}

func TestScanDishRouteNeedsAKey(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	status, body := call(t, server, http.MethodPost, "/v1/dishes/scan", token, map[string]any{"image": "aGk=", "mediaType": "image/jpeg"})
	if status != http.StatusServiceUnavailable || body["error"].(map[string]any)["code"] != "scan_unavailable" {
		t.Fatalf("without a key: %d %v", status, body)
	}
}

func TestScanDishRouteChecksTheUploadBeforeTheModel(t *testing.T) {
	store := testStore(t)
	vision, _ := fakeModel(t, dishPhotoReply, "end_turn")
	server := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, vision))
	t.Cleanup(server.Close)
	username, password := testUser(t, store)
	image := base64.StdEncoding.EncodeToString([]byte("jpeg bytes"))
	if status, _ := call(t, server, http.MethodPost, "/v1/dishes/scan", "", map[string]any{"image": image, "mediaType": "image/jpeg"}); status != http.StatusUnauthorized {
		t.Fatalf("without a token: %d", status)
	}
	token := signIn(t, server, username, password)
	rejected := map[string]map[string]any{
		"not an image type": {"image": image, "mediaType": "application/pdf"},
		"not base64":        {"image": "not base64!!", "mediaType": "image/jpeg"},
		"empty image":       {"image": "", "mediaType": "image/jpeg"},
		"over 5 MB":         {"image": base64.StdEncoding.EncodeToString(make([]byte, maxScanImageSize+1)), "mediaType": "image/png"},
	}
	for name, body := range rejected {
		if status, reply := call(t, server, http.MethodPost, "/v1/dishes/scan", token, body); status/100 != 4 || status == http.StatusUnauthorized {
			t.Fatalf("%s: %d %v", name, status, reply)
		}
	}
	status, body := call(t, server, http.MethodPost, "/v1/dishes/scan", token, map[string]any{"image": image, "mediaType": "image/jpeg"})
	if status != http.StatusOK || body["name"] != "Misal pav" || body["kcal"].(float64) != 870 || body["serves"].(float64) != 2 || len(body["ingredients"].([]any)) != 2 {
		t.Fatalf("scan: %d %v", status, body)
	}
}
