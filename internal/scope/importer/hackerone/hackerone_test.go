package hackerone

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeH1 stands up a minimal server that answers GET
// /v1/hackers/programs/<slug>/structured_scopes with canned JSON.
func fakeH1(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/structured_scopes") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
}

func TestImport_MapsAssetTypes(t *testing.T) {
	srv := fakeH1(t, `{
		"data": [
			{"attributes": {"asset_identifier": "*.acme.corp",  "asset_type": "WILDCARD",   "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "api.acme.corp","asset_type": "URL",        "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "10.0.0.0/24",  "asset_type": "CIDR",       "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "1.2.3.4",      "asset_type": "IP_ADDRESS", "eligible_for_submission": true}},
			{"attributes": {"asset_identifier": "not-in-scope.corp","asset_type": "DOMAIN", "eligible_for_submission": false}},
			{"attributes": {"asset_identifier": "ios-app",      "asset_type": "IOS_APP",    "eligible_for_submission": true}}
		]
	}`)
	defer srv.Close()

	c := NewClient(Config{})
	c.baseURL = srv.URL + "/v1" // point at fake

	def, err := c.Import(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	// WILDCARD + URL land in AllowedDomains, ineligible item dropped, unsupported type dropped.
	wantDomains := map[string]bool{"*.acme.corp": true, "api.acme.corp": true}
	if len(def.AllowedDomains) != len(wantDomains) {
		t.Fatalf("domains: want 2, got %v", def.AllowedDomains)
	}
	for _, d := range def.AllowedDomains {
		if !wantDomains[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
	// CIDR passes through; bare IP becomes /32.
	wantCIDRs := map[string]bool{"10.0.0.0/24": true, "1.2.3.4/32": true}
	for _, c := range def.AllowedCIDRs {
		if !wantCIDRs[c] {
			t.Errorf("unexpected cidr %q", c)
		}
	}
	if len(def.AllowedCIDRs) != 2 {
		t.Fatalf("cidrs: want 2, got %v", def.AllowedCIDRs)
	}
}

func TestImport_AuthHeaderWhenCredentialsProvided(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	defer srv.Close()

	c := NewClient(Config{APIUser: "akhil", APIToken: "tkn"})
	c.baseURL = srv.URL + "/v1"
	_, _ = c.Import(context.Background(), "acme")

	if !strings.HasPrefix(seen, "Basic ") {
		t.Fatalf("expected Basic auth header; got %q", seen)
	}
}

func TestImport_SurfacesHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(Config{})
	c.baseURL = srv.URL + "/v1"
	_, err := c.Import(context.Background(), "unknown")
	if err == nil {
		t.Fatal("want error on 404")
	}
}
