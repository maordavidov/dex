package microsoft

import (
"encoding/json"
"errors"
"fmt"
"net/http"
"net/http/httptest"
"net/url"
"os"
"reflect"
"testing"

"github.com/dexidp/dex/connector"
)

type testResponse struct {
data interface{}
}

const (
tenant   = "9b1c3439-a67e-4e92-bb0d-0571d44ca965"
clientID = "a115ebf3-6020-4384-8eb1-c0c42e667b6f"
)

var dummyToken = testResponse{data: map[string]interface{}{
"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
"expires_in":   "30",
}}

func TestLoginURL(t *testing.T) {
testURL := "https://test.com"
testState := "some-state"

conn := microsoftConnector{
apiURL:      testURL,
graphURL:    testURL,
redirectURI: testURL,
clientID:    clientID,
tenant:      tenant,
}

loginURL, _, _ := conn.LoginURL(connector.Scopes{}, conn.redirectURI, testState)

parsedLoginURL, _ := url.Parse(loginURL)
queryParams := parsedLoginURL.Query()

expectEquals(t, parsedLoginURL.Path, "/"+tenant+"/oauth2/v2.0/authorize")
expectEquals(t, queryParams.Get("client_id"), clientID)
expectEquals(t, queryParams.Get("redirect_uri"), testURL)
expectEquals(t, queryParams.Get("response_type"), "code")
expectEquals(t, queryParams.Get("scope"), "user.read")
expectEquals(t, queryParams.Get("state"), testState)
expectEquals(t, queryParams.Get("prompt"), "")
expectEquals(t, queryParams.Get("domain_hint"), "")
}

func TestLoginURLWithOptions(t *testing.T) {
testURL := "https://test.com"
promptType := "consent"
domainHint := "domain.hint"

conn := microsoftConnector{
apiURL:      testURL,
graphURL:    testURL,
redirectURI: testURL,
clientID:    clientID,
tenant:      tenant,

promptType: promptType,
domainHint: domainHint,
}

loginURL, _, _ := conn.LoginURL(connector.Scopes{}, conn.redirectURI, "some-state")

parsedLoginURL, _ := url.Parse(loginURL)
queryParams := parsedLoginURL.Query()

expectEquals(t, queryParams.Get("prompt"), promptType)
expectEquals(t, queryParams.Get("domain_hint"), domainHint)
}

func TestUserIdentityFromGraphAPI(t *testing.T) {
s := newTestServer(map[string]testResponse{
"/v1.0/me?$select=id,displayName,userPrincipalName": {
data: user{ID: "S56767889", Name: "Jane Doe", Email: "jane.doe@example.com"},
},
"/" + tenant + "/oauth2/v2.0/token": dummyToken,
})
defer s.Close()

req, _ := http.NewRequest("GET", s.URL, nil)

c := microsoftConnector{apiURL: s.URL, graphURL: s.URL, tenant: tenant}
identity, err := c.HandleCallback(connector.Scopes{Groups: false}, nil, req)
expectNil(t, err)
expectEquals(t, identity.Username, "Jane Doe")
expectEquals(t, identity.UserID, "S56767889")
expectEquals(t, identity.PreferredUsername, "")
expectEquals(t, identity.Email, "jane.doe@example.com")
expectEquals(t, identity.EmailVerified, true)
expectEquals(t, len(identity.Groups), 0)
}

func TestUserGroupsFromGraphAPI(t *testing.T) {
s := newTestServer(map[string]testResponse{
"/v1.0/me?$select=id,displayName,userPrincipalName": {data: user{}},
"/v1.0/me/getMemberGroups": {data: map[string]interface{}{
"value": []string{"a", "b"},
}},
"/" + tenant + "/oauth2/v2.0/token": dummyToken,
})
defer s.Close()

req, _ := http.NewRequest("GET", s.URL, nil)

c := microsoftConnector{apiURL: s.URL, graphURL: s.URL, tenant: tenant}
identity, err := c.HandleCallback(connector.Scopes{Groups: true}, nil, req)
expectNil(t, err)
expectEquals(t, identity.Groups, []string{"a", "b"})
}

func TestUserNotInRequiredGroupFromGraphAPI(t *testing.T) {
s := newTestServer(map[string]testResponse{
"/v1.0/me?$select=id,displayName,userPrincipalName": {
data: user{ID: "user-id-123", Name: "Jane Doe", Email: "jane.doe@example.com"},
},
// The user is a member of groups "c" and "d", but the connector only
// allows group "a" — so the user should be denied.
"/v1.0/me/getMemberGroups": {data: map[string]interface{}{
"value": []string{"c", "d"},
}},
"/" + tenant + "/oauth2/v2.0/token": dummyToken,
})
defer s.Close()

req, _ := http.NewRequest("GET", s.URL, nil)

c := microsoftConnector{
apiURL:   s.URL,
graphURL: s.URL,
tenant:   tenant,
groups:   []string{"a"},
}
_, err := c.HandleCallback(connector.Scopes{Groups: true}, nil, req)
if err == nil {
t.Fatal("expected error when user is not in any required group, got nil")
}

var groupsErr *connector.UserNotInRequiredGroupsError
if !errors.As(err, &groupsErr) {
t.Errorf("expected *connector.UserNotInRequiredGroupsError, got %T: %v", err, err)
}
}

func TestDomainNotAllowed(t *testing.T) {
s := newTestServer(map[string]testResponse{
"/v1.0/me?$select=id,displayName,userPrincipalName": {
data: user{ID: "S56767889", Name: "Jane Doe", Email: "jane.doe@example.com"},
},
"/" + tenant + "/oauth2/v2.0/token": dummyToken,
})
defer s.Close()

req, _ := http.NewRequest("GET", s.URL, nil)

c := microsoftConnector{apiURL: s.URL, graphURL: s.URL, tenant: tenant, allowedDomains: []string{"dcode.tech"}}
identity, err := c.HandleCallback(connector.Scopes{Groups: false}, nil, req)

if err == nil {
t.Error("expected error for domain not allowed, got nil")
}
expectEquals(t, identity, connector.Identity{})
}

func TestDomainListAllowed(t *testing.T) {
testCases := []struct {
email   string
allowed bool
domain  string
}{
{"jane.doe@dcode.tech", true, "dcode.tech"},              // Allowed domain
{"joe.bloggs@example.com", true, "example.com"},          // Allowed domain
{"john.smith@otherdomain.com", false, "otherdomain.com"}, // Not allowed domain
}

for _, tc := range testCases {
s := newTestServer(map[string]testResponse{
"/v1.0/me?$select=id,displayName,userPrincipalName": {
data: user{ID: "S56767889", Name: "John Doe", Email: tc.email},
},
"/" + tenant + "/oauth2/v2.0/token": dummyToken,
})
defer s.Close()

req, _ := http.NewRequest("GET", s.URL, nil)

c := microsoftConnector{
apiURL:         s.URL,
graphURL:       s.URL,
tenant:         tenant,
allowedDomains: []string{"dcode.tech", "example.com"},
}

identity, err := c.HandleCallback(connector.Scopes{Groups: false}, nil, req)

if tc.allowed {
expectNil(t, err)
if reflect.DeepEqual(identity, connector.Identity{}) {
t.Errorf("expected non-empty identity for allowed domain %s", tc.domain)
}
} else {
if err == nil {
t.Errorf("expected error for non-allowed domain %s, got nil", tc.email)
}
expectEquals(t, identity, connector.Identity{})
}
}
}

// TestIsAllowedDomain directly exercises the isAllowedDomain helper with all
// relevant edge-cases so that bugs in the pure logic can be caught without
// needing a mock HTTP server.
func TestIsAllowedDomain(t *testing.T) {
	tests := []struct {
		name           string
		allowedDomains []string
		email          string
		want           bool
	}{
		{
			name:           "empty allowed list permits every domain",
			allowedDomains: []string{},
			email:          "user@any-domain.io",
			want:           true,
		},
		{
			name:           "nil allowed list permits every domain",
			allowedDomains: nil,
			email:          "user@any-domain.io",
			want:           true,
		},
		{
			name:           "email domain matches single allowed domain",
			allowedDomains: []string{"example.com"},
			email:          "user@example.com",
			want:           true,
		},
		{
			name:           "email domain matches one of several allowed domains",
			allowedDomains: []string{"foo.com", "example.com", "bar.org"},
			email:          "user@example.com",
			want:           true,
		},
		{
			name:           "email domain not in allowed list",
			allowedDomains: []string{"example.com"},
			email:          "user@other.com",
			want:           false,
		},
		{
			name:           "email without @ sign is rejected",
			allowedDomains: []string{"example.com"},
			email:          "invalid-email",
			want:           false,
		},
		{
			name:           "email with multiple @ signs is rejected",
			allowedDomains: []string{"example.com"},
			email:          "user@host@example.com",
			want:           false,
		},
		{
			name:           "domain match is case-sensitive",
			allowedDomains: []string{"Example.com"},
			email:          "user@example.com",
			want:           false,
		},
		{
			name:           "exact case match succeeds",
			allowedDomains: []string{"Example.com"},
			email:          "user@Example.com",
			want:           true,
		},
		{
			name:           "empty email string is rejected",
			allowedDomains: []string{"example.com"},
			email:          "",
			want:           false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := microsoftConnector{allowedDomains: tc.allowedDomains}
			got := c.isAllowedDomain(tc.email)
			if got != tc.want {
				t.Errorf("isAllowedDomain(%q) with allowedDomains=%v = %v, want %v",
					tc.email, tc.allowedDomains, got, tc.want)
			}
		})
	}
}

// TestAllowedDomainsEmptyAllowsAll is an integration-level test confirming that
// when no allowedDomains are configured the connector accepts users from any
// domain — i.e. the feature is opt-in and does not break existing behaviour.
func TestAllowedDomainsEmptyAllowsAll(t *testing.T) {
	emails := []string{
		"alice@example.com",
		"bob@dcode.tech",
		"carol@completely-different.org",
	}

	for _, email := range emails {
		s := newTestServer(map[string]testResponse{
			"/v1.0/me?$select=id,displayName,userPrincipalName": {
				data: user{ID: "id-001", Name: "Test User", Email: email},
			},
			"/" + tenant + "/oauth2/v2.0/token": dummyToken,
		})
		defer s.Close()

		req, _ := http.NewRequest("GET", s.URL, nil)
		c := microsoftConnector{
			apiURL:   s.URL,
			graphURL: s.URL,
			tenant:   tenant,
			// intentionally no allowedDomains — all domains must be accepted
		}

		identity, err := c.HandleCallback(connector.Scopes{Groups: false}, nil, req)
		if err != nil {
			t.Errorf("email %q: expected no error with empty allowedDomains, got: %v", email, err)
		}
		if identity.Email != email {
			t.Errorf("email %q: expected identity.Email to be %q, got %q", email, email, identity.Email)
		}
	}
}

// TestEmailToLowercaseWithAllowedDomains verifies that when emailToLowercase is
// enabled the domain comparison still works correctly because the email is
// lowercased before the domain check is performed.
func TestEmailToLowercaseWithAllowedDomains(t *testing.T) {
	tests := []struct {
		name           string
		rawEmail       string   // email returned by the Graph API (potentially mixed-case)
		allowedDomains []string // domains configured in the connector
		wantErr        bool
		wantEmail      string // expected value of identity.Email after lowercasing
	}{
		{
			name:           "mixed-case email lowercased before domain check",
			rawEmail:       "User@Example.COM",
			allowedDomains: []string{"example.com"},
			wantErr:        false,
			wantEmail:      "user@example.com",
		},
		{
			name:           "already lowercase email passes domain check",
			rawEmail:       "user@example.com",
			allowedDomains: []string{"example.com"},
			wantErr:        false,
			wantEmail:      "user@example.com",
		},
		{
			name:           "lowercased domain not in allowed list is rejected",
			rawEmail:       "User@Other.COM",
			allowedDomains: []string{"example.com"},
			wantErr:        true,
			wantEmail:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(map[string]testResponse{
				"/v1.0/me?$select=id,displayName,userPrincipalName": {
					data: user{ID: "id-001", Name: "Test User", Email: tc.rawEmail},
				},
				"/" + tenant + "/oauth2/v2.0/token": dummyToken,
			})
			defer s.Close()

			req, _ := http.NewRequest("GET", s.URL, nil)
			c := microsoftConnector{
				apiURL:           s.URL,
				graphURL:         s.URL,
				tenant:           tenant,
				allowedDomains:   tc.allowedDomains,
				emailToLowercase: true,
			}

			identity, err := c.HandleCallback(connector.Scopes{Groups: false}, nil, req)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error but got identity %+v", identity)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if identity.Email != tc.wantEmail {
				t.Errorf("identity.Email = %q, want %q", identity.Email, tc.wantEmail)
			}
		})
	}
}

func newTestServer(responses map[string]testResponse) *httptest.Server {
s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
response, found := responses[r.RequestURI]
if !found {
fmt.Fprintf(os.Stderr, "Mock response for %q not found\n", r.RequestURI)
http.NotFound(w, r)
return
}
w.Header().Add("Content-Type", "application/json")
json.NewEncoder(w).Encode(response.data)
}))
return s
}

func expectNil(t *testing.T, a interface{}) {
if a != nil {
t.Errorf("Expected %+v to equal nil", a)
}
}

func expectEquals(t *testing.T, a interface{}, b interface{}) {
if !reflect.DeepEqual(a, b) {
t.Errorf("Expected %+v to equal %+v", a, b)
}
}
