package proxy

import (
	"fmt"
	"strings"
	"testing"
)

func TestAProxyListIsCutOnSemicolonsOrWhitespace(t *testing.T) {
	cases := []struct {
		name string
		list string
		want []Server
	}{
		{
			name: "a bare name is the default for every protocol",
			list: "proxy_server",
			want: []Server{{Address: "proxy_server"}},
		},
		{
			name: "the vendor's worked example",
			list: "http=http_proxy other_proxy",
			want: []Server{
				{Protocol: "http", Address: "http_proxy"},
				{Address: "other_proxy"},
			},
		},
		{
			name: "semicolons cut as well as spaces",
			list: "http=a;https=b",
			want: []Server{
				{Protocol: "http", Address: "a"},
				{Protocol: "https", Address: "b"},
			},
		},
		{
			name: "the proxy has a scheme of its own",
			list: "https=http://p.corp:8080",
			want: []Server{{Protocol: "https", Scheme: "http", Address: "p.corp:8080"}},
		},
		{
			name: "a scheme without a protocol",
			list: "http://p.corp:8080",
			want: []Server{{Scheme: "http", Address: "p.corp:8080"}},
		},
		{
			name: "the protocol is case insensitive and the address is left alone",
			list: "HTTPS=P.Corp:8080",
			want: []Server{{Protocol: "https", Address: "P.Corp:8080"}},
		},
		{
			name: "an entry naming no address is dropped",
			list: "http=;https=b",
			want: []Server{{Protocol: "https", Address: "b"}},
		},
		{
			name: "a path is not part of a server name",
			list: "http://p.corp:8080/proxy.pac",
			want: []Server{{Scheme: "http", Address: "p.corp:8080"}},
		},
		{
			name: "an equals sign after the scheme is not a protocol",
			list: "http://p.corp/?a=b",
			want: []Server{{Scheme: "http", Address: "p.corp"}},
		},
		{
			name: "an empty list names nobody",
			list: "   ;; ",
			want: []Server{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseServerList(c.list)
			if len(got) != len(c.want) {
				t.Fatalf("list %q gave %d entries, want %d: %+v", c.list, len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("list %q entry %d is %+v, want %+v", c.list, i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestTheProtocolEntryWinsAndTheBareOneIsTheFallback is the vendor's example
// read literally, and it is the whole reason Protocol and Scheme are two fields.
func TestTheProtocolEntryWinsAndTheBareOneIsTheFallback(t *testing.T) {
	servers := ParseServerList("http=http_proxy other_proxy")

	if got, ok := ServerFor(servers, "http"); !ok || got.Address != "http_proxy" {
		t.Errorf("an http request got %+v (found %v), want http_proxy", got, ok)
	}
	if got, ok := ServerFor(servers, "https"); !ok || got.Address != "other_proxy" {
		t.Errorf("an https request got %+v (found %v), want other_proxy", got, ok)
	}
	if got, ok := ServerFor(servers, "HTTP"); !ok || got.Address != "http_proxy" {
		t.Errorf("an upper case protocol got %+v (found %v), want http_proxy", got, ok)
	}
}

func TestAListWithoutADefaultAnswersOnlyTheProtocolsItNames(t *testing.T) {
	servers := ParseServerList("http=a;https=b")

	if got, ok := ServerFor(servers, "https"); !ok || got.Address != "b" {
		t.Errorf("https got %+v (found %v), want b", got, ok)
	}
	if got, ok := ServerFor(servers, "ftp"); ok {
		t.Errorf("ftp got %+v, and no entry in this list applies to it", got)
	}
	if _, ok := ServerFor(nil, "http"); ok {
		t.Error("an empty list answered that some proxy applies")
	}
}

// TestAskingWithNoProtocolGivesTheDefaultEntry pins the behaviour a caller who
// does not know the scheme gets. It is deliberately NOT phrased as a claim about
// which of the two loops answers: a default entry is one whose Protocol is
// empty, so an empty question finds it in the first, and a test naming the loop
// would be defending an implementation rather than a promise.
func TestAskingWithNoProtocolGivesTheDefaultEntry(t *testing.T) {
	servers := ParseServerList("http=a other")
	got, ok := ServerFor(servers, "")
	if !ok || got.Address != "other" {
		t.Errorf("asking with no protocol gave %+v (found %v), want the default entry", got, ok)
	}
}

func TestADefaultEntryIsRecognisedAsOne(t *testing.T) {
	if !(Server{Address: "p"}).IsDefault() {
		t.Error("an entry naming no protocol is not the default")
	}
	if (Server{Protocol: "http", Address: "p"}).IsDefault() {
		t.Error("an entry naming a protocol is being treated as the default for every other one")
	}
}

// TestAPasswordInAProxyEntryNeverReachesTheServer is inviolable rule 17 made
// structural rather than promised: the value is not removed from Address by
// something downstream, it never gets in.
//
// THE LAST ASSERTION LOOKS AT THE WHOLE STRUCT AND NOT AT Address, which is the
// half that would rot first. A field added later and quietly filled with the raw
// entry would leave every Address assertion green.
func TestAPasswordInAProxyEntryNeverReachesTheServer(t *testing.T) {
	const secret = "hunter2"
	cases := []struct {
		name    string
		entry   string
		dropped bool
		want    Server
	}{
		{
			name:  "a user and a password",
			entry: "http://bob:hunter2@p.corp:8080",
			want:  Server{Scheme: "http", Address: "p.corp:8080", CarriedCredentials: true},
		},
		{
			name:  "a user with no password is still a credential",
			entry: "http://bob@p.corp:8080",
			want:  Server{Scheme: "http", Address: "p.corp:8080", CarriedCredentials: true},
		},
		{
			name:  "an empty userinfo carries nothing to hide",
			entry: "http://@p.corp:8080",
			want:  Server{Scheme: "http", Address: "p.corp:8080"},
		},
		{
			name:  "an at sign in a path is not userinfo",
			entry: "http://p.corp:8080/a@b",
			want:  Server{Scheme: "http", Address: "p.corp:8080"},
		},
		{
			name:  "a password holding an at sign is cut at the last one",
			entry: "http://bob:hunter2@x@p.corp:8080",
			want:  Server{Scheme: "http", Address: "p.corp:8080", CarriedCredentials: true},
		},
		{
			name:    "credentials and no address name nobody",
			entry:   "http://bob:hunter2@",
			dropped: true,
		},
		{
			name:  "an entry with a protocol keeps it",
			entry: "https=http://bob:hunter2@p.corp:8080",
			want:  Server{Protocol: "https", Scheme: "http", Address: "p.corp:8080", CarriedCredentials: true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseServerList(c.entry)
			if c.dropped {
				if len(got) != 0 {
					t.Fatalf("entry %q gave %+v, and it names no address at all", c.entry, got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("entry %q gave %d servers, want 1: %+v", c.entry, len(got), got)
			}
			if got[0] != c.want {
				t.Errorf("entry %q gave %+v, want %+v", c.entry, got[0], c.want)
			}
			if strings.Contains(fmt.Sprintf("%+v", got[0]), secret) {
				t.Errorf("entry %q left the password somewhere in %+v", c.entry, got[0])
			}
		})
	}
}
