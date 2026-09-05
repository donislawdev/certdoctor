package proxy

import "testing"

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
