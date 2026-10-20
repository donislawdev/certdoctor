package render

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The terminal page at a fixed width - OBS165.
//
// UNTIL 2026-10-20 THE PAGE HAD NO WIDTH. Every summary in a layer was padded to
// the longest one, so a single sentence in the trust matrix set thirteen rows
// four hundred characters wide, and a window of 120 columns broke each of them
// into pieces with the source column floating somewhere in the middle. The tests
// here hold what replaced it: a table when the layer fits on the page, running
// text when it does not, prose wrapped at its spaces and data never wrapped.

// authorityRow is a signer some stores hold and others refuse, with a summary
// longer than one line and store names whose paths have spaces in them.
func authorityRow() report.Finding {
	return report.Finding{
		Kind: report.FindingSigningAuthority,
		Summary: "CN=Example Inspection Root,O=Example Corp,L=Somewhere Far Away,C=US signed this " +
			"certificate and is an authority local to this machine - 1 store(s) here hold it and 3 do not",
		Source: report.SourceDetected,
		SigningAuthority: &report.SigningAuthority{
			Issuer:          "CN=Example Inspection Root,O=Example Corp,L=Somewhere Far Away,C=US",
			LeafFingerprint: leafFingerprint,
			HeldBy:          report.HeldBySomeStores,
			TrustingStores:  []string{"system-store CurrentUser"},
			RefusingStores: []string{
				`java C:\Users\jdoe\OpenJDK\jdk-25`,
				`java C:\Program Files (x86)\Java\jre1.8.0_501`,
				`git C:\Program Files\Git\cmd\git.exe`,
			},
			Caveat: "TLS inspection looks exactly like this and so does an organisation's own certificate " +
				"authority, and nothing measured here tells the two apart",
		},
	}
}

// wrappingRow is the case measured on the owner's machine: a summary that fits
// on the line by itself and does not fit once its source is beside it.
func wrappingRow() report.Finding {
	no := false
	return report.Finding{
		Kind:    report.FindingTrustStore,
		Summary: `java C:\Program Files (x86)\Java\jre1.8.0_501 does NOT trust the presented chain (112 anchors)`,
		Source:  report.SourceDetected,
		TrustStore: &report.TrustStore{
			Runtime:              "java",
			Instance:             `C:\Program Files (x86)\Java\jre1.8.0_501`,
			StoreForm:            report.StoreFile,
			TrustAnchorCount:     112,
			TrustsPresentedChain: &no,
			TrustFailure:         report.UnknownAuthority,
		},
	}
}

// trustSectionAsText is the trust matrix of pageWith(authorityRow(),
// refusingRow(), wrappingRow()) as a person sees it, pinned as text for the same
// reason screenPlainASCII is: so that looking at it is a check and not a habit.
//
// READ IT FOR THE RULES, NOT THE BYTES. The authority's summary wraps under
// itself. The list of stores breaks between stores and lines up after its
// label, and no path is cut at its space. The command runs past the page,
// because a command cut in two is pasted as two. And "detected" travels with
// the last word of the sentence it qualifies instead of standing on a line of
// its own.
const trustSectionAsText = `  ! WARN     L5  Trust matrix     access_denied  one of the configured resolvers could not be read
      CN=Example Inspection Root,O=Example Corp,L=Somewhere Far Away,C=US signed this certificate
        and is an authority local to this machine - 1 store(s) here hold it and 3 do not  detected
        evidence: leaf fingerprint 6153a96f6c53d1a2b9a44b1bd8dbbeaa9e1cbd0b1a25c2d0e8f4a7b3c6d9e2f0
        held by: system-store CurrentUser
        not held by: java C:\Users\jdoe\OpenJDK\jdk-25,
                     java C:\Program Files (x86)\Java\jre1.8.0_501,
                     git C:\Program Files\Git\cmd\git.exe
        note: TLS inspection looks exactly like this and so does an organisation's own certificate
              authority, and nothing measured here tells the two apart
      java jdk-25 does NOT trust the presented chain (158 anchors)  detected
        needs elevated rights: this store is outside this account's own files
        run: "C:\Users\jdoe\OpenJDK\jdk-25\bin\keytool" -importcert -trustcacerts -keystore "C:\Users\jdoe\OpenJDK\jdk-25\lib\security\cacerts" -storepass changeit -alias <alias> -file <certificate.pem>
        replace first: <alias>, <certificate.pem>
        note: installing a newer build of this runtime brings its own store
      java C:\Program Files (x86)\Java\jre1.8.0_501 does NOT trust the presented chain (112
        anchors)  detected
`

// TestALayerTooWideForATableIsWrittenAsText pins the trust matrix laid out as
// text, which is the shape it takes on nearly every real machine.
func TestALayerTooWideForATableIsWrittenAsText(t *testing.T) {
	page := pageWith(t, authorityRow(), refusingRow(), wrappingRow())

	start := strings.Index(page, "  ! WARN     L5")
	end := strings.Index(page, "\nNOTES")
	if start < 0 || end < start {
		t.Fatalf("the page has no trust matrix where it should:\n%s", page)
	}
	if got := page[start:end]; got != trustSectionAsText {
		t.Errorf("the trust matrix changed.\n--- got ---\n%s\n--- want ---\n%s", got, trustSectionAsText)
	}
}

// TestACommandWiderThanThePageIsPrintedWhole is the one exception to the width,
// asked on its own so that it fails with its own name.
func TestACommandWiderThanThePageIsPrintedWhole(t *testing.T) {
	row := refusingRow()
	want := "\n        run: " + row.TrustStore.Fix.Command + "\n"
	if widthOf(want) <= pageWidth {
		t.Fatal("the fixture's command fits on the page, so this no longer tests anything")
	}
	if page := pageWith(t, row); !strings.Contains(page, want) {
		t.Errorf("the command was not printed whole on one line:\n%s", page)
	}
}

// TestTheSourceNeverStandsAloneOnALine is the measured defect of the first
// prototype, kept from coming back.
func TestTheSourceNeverStandsAloneOnALine(t *testing.T) {
	row := wrappingRow()
	alone := widthOf(findingIndent) + widthOf(row.Summary)
	if alone > pageWidth || alone+2+widthOf(row.Source.String()) <= pageWidth {
		t.Fatal("the fixture is no longer a summary that fits only without its source")
	}

	page := pageWith(t, row)
	for _, line := range strings.Split(page, "\n") {
		if strings.TrimSpace(line) == row.Source.String() {
			t.Errorf("the source stands on a line of its own:\n%s", page)
		}
	}
}

// TestAValueInRunningTextIsPrintedWhole: in a layer too wide for a table the
// value still reaches the page, and on one line, spaces and all - it is what the
// machine holds, and a copy of half of it is a different value.
func TestAValueInRunningTextIsPrintedWhole(t *testing.T) {
	value := "-Djavax.net.ssl.trustStore=C:\\Users\\jdoe\\My Stores\\corp.jks -Djavax.net.ssl.trustStorePassword=[redacted]"
	row := environmentRow(strings.Repeat("a long sentence about a variable ", 3), value)

	page := pageWith(t, row)
	if measureFindings([]report.Finding{row}).table {
		t.Fatal("the fixture fits as a table, so this no longer tests running text")
	}
	for _, line := range strings.Split(page, "\n") {
		if strings.Contains(line, "-Djavax") {
			if strings.TrimLeft(line, " ") != value {
				t.Errorf("the value shares its line or was cut: %q", line)
			}
			return
		}
	}
	t.Errorf("the value never reached the page:\n%s", page)
}

// TestARowWithNoSummaryStillSaysWhereItCameFrom is the edge of the rule that the
// source travels with the last word: with no word to travel with, it is printed
// on its own rather than dropped.
func TestARowWithNoSummaryStillSaysWhereItCameFrom(t *testing.T) {
	empty := environmentRow("", "")
	empty.Source = report.SourceDerived
	page := pageWith(t, environmentRow(strings.Repeat("s", pageWidth), ""), empty)

	if !strings.Contains(page, "\n"+findingIndent+report.SourceDerived.String()+"\n") {
		t.Errorf("a row with no summary lost its source:\n%s", page)
	}
}

// TestAListIsEscapedEntryByEntry: the lists on this page used to be escaped
// joined, as one string, and now each entry is escaped on its own so the list
// can wrap between entries. A store name is a path off this machine and a DNS
// name comes from the network, so an entry that skipped the escaping would put
// a sequence a terminal acts on in front of the person reading it.
func TestAListIsEscapedEntryByEntry(t *testing.T) {
	authority := authorityRow()
	authority.SigningAuthority.TrustingStores = []string{hostileText, hostileText}
	authority.SigningAuthority.RefusingStores = []string{hostileText}
	fix := refusingRow()
	fix.TrustStore.Fix.Placeholders = []string{hostileText, hostileText}

	r := handshakeReport()
	for i := range r.Layers {
		switch r.Layers[i].ID {
		case layer.TrustMatrix:
			r.Layers[i].Findings = []report.Finding{authority, fix}
		case layer.TLS:
			carrier := r.Layers[i].Findings[0]
			shake := *carrier.TLSHandshake
			shake.Chain = slices.Clone(shake.Chain)
			shake.Chain[0].DNSNames = []string{hostileText, hostileText}
			carrier.TLSHandshake = &shake
			r.Layers[i].Findings[0] = carrier
		}
	}
	page := renderPage(t, r)

	for i, line := range strings.Split(page, "\n") {
		for _, symbol := range line {
			if forbiddenOnAPage(symbol) {
				t.Fatalf("line %d carries U+%04X, which a terminal acts on: %q", i+1, symbol, line)
			}
		}
	}
	// Seven entries carried it, so seven escaped spellings - a list that
	// deleted the bytes instead would pass the loop above and show a value that
	// is not the one on the machine.
	if got := strings.Count(page, `\u001b`); got != 7 {
		t.Errorf("%d escaped sequences on the page, want 7 - one per hostile entry", got)
	}
}

// environmentRow is a finding whose widths are whatever a test needs them to be.
func environmentRow(summary, value string) report.Finding {
	return report.Finding{
		Kind:    report.FindingEnvironmentVariable,
		Summary: summary,
		Source:  report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{
			Name:  "SOME_VARIABLE",
			Value: value,
			Set:   value != "",
		},
	}
}

// TestALayerIsATableExactlyWhenItsWidestRowFits pins the boundary from both
// sides, with and without a value, because each of the three widths a row adds
// up is a place an off-by-one would hide.
func TestALayerIsATableExactlyWhenItsWidestRowFits(t *testing.T) {
	room := pageWidth - widthOf(findingIndent) - 2 - widthOf(report.SourceDetected.String())

	cases := []struct {
		name  string
		rows  []report.Finding
		table bool
	}{
		{"a summary filling the page", []report.Finding{environmentRow(strings.Repeat("s", room), "")}, true},
		{"one character more", []report.Finding{environmentRow(strings.Repeat("s", room+1), "")}, false},
		{"a value filling the page", []report.Finding{environmentRow(strings.Repeat("s", room-7), "vvvvv")}, true},
		{"a value one character over", []report.Finding{environmentRow(strings.Repeat("s", room-6), "vvvvv")}, false},
		{"a short row beside a long one", []report.Finding{
			environmentRow("short", ""),
			environmentRow(strings.Repeat("s", room+1), ""),
		}, false},
	}
	for _, c := range cases {
		if got := measureFindings(c.rows).table; got != c.table {
			t.Errorf("%s: table is %v, want %v", c.name, got, c.table)
		}
	}
}

// TestEveryLineOfAWrappedVerdictIsPaintedOnItsOwn: a colour left open at a line
// break is a colour a pager drops, and the second half of the verdict would lose
// the status it belongs to.
func TestEveryLineOfAWrappedVerdictIsPaintedOnItsOwn(t *testing.T) {
	r := everyStatusReport()
	r.Verdict.Sentence = strings.Repeat("the verdict says something long ", 10)

	var page strings.Builder
	if err := (Terminal{Color: ColorOn}).Render(&page, r); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}

	var verdict []string
	for _, line := range strings.Split(page.String(), "\n") {
		if strings.Contains(line, "verdict says") {
			verdict = append(verdict, line)
		}
	}
	if len(verdict) < 2 {
		t.Fatalf("a sentence of three hundred characters did not wrap:\n%s", page.String())
	}
	for i, line := range verdict {
		if !strings.HasSuffix(line, reset) {
			t.Errorf("line %d of the verdict leaves its colour open: %q", i, line)
		}
		if i > 0 && !strings.HasPrefix(line, "  \x1b[") {
			t.Errorf("continuation %d of the verdict is not painted from its indent: %q", i, line)
		}
	}
}

// TestTheNamesOfACertificateWrapBetweenNames covers the one list in a chain with
// no limit - a certificate a content network shares names a hundred hosts.
func TestTheNamesOfACertificateWrapBetweenNames(t *testing.T) {
	names := make([]string, 30)
	for i := range names {
		names[i] = fmt.Sprintf("host%02d.cdn.example.com", i)
	}

	r := handshakeReport()
	for i := range r.Layers {
		if r.Layers[i].ID != layer.TLS {
			continue
		}
		// A copy, because the fixture's chain is shared with every other test.
		carrier := r.Layers[i].Findings[0]
		shake := *carrier.TLSHandshake
		shake.Chain = slices.Clone(shake.Chain)
		shake.Chain[0].DNSNames = names
		carrier.TLSHandshake = &shake
		r.Layers[i].Findings[0] = carrier
	}
	page := renderPage(t, r)

	rows := strings.Split(page, "\n")
	first := slices.IndexFunc(rows, func(line string) bool { return strings.Contains(line, "names      ") })
	if first < 0 {
		t.Fatalf("the page has no names line:\n%s", page)
	}
	// Every continuation lines up under the first name, which is where the label
	// line's own text starts after "names".
	column := strings.Repeat(" ", strings.Index(rows[first], "names      ")+widthOf("names      "))
	shown := 0
	for i, line := range rows[first:] {
		if i > 0 && !strings.HasPrefix(line, column+"host") {
			break
		}
		if widthOf(line) > pageWidth {
			t.Errorf("a line of names ran past the page: %q", line)
		}
		shown += strings.Count(line, ".cdn.example.com")
	}
	if shown != len(names) {
		t.Errorf("%d of %d names reached the block under the names label:\n%s", shown, len(names), page)
	}
	for _, name := range names {
		if !strings.Contains(page, name) {
			t.Errorf("%s was cut or lost", name)
		}
	}
}

// TestANoteWrapsUnderItsOwnText: the continuation of a note lines up with the
// text after its dash, so the dash column stays a column of notes.
func TestANoteWrapsUnderItsOwnText(t *testing.T) {
	r := everyStatusReport()
	r.Notes = []report.Note{{
		Kind:   report.NoteUndetermined,
		Field:  "run.platform.container",
		Detail: strings.Repeat("a note that goes on ", 12),
	}}
	page := renderPage(t, r)

	notes := strings.Split(page[strings.Index(page, "NOTES\n")+len("NOTES\n"):], "\n")
	if !strings.HasPrefix(notes[0], "  - run.platform.container [undetermined] a note") {
		t.Fatalf("the note does not open with its field and kind: %q", notes[0])
	}
	if !strings.HasPrefix(notes[1], "    ") || strings.TrimLeft(notes[1], " ") == "" ||
		strings.HasPrefix(notes[1], "     ") || strings.HasPrefix(notes[1], "    -") {
		t.Errorf("the note did not continue under its text: %q", notes[1])
	}
	for _, line := range notes[:2] {
		if widthOf(line) > pageWidth {
			t.Errorf("a line of the note ran past the page: %q", line)
		}
	}
}

// TestNoLineOfProseRunsPastThePage is the width as a property of the page:
// every field that is a sentence made long, every datum kept short, and not one
// line over. A field printed some new way that forgot to wrap fails here, not
// in a window somebody happened to have open.
func TestNoLineOfProseRunsPastThePage(t *testing.T) {
	long := strings.Repeat("a sentence of ordinary words ", 12)

	r := everyStatusReport()
	r.Verdict.Sentence = long
	for i := range r.Layers {
		r.Layers[i].Detail = long
	}
	for i := range r.Notes {
		r.Notes[i].Detail = long
	}

	authority := authorityRow()
	authority.Summary = long
	authority.SigningAuthority.Caveat = long
	stores := make([]string, 12)
	for i := range stores {
		stores[i] = fmt.Sprintf("java jdk-%d", i)
	}
	authority.SigningAuthority.RefusingStores = stores

	fix := refusingRow()
	fix.Summary = long
	fix.TrustStore.Fix.Command = "keytool -importcert"
	fix.TrustStore.Fix.Elevation = long
	fix.TrustStore.Fix.Caveat = long

	stack := bodyFixtures[report.FindingProxyStack]
	stack.Summary = long
	body := *stack.ProxyStack
	body.Caveats = []string{long, long}
	stack.ProxyStack = &body

	for i := range r.Layers {
		if r.Layers[i].ID == layer.TrustMatrix {
			r.Layers[i].Findings = []report.Finding{authority, fix, stack}
		}
	}

	for i, line := range strings.Split(renderPage(t, r), "\n") {
		if widthOf(line) > pageWidth {
			t.Errorf("line %d is %d wide: %q", i+1, widthOf(line), line)
		}
	}
}
