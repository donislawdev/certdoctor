package pac

import (
	"testing"
	"time"
)

// frozen returns ports whose clock always reads moment.
//
// THE MOMENT IS CHECKED AGAINST THE STANDARD LIBRARY BEFORE IT IS USED. A test
// asserting "Friday" against a date nobody verified would pass just as happily
// on a Thursday, and the failure would look like a bug in WeekdayRange. time is
// an independent witness here: it shares no line with the code under test.
func frozen(t *testing.T, iso string, want time.Weekday) Ports {
	t.Helper()
	moment, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		t.Fatalf("bad fixture time %q: %v", iso, err)
	}
	if got := moment.UTC().Weekday(); got != want {
		t.Fatalf("fixture %s is a %v, not the %v this test is written about", iso, got, want)
	}
	return Ports{Now: func() time.Time { return moment }}
}

const gmt = "GMT"

func TestWeekdayRange(t *testing.T) {
	// A Wednesday, checked above.
	ports := frozen(t, "2026-09-02T12:00:00Z", time.Wednesday)

	for _, c := range []struct {
		name             string
		args             []Argument
		want, understood bool
	}{
		// Mozilla's documented examples.
		{"the day itself", []Argument{TextArgument("WED"), TextArgument(gmt)}, true, true},
		{"another day", []Argument{TextArgument("SAT"), TextArgument(gmt)}, false, true},
		{"MON to FRI covers it", []Argument{TextArgument("MON"), TextArgument("FRI"), TextArgument(gmt)}, true, true},
		{"THU to FRI does not", []Argument{TextArgument("THU"), TextArgument("FRI"), TextArgument(gmt)}, false, true},

		// THE DOCUMENTED SURPRISE: a descending pair does NOT wrap. Mozilla
		// says weekdayRange("WED","SUN") is true "only if current day is
		// Wednesday or Sunday" - so today matches as a BOUND, not as a member
		// of a range running Wed-Thu-Fri-Sat-Sun.
		{"descending pair matches the bound", []Argument{TextArgument("WED"), TextArgument("SUN"), TextArgument(gmt)}, true, true},
		// The same descending pair on a day INSIDE the wrapped range must be
		// false. This is the row that fails if somebody "fixes" the wrap.
		{"descending pair excludes the middle", []Argument{TextArgument("SAT"), TextArgument("TUE"), TextArgument(gmt)}, false, true},

		// Shapes we refuse to guess at rather than answering false.
		{"not a weekday", []Argument{TextArgument("XYZ")}, false, false},
		{"a number", []Argument{NumberArgument(3)}, false, false},
		{"no arguments", nil, false, false},
		{"three days", []Argument{TextArgument("MON"), TextArgument("TUE"), TextArgument("WED")}, false, false},
	} {
		got, understood := ports.WeekdayRange(c.args)
		if got != c.want || understood != c.understood {
			t.Errorf("%s: WeekdayRange = (%v, %v), want (%v, %v)", c.name, got, understood, c.want, c.understood)
		}
	}
}

func TestDateRange(t *testing.T) {
	// 2 September 2026.
	ports := frozen(t, "2026-09-02T12:00:00Z", time.Wednesday)

	for _, c := range []struct {
		name             string
		args             []Argument
		want, understood bool
	}{
		// Single values. A bare number 31 or under is a DAY, above it a YEAR -
		// the specification's own rule, and the reason dateRange(2) and
		// dateRange(2026) mean entirely different things.
		{"day of the month", []Argument{NumberArgument(2), TextArgument(gmt)}, true, true},
		{"another day", []Argument{NumberArgument(3), TextArgument(gmt)}, false, true},
		{"the month", []Argument{TextArgument("SEP"), TextArgument(gmt)}, true, true},
		{"another month", []Argument{TextArgument("JAN"), TextArgument(gmt)}, false, true},
		{"the year", []Argument{NumberArgument(2026), TextArgument(gmt)}, true, true},
		{"another year", []Argument{NumberArgument(1995), TextArgument(gmt)}, false, true},

		// Pairs.
		{"first half of the month", []Argument{NumberArgument(1), NumberArgument(15), TextArgument(gmt)}, true, true},
		{"second half", []Argument{NumberArgument(16), NumberArgument(31), TextArgument(gmt)}, false, true},
		{"a quarter", []Argument{TextArgument("JUL"), TextArgument("SEP"), TextArgument(gmt)}, true, true},
		{"years 1995 to 1997", []Argument{NumberArgument(1995), NumberArgument(1997), TextArgument(gmt)}, false, true},
		{"years 2020 to 2030", []Argument{NumberArgument(2020), NumberArgument(2030), TextArgument(gmt)}, true, true},
		// Descending months do not wrap, same rule as weekdays.
		{"DEC to JAN excludes September", []Argument{TextArgument("DEC"), TextArgument("JAN"), TextArgument(gmt)}, false, true},

		// Day and month, four arguments, repeating every year.
		{"1 JUN to 15 AUG", []Argument{NumberArgument(1), TextArgument("JUN"), NumberArgument(15), TextArgument("AUG"), TextArgument(gmt)}, false, true},
		{"1 JUN to 15 SEP", []Argument{NumberArgument(1), TextArgument("JUN"), NumberArgument(15), TextArgument("SEP"), TextArgument(gmt)}, true, true},

		// Month and year, four arguments.
		{"OCT 1995 to MAR 1996", []Argument{TextArgument("OCT"), NumberArgument(1995), TextArgument("MAR"), NumberArgument(1996), TextArgument(gmt)}, false, true},
		{"JAN 2026 to DEC 2026", []Argument{TextArgument("JAN"), NumberArgument(2026), TextArgument("DEC"), NumberArgument(2026), TextArgument(gmt)}, true, true},

		// Full dates, six arguments.
		{"1 JUN 1995 to 15 AUG 1995", []Argument{NumberArgument(1), TextArgument("JUN"), NumberArgument(1995), NumberArgument(15), TextArgument("AUG"), NumberArgument(1995), TextArgument(gmt)}, false, true},
		{"1 JAN 2026 to 31 DEC 2026", []Argument{NumberArgument(1), TextArgument("JAN"), NumberArgument(2026), NumberArgument(31), TextArgument("DEC"), NumberArgument(2026), TextArgument(gmt)}, true, true},

		// Shapes we will not guess at.
		{"a day and a year in one pair", []Argument{NumberArgument(2), NumberArgument(2026)}, false, false},
		{"three arguments", []Argument{NumberArgument(1), NumberArgument(2), NumberArgument(3)}, false, false},
		{"not a month", []Argument{TextArgument("SMARCH")}, false, false},
	} {
		got, understood := ports.DateRange(c.args)
		if got != c.want || understood != c.understood {
			t.Errorf("%s: DateRange = (%v, %v), want (%v, %v)", c.name, got, understood, c.want, c.understood)
		}
	}
}

func TestTimeRange(t *testing.T) {
	// 14:30:15 UTC.
	ports := frozen(t, "2026-09-02T14:30:15Z", time.Wednesday)

	for _, c := range []struct {
		name             string
		args             []Argument
		want, understood bool
	}{
		// One argument is an HOUR, not an instant: noon means noon until one.
		{"the hour itself", []Argument{NumberArgument(14), TextArgument(gmt)}, true, true},
		{"the hour before", []Argument{NumberArgument(13), TextArgument(gmt)}, false, true},
		{"9 to 17", []Argument{NumberArgument(9), NumberArgument(17), TextArgument(gmt)}, true, true},
		{"17 to 18", []Argument{NumberArgument(17), NumberArgument(18), TextArgument(gmt)}, false, true},
		{"8:30 to 17:00", []Argument{NumberArgument(8), NumberArgument(30), NumberArgument(17), NumberArgument(0), TextArgument(gmt)}, true, true},
		{"8:30 to 14:00", []Argument{NumberArgument(8), NumberArgument(30), NumberArgument(14), NumberArgument(0), TextArgument(gmt)}, false, true},
		{"to the second", []Argument{NumberArgument(14), NumberArgument(30), NumberArgument(0), NumberArgument(14), NumberArgument(30), NumberArgument(30), TextArgument(gmt)}, true, true},
		{"a second too early", []Argument{NumberArgument(14), NumberArgument(29), NumberArgument(0), NumberArgument(14), NumberArgument(30), NumberArgument(14), TextArgument(gmt)}, false, true},

		// Shapes we will not guess at: three and five arguments are not among
		// the documented forms, and a word is not a time.
		{"three arguments", []Argument{NumberArgument(1), NumberArgument(2), NumberArgument(3)}, false, false},
		{"five arguments", []Argument{NumberArgument(1), NumberArgument(2), NumberArgument(3), NumberArgument(4), NumberArgument(5)}, false, false},
		{"a word", []Argument{TextArgument("NOON")}, false, false},
	} {
		got, understood := ports.TimeRange(c.args)
		if got != c.want || understood != c.understood {
			t.Errorf("%s: TimeRange = (%v, %v), want (%v, %v)", c.name, got, understood, c.want, c.understood)
		}
	}
}

// TestTheTimeHelpersRefuseWithoutAClock pins the direction a missing port fails
// in. Answering false would be a verdict; answering "not understood" is the
// absence of one, which is what inviolable rule 15 asks for.
func TestTheTimeHelpersRefuseWithoutAClock(t *testing.T) {
	var none Ports
	if _, understood := none.WeekdayRange([]Argument{TextArgument("WED")}); understood {
		t.Error("WeekdayRange claimed to understand a question it had no clock to answer")
	}
	if _, understood := none.DateRange([]Argument{NumberArgument(1)}); understood {
		t.Error("DateRange claimed to understand a question it had no clock to answer")
	}
	if _, understood := none.TimeRange([]Argument{NumberArgument(1)}); understood {
		t.Error("TimeRange claimed to understand a question it had no clock to answer")
	}
}
