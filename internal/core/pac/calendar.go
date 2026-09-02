package pac

import (
	"strings"
	"time"
)

// Argument is one value a PAC file passed to a time helper.
//
// THE THREE TIME HELPERS ARE VARIADIC AND MIX TYPES, WHICH IS WHY THIS EXISTS.
// dateRange accepts seven documented shapes and tells a day from a year by
// SIZE - not by position - so the arguments have to arrive with their types
// intact rather than pre-converted.
type Argument struct {
	Text   string
	Number int
	IsText bool
}

// TextArgument and NumberArgument build the two kinds.
func TextArgument(s string) Argument { return Argument{Text: s, IsText: true} }
func NumberArgument(n int) Argument  { return Argument{Number: n} }

// weekdays and months carry the spellings the specification fixes.
var weekdays = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
var months = []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}

// within is the ordering rule all three time helpers share.
//
// IT IS THE PART THAT LOOKS LIKE A BUG AND IS NOT - SOURCE: Mozilla's PAC
// documentation, read 2026-09-02, under all three functions. When the bounds are
// given in ascending order the range is inclusive and ordinary. When they are
// given DESCENDING it does NOT wrap: weekdayRange("WED","SUN") is documented as
// true "only if current day is Wednesday or Sunday", and dateRange("DEC","JAN")
// likewise matches December or January and nothing between.
//
// BEFORE FIREFOX 49 THE DESCENDING FORM WAS ALWAYS TRUE, which is why a PAC file
// in the wild may have been written against either behaviour. We follow the
// current one, because that is what the browser reading the file today does.
//
// IT LIVES IN ONE FUNCTION FOR THE REASON OBS50 KEEPS MEASURING: written out
// three times it would be one rule in three places, and the first sign of the
// copies disagreeing would be the mutation register reporting SKIP.
func within(now, lo, hi int) bool {
	if lo <= hi {
		return now >= lo && now <= hi
	}
	return now == lo || now == hi
}

// splitGMT removes a trailing "GMT" argument and says whether it was there.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - every one of the three
// helpers takes an optional final argument that is either the string "GMT" or
// absent, meaning local time.
func splitGMT(args []Argument) ([]Argument, bool) {
	if n := len(args); n > 0 && args[n-1].IsText && strings.EqualFold(args[n-1].Text, "GMT") {
		return args[:n-1], true
	}
	return args, false
}

// indexOf returns the position of name in table, or -1.
func indexOf(table []string, name string) int {
	for i, candidate := range table {
		if strings.EqualFold(candidate, name) {
			return i
		}
	}
	return -1
}

// at returns the current time in the zone the arguments asked for.
func (p Ports) at(gmt bool) (time.Time, bool) {
	if p.Now == nil {
		return time.Time{}, false
	}
	now := p.Now()
	if gmt {
		return now.UTC(), true
	}
	return now.Local(), true
}

// WeekdayRange reports whether today falls in the given range of weekdays.
//
// It returns (result, understood). An unrecognised shape - a spelling that is
// not one of the seven days, or too many arguments - is reported as NOT
// understood rather than as false, because a PAC file this program cannot read
// is inviolable rule 15's case: unknown is never a quiet no.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - one day means that day,
// two days mean the range between them under the ordering rule in within.
func (p Ports) WeekdayRange(args []Argument) (bool, bool) {
	days, gmt := splitGMT(args)
	if len(days) < 1 || len(days) > 2 {
		return false, false
	}

	bounds := make([]int, 0, 2)
	for _, day := range days {
		if !day.IsText {
			return false, false
		}
		index := indexOf(weekdays, day.Text)
		if index < 0 {
			return false, false
		}
		bounds = append(bounds, index)
	}

	now, ok := p.at(gmt)
	if !ok {
		return false, false
	}
	today := int(now.Weekday())
	if len(bounds) == 1 {
		return today == bounds[0], true
	}
	return within(today, bounds[0], bounds[1]), true
}

// TimeRange reports whether the current time falls in the given range.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02. Four shapes carry
// worked examples: timeRange(12) is noon to 1pm, timeRange(9,17) is 9am to 5pm,
// timeRange(8,30,17,0) is 8:30 to 17:00, and timeRange(0,0,0,0,0,30) is midnight
// to thirty seconds past.
//
// THE ONE-ARGUMENT FORM IS AN HOUR, NOT AN INSTANT, and it is the only shape
// where a bound is invented rather than given: noon means noon until one. Any
// other argument count is reported as not understood rather than guessed at.
func (p Ports) TimeRange(args []Argument) (bool, bool) {
	values, gmt := splitGMT(args)
	for _, value := range values {
		if value.IsText {
			return false, false
		}
	}

	var lo, hi int
	switch len(values) {
	case 1:
		lo = seconds(values[0].Number, 0, 0)
		hi = seconds(values[0].Number+1, 0, 0) - 1
	case 2:
		lo = seconds(values[0].Number, 0, 0)
		hi = seconds(values[1].Number, 0, 0)
	case 4:
		lo = seconds(values[0].Number, values[1].Number, 0)
		hi = seconds(values[2].Number, values[3].Number, 0)
	case 6:
		lo = seconds(values[0].Number, values[1].Number, values[2].Number)
		hi = seconds(values[3].Number, values[4].Number, values[5].Number)
	default:
		return false, false
	}

	now, ok := p.at(gmt)
	if !ok {
		return false, false
	}
	return within(seconds(now.Hour(), now.Minute(), now.Second()), lo, hi), true
}

func seconds(hour, minute, second int) int { return hour*3600 + minute*60 + second }
