package pac

import "time"

// DateRange reports whether today falls in the given range of dates.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02, which lists seven
// shapes and gives each a worked example: dateRange(1) is the first of every
// month, dateRange(1,15) the first half, dateRange(24,"DEC") one day a year,
// dateRange("JAN","MAR") a quarter, dateRange(1,"JUN",15,"AUG") a summer,
// dateRange("OCT",1995,"MAR",1996) a span of months, dateRange(1995,1997) three
// whole years, and dateRange(1,"JUN",1995,15,"AUG",1995) one exact span.
//
// A BARE NUMBER IS A DAY WHEN IT IS 31 OR LESS AND A YEAR OTHERWISE, and that
// is the specification's own rule, not a heuristic of ours. dateRange(1) means
// the first of the month while dateRange(1995) means a year, and nothing in the
// call distinguishes them but the magnitude. It is also why years must be given
// in full: dateRange(95) would ask about the 95th day of a month, which never
// arrives, and the documentation says "e.g. 2016, not 16" for that reason.
//
// It returns (result, understood), so a shape this program cannot read is
// reported rather than silently answered false.
func (p Ports) DateRange(args []Argument) (bool, bool) {
	values, gmt := splitGMT(args)
	now, ok := p.at(gmt)
	if !ok {
		return false, false
	}

	switch len(values) {
	case 1:
		return p.dateRangeOne(values[0], now)
	case 2:
		return p.dateRangeTwo(values, now)
	case 4:
		return p.dateRangeFour(values, now)
	case 6:
		return p.dateRangeSix(values, now)
	default:
		return false, false
	}
}

// isDay reports whether a bare number is a day rather than a year.
func isDay(n int) bool { return n >= 1 && n <= 31 }

// monthOf turns a month spelling into 1-12, or reports that it is not one.
func monthOf(a Argument) (int, bool) {
	if !a.IsText {
		return 0, false
	}
	index := indexOf(months, a.Text)
	if index < 0 {
		return 0, false
	}
	return index + 1, true
}

// dateRangeOne handles a single day, month or year.
func (p Ports) dateRangeOne(only Argument, now time.Time) (bool, bool) {
	if month, ok := monthOf(only); ok {
		return int(now.Month()) == month, true
	}
	if only.IsText {
		return false, false
	}
	if isDay(only.Number) {
		return now.Day() == only.Number, true
	}
	return now.Year() == only.Number, true
}

// dateRangeTwo handles a pair of days, a pair of months or a pair of years.
func (p Ports) dateRangeTwo(values []Argument, now time.Time) (bool, bool) {
	first, firstIsMonth := monthOf(values[0])
	second, secondIsMonth := monthOf(values[1])
	if firstIsMonth && secondIsMonth {
		return within(int(now.Month()), first, second), true
	}
	if values[0].IsText || values[1].IsText {
		return false, false
	}

	// Both bare numbers. They must agree about what they are, because a range
	// running from a day to a year is not a shape the specification has.
	lo, hi := values[0].Number, values[1].Number
	if isDay(lo) != isDay(hi) {
		return false, false
	}
	if isDay(lo) {
		return within(now.Day(), lo, hi), true
	}
	return within(now.Year(), lo, hi), true
}

// dateRangeFour handles (day, month, day, month) and (month, year, month, year).
//
// The two are told apart by the type of the FIRST argument, which is the only
// thing that separates them: one starts with a number, the other with a month.
func (p Ports) dateRangeFour(values []Argument, now time.Time) (bool, bool) {
	if month1, ok := monthOf(values[0]); ok {
		month2, ok2 := monthOf(values[2])
		if !ok2 || values[1].IsText || values[3].IsText {
			return false, false
		}
		// Ordered as year then month, so a later year always outranks a later
		// month within it.
		return within(now.Year()*100+int(now.Month()),
			values[1].Number*100+month1,
			values[3].Number*100+month2), true
	}

	month1, ok1 := monthOf(values[1])
	month2, ok2 := monthOf(values[3])
	if !ok1 || !ok2 || values[0].IsText || values[2].IsText {
		return false, false
	}
	// No year in this shape: the span repeats every year, so the comparison
	// runs on month and day alone.
	return within(int(now.Month())*100+now.Day(),
		month1*100+values[0].Number,
		month2*100+values[2].Number), true
}

// dateRangeSix handles (day, month, year, day, month, year).
func (p Ports) dateRangeSix(values []Argument, now time.Time) (bool, bool) {
	month1, ok1 := monthOf(values[1])
	month2, ok2 := monthOf(values[4])
	if !ok1 || !ok2 {
		return false, false
	}
	for _, index := range []int{0, 2, 3, 5} {
		if values[index].IsText {
			return false, false
		}
	}
	return within(stamp(now.Year(), int(now.Month()), now.Day()),
		stamp(values[2].Number, month1, values[0].Number),
		stamp(values[5].Number, month2, values[3].Number)), true
}

func stamp(year, month, day int) int { return year*10000 + month*100 + day }
