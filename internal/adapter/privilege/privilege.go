// Package privilege answers one question about the process certdoctor runs as:
// whether it can see what an administrator sees.
//
// WHY THIS IS A REPORT FIELD RATHER THAN A DETAIL. certdoctor run as a user and
// run as an administrator sees different trust stores and different runtime
// installations, so two reports taken at different levels are DIFFERENT
// DOCUMENTS rather than one of them being worse. Without this field a
// comparison of host against container would report a difference where nothing
// changed but the privilege - a false finding delivered with confidence, which
// is the failure this whole tool exists to avoid producing.
//
// IDENTIFIERS, NEVER DISPLAY NAMES. The level comes from the process token on
// Windows and from the effective user id everywhere else. The obvious
// alternative - asking whether the account is in a group called
// "Administrators" - returns false on a system in another language, where the
// group is called something else. That mistake does not crash anything. It
// quietly produces a wrong answer, which is worse.
package privilege

import "github.com/donislawdev/certdoctor/internal/core/report"

// Level reports the privilege level of the current process.
//
// It never returns an empty value. A question that could not be answered comes
// back as unknown, which the report then has to announce.
func Level() report.PrivilegeLevel {
	return levelFrom(ask())
}

// levelFrom turns the platform's answer into a level.
//
// It is separate from asking for two reasons. The rule can then be tested on
// every platform, including the failure branch that no test could provoke for
// real. And the rule lives in one place: AN ERROR MEANS UNKNOWN, NEVER A GUESS.
//
// Answering "user" because the question failed would be a measurement nobody
// took, recorded in the one field whose entire purpose is to keep comparisons
// honest. It is the metadata version of a probe reporting PASS because it did
// not understand what it saw.
func levelFrom(elevated bool, err error) report.PrivilegeLevel {
	if err != nil {
		return report.PrivilegeUnknown
	}
	if elevated {
		return report.PrivilegeElevated
	}
	return report.PrivilegeUser
}
