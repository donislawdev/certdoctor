package planted

// A fixture with planted violations. Neither account name below is on the list
// of invented ones, which is what the guard has to notice.
//
// BOTH SPELLINGS OF THE WINDOWS SEPARATOR ARE HERE ON PURPOSE. The same path
// appears in Go source two ways - unescaped inside a raw string, and doubled
// inside an ordinary one - and a scanner that knew only one of them would report
// a clean tree while half of it went unread. That is not a hypothesis: a shell
// version of this scan, written while building the guard, missed the doubled
// form and called the repository clean.
const (
	raw    = `C:\Users\realperson\AppData\Roaming\npm\.npmrc`
	quoted = "C:\\Users\\otherperson\\AppData\\Roaming\\npm"
)
