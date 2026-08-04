package planted

// A planted violation: a package that has no business opening a connection
// declares an import that can.
import "net"

var _ = net.Dial
