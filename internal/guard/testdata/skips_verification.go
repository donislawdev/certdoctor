// This file is a fixture with a planted violation. It is under testdata, so the
// module walk never reaches it and no guard is red because of it. It exists so
// the guard below can be seen to FAIL, which is the only way to know it can.
package planted

import "crypto/tls"

func config() *tls.Config {
	return &tls.Config{
		ServerName: "example.com",
		// The planted violation: a certificate check switched off somewhere that
		// is not the one file allowed to do it.
		InsecureSkipVerify: true,
	}
}

func alsoPlanted(c *tls.Config) {
	// The second shape, because an assignment is not a composite literal and a
	// guard reading only one of them would have a hole exactly here.
	c.InsecureSkipVerify = true
}
