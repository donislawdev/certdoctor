package cert

// A certificate request, for the refusal that sends one to the CSR decoder, written by internal_tools/zadania-testowe (ADR154).
// They are text because the tools' tests may not read a file or make a key.

const (
	// fixtureRequest is a request signed by a P-256 key.
	fixtureRequest = `-----BEGIN CERTIFICATE REQUEST-----
MIIBRzCB7QIBADAtMRAwDgYDVQQKEwdFeGFtcGxlMRkwFwYDVQQDExB3d3cuZXhh
bXBsZS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVOIHxgPbll8Y+7MN
BLUARok+1MQ4ws3y3qgL/5VPMOERIwbTyTbANW97S4V3nTuXYf3yNFMimNpnRBzZ
fbi0p6BeMFwGCSqGSIb3DQEJDjFPME0wKQYDVR0RBCIwIIIQd3d3LmV4YW1wbGUu
dGVzdIIMZXhhbXBsZS50ZXN0MAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF
BQcDATAKBggqhkjOPQQDAgNJADBGAiEAqHzSKy8tZGUsw3Y0SXGDRABzVztagQt+
mxbrPilivBgCIQDxqQ+ew9aO0YB3jdKMCW2ADe9r6V3RAQjQ8yF8UK87cw==
-----END CERTIFICATE REQUEST-----
`
)
