package probe

import (
	"errors"
	"io"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// EndOf says how a store's bytes end, for the command that would append a
// certificate to that store - ADR114 B13.
//
// ONLY A LINE FEED ENDS A LINE HERE. encoding/pem looks for its markers after a
// "\n" and nothing else, and OpenSSL reads a PEM file line by line up to a
// "\n" - so a file ending in a lone "\r", a space or a stray byte leaves the
// next block on the line that is already there. An empty file has no line to
// continue.
func EndOf(data []byte) report.FileEnd {
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return report.FileEndMidLine
	}
	return report.FileEndLineBreak
}

// endCeiling is how much of one file ReadEndOf reads before it gives up on
// seeing the end - the bound the certificate directories are read within, and
// far past any bundle measured on this project.
const endCeiling = 64 << 20

// ReadEndOf reads the file at path and says how it ends, for a probe whose
// runtime read the file itself - python and node - so its bytes never reached
// this program.
//
// A FILE THAT CANNOT BE READ IS ONE WHOSE END WAS NOT SEEN, and gets no command
// - the runtime may have read it a moment ago, and this program still did not.
// The bytes stream through and only the last one is kept, so a large file costs
// time up to the ceiling and no memory.
func ReadEndOf(source func(string) (io.ReadCloser, error), path string) report.FileEnd {
	reader, err := source(path)
	if err != nil {
		return report.FileEndUnseen
	}
	defer func() { _ = reader.Close() }()
	var last lastByte
	read, err := io.CopyN(&last, reader, endCeiling+1)
	if err != nil && !errors.Is(err, io.EOF) || read > endCeiling {
		return report.FileEndUnseen
	}
	return EndOf(last.kept)
}

// lastByte is a writer that keeps the last byte written to it and nothing else.
type lastByte struct{ kept []byte }

func (l *lastByte) Write(p []byte) (int, error) {
	if len(p) > 0 {
		l.kept = append(l.kept[:0], p[len(p)-1])
	}
	return len(p), nil
}
