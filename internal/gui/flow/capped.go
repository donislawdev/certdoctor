package flow

// Capped is a stream the command line writes into that keeps at most a limit
// of what it was given and says whether there was more.
//
// A write is never refused. A writer that returned an error would stop the
// copy from the child's pipe, and a child writing into a pipe nobody reads
// waits for ever - so the rest is taken and dropped, the child ends as it
// would have, and the window says the output was too long instead of hanging
// with it (rule 35: input from outside can be too big).
//
// One writer at a time: the process package copies each stream from one
// goroutine of its own and is done with it before Wait returns, which is when
// Bytes is read.
type Capped struct {
	limit int
	kept  []byte
	over  bool
}

// NewCapped is a stream that keeps at most limit bytes.
func NewCapped(limit int) *Capped { return &Capped{limit: limit} }

// Write keeps what fits and drops the rest.
func (c *Capped) Write(p []byte) (int, error) {
	room := c.limit - len(c.kept)
	if len(p) > room {
		c.kept = append(c.kept, p[:max(room, 0)]...)
		c.over = true
		return len(p), nil
	}
	c.kept = append(c.kept, p...)
	return len(p), nil
}

// Bytes is what was kept.
func (c *Capped) Bytes() []byte { return c.kept }

// Over says more was written than was kept.
func (c *Capped) Over() bool { return c.over }
