package jsontext

import (
	"strings"
)

// Indent writes v as JSON with two spaces per level, members in the order they
// were read and duplicates kept, so a person sees what the issuer wrote.
func (v Value) Indent() string {
	var b strings.Builder
	write(&b, v, "\n", "  ")
	return b.String()
}

// Compact writes v as JSON on one line, members in the order they were read.
// With duplicates in it, it carries them too - a caller that hands it on as a
// document checks first.
func (v Value) Compact() string {
	var b strings.Builder
	write(&b, v, "", "")
	return b.String()
}

// write writes v, each new line starting with newline and growing by step.
func write(b *strings.Builder, v Value, newline, step string) {
	switch v.Kind {
	case Object:
		writeMembers(b, v.Members, newline, step)
	case Array:
		writeItems(b, v.Items, newline, step)
	case String:
		quote(b, v.Text)
	case Null:
		b.WriteString("null")
	default:
		b.WriteString(v.Text)
	}
}

func writeMembers(b *strings.Builder, members []Member, newline, step string) {
	if len(members) == 0 {
		b.WriteString("{}")
		return
	}
	inner := newline + step
	b.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(inner)
		quote(b, m.Name)
		b.WriteByte(':')
		if step != "" {
			b.WriteByte(' ')
		}
		write(b, m.Value, inner, step)
	}
	b.WriteString(newline)
	b.WriteByte('}')
}

func writeItems(b *strings.Builder, items []Value, newline, step string) {
	if len(items) == 0 {
		b.WriteString("[]")
		return
	}
	inner := newline + step
	b.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(inner)
		write(b, item, inner, step)
	}
	b.WriteString(newline)
	b.WriteByte(']')
}

// quote writes s as a JSON string. Every control character comes out escaped,
// so a value that holds one cannot move a terminal's cursor from inside the
// text a person reads, and U+2028 and U+2029 are escaped too, because a
// JavaScript reader takes them for line ends. Nothing else is: <, > and & stay
// themselves, because this is read by people, not pasted into HTML.
func quote(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029:
			b.WriteString(`\u`)
			for shift := 12; shift >= 0; shift -= 4 {
				b.WriteByte(hex[(r>>shift)&0xf])
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
