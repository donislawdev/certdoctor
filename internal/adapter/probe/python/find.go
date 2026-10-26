package python

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"path/filepath"
	"strings"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// interpreter is one Python this machine runs when a person types one of the
// commands, with the commands that reach it.
type interpreter struct {
	// path is what is started - the first spelling found.
	path string
	// selectedBy is PATH, then each command whose first hit on PATH leads here.
	selectedBy []string
	// asked says the interpreter was already asked, through an app execution
	// alias, and reply and why are what it said - so it is not asked twice.
	asked bool
	reply answer
	why   string
}

// commands are the four names a person types, as they sit on disk here. pip
// and pip3 lead to an interpreter as well, and one reached only through them -
// a pip on PATH whose Python is not - still gets its row - ADR112 part 1.
func commands(platform string) []string {
	if platform == "windows" {
		return []string{"python.exe", "python3.exe", "pip.exe", "pip3.exe"}
	}
	return []string{"python", "python3", "pip", "pip3"}
}

// interpreters walks PATH once and returns every interpreter the four commands
// lead to, each once, in the order PATH reaches them.
//
// ONE INTERPRETER IS ONE ROW, NOT ONE FILE - ADR112 part 1, decided by the owner.
// Measured with probe S28 on the owner's machine: six spellings on PATH lead to
// one interpreter through the Python install manager's aliases, and a pip on
// PATH can belong to another Python than the python beside it. So every hit is
// followed to the interpreter it starts, structurally and without running it.
//
// A COMMAND IS CREDITED ONLY TO WHAT IT RUNS: the first hit of each name on PATH.
// A later hit is shadowed - a person typing the command never reaches it - so its
// interpreter keeps the row and not the name. A first hit this cannot follow
// still takes the name, so no later hit claims it.
//
// A SHADOWED ALIAS OF A PACKAGE ALREADY STARTED IS NOT STARTED - OBS191, the
// cheaper variant the owner chose. Each alias is a process, and the probe has
// ten seconds: a hit nobody reaches by typing takes no name, so all it could add
// is a runtime only it leads to, and an alias of the same package has already
// said which runtime that package starts. The same rule skips an alias met a
// second time through a directory PATH lists twice.
func (m machine) interpreters(ctx context.Context, pathDirs []string) []interpreter {
	var found []interpreter
	at := map[string]int{}
	typed := map[string]bool{}
	asked := map[string]bool{}
	for _, hit := range probe.OnPathOrAliases(m.source, m.alias, pathDirs, commands(m.platform)...) {
		command := strings.TrimSuffix(hit.Name, ".exe")
		first := !typed[command]
		typed[command] = true
		pkg := strings.ToLower(hit.Package)
		if pkg != "" && !first && asked[pkg] {
			continue
		}
		in, key := m.follow(ctx, pathDirs, hit)
		asked[pkg] = asked[pkg] || in.asked
		if in.path == "" {
			continue
		}
		i, known := at[key]
		switch {
		case !known:
			i = len(found)
			at[key] = i
			in.selectedBy = []string{"PATH"}
			found = append(found, in)
		case in.asked && !found[i].asked:
			// Found before and not yet asked, and an alias leading to it just was.
			found[i].asked, found[i].reply, found[i].why = true, in.reply, in.why
		}
		if first {
			found[i].selectedBy = append(found[i].selectedBy, command)
		}
	}
	return found
}

// follow is the interpreter one hit leads to and the key it is told apart by, or
// an interpreter with no path when that cannot be learned.
func (m machine) follow(ctx context.Context, pathDirs []string, hit probe.Hit) (interpreter, string) {
	if hit.Package != "" {
		return m.appAlias(ctx, hit)
	}
	target := leadsTo(m.source, pathDirs, m.platform, hit)
	if target == "" {
		return interpreter{}, ""
	}
	return interpreter{path: target}, identity(m.source, m.resolve, target)
}

// storeStandIn is the package behind the python and python3 a Windows with no
// Python has: App Installer's PythonRedirector - the manifest of App Installer
// 1.29.380.0, read on the owner's machine 2026-10-21, declares both aliases for
// it, and lets an installed Python take them over.
const storeStandIn = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"

// appAlias is the interpreter an app execution alias starts - ADR112, decided by
// the owner 2026-10-21.
//
// WHAT AN ALIAS STARTS CANNOT BE READ OFF THE DISK, so the interpreter is asked
// and names itself in sys.executable. The alias names a file inside the package
// behind it, and for the Python install manager that file is the manager's own
// launcher, which starts whichever runtime is its default - measured with probe
// S28 on the owner's machine: python.exe of PythonManager 26.4 named its own
// python.exe, and started pythoncore-3.15-64. An alias that gives no answer, or
// no absolute path, is told apart by its package, so the aliases of one package
// that says nothing are one row and not one per name.
//
// THE STORE'S STAND-IN IS NOT STARTED: on every run it would give a row for a
// Python that is not there, and what it does with arguments is known only from
// forums - ADR112. Nor is an alias of pip, which starts pip and would hand the
// script's arguments to pip's code - ADR112 part 6. Both still take the name,
// because a person typing it reaches them and nothing later on PATH. Python from
// the Microsoft Store was not measured.
func (m machine) appAlias(ctx context.Context, hit probe.Hit) (interpreter, string) {
	if strings.EqualFold(hit.Package, storeStandIn) || !strings.HasPrefix(hit.Name, "python") {
		return interpreter{}, ""
	}
	a, why := ask(ctx, m.run, hit.Path)
	in := interpreter{path: hit.Path, asked: true, reply: a, why: why}
	if why != "" || !filepath.IsAbs(a.Executable) {
		return in, "\x00" + strings.ToLower(hit.Package)
	}
	in.path = a.Executable
	return in, identity(m.source, m.resolve, a.Executable)
}

// leadsTo is the interpreter one hit starts, or the empty string when that
// cannot be read off the disk.
//
// THE PYTHON INSTALL MANAGER'S ALIASES COME FIRST, on Windows, whatever their
// name: each one is the same small launcher, and the interpreter it starts is
// written beside it in <name>.__target__ - measured with probe S28 on the
// owner's machine, Python install manager 26.4, where python.exe, pip.exe and
// their kin in %LOCALAPPDATA%\Python\bin all named pythoncore-3.15-64.
func leadsTo(source file.Source, pathDirs []string, platform string, hit probe.Hit) string {
	var target string
	if platform == "windows" {
		target = aliasTarget(source, hit.Path)
	}
	switch {
	case target != "":
	case strings.HasPrefix(hit.Name, "python"):
		target = hit.Path
	case platform == "windows":
		target = launcherTarget(source, hit.Path)
	default:
		target = scriptTarget(source, pathDirs, hit.Path)
	}
	// AN INTERPRETER IS STARTED BY ITS ABSOLUTE PATH OR NOT AT ALL - ADR49. A
	// relative entry on PATH, or a script naming a relative interpreter, names a
	// file that depends on where somebody stands.
	if !filepath.IsAbs(target) || !probe.Readable(source, target) {
		return ""
	}
	return target
}

// aliasTarget reads <path>.__target__, or returns the empty string.
func aliasTarget(source file.Source, path string) string {
	data, err := head(source, path+".__target__", 4096)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// identity is what two interpreters are told apart by: the file each one really
// is, and the virtual environment it starts in.
//
// A VIRTUAL ENVIRONMENT IS A LINK TO THE PYTHON IT WAS MADE FROM, and a different
// environment all the same - its own site-packages, its own pip. CPython knows
// one by a pyvenv.cfg in the parent of the directory it was started from, or else
// in that directory, and it looks before following any link - Modules/getpath.py
// of CPython 3.15, read 2026-10-21 at
// https://github.com/python/cpython/blob/3.15/Modules/getpath.py - so the same
// is asked here, of the path as PATH spelled it.
func identity(source file.Source, resolve file.Resolve, path string) string {
	return probe.IdentityKey(resolve, path) + "\x00" + environmentOf(source, path)
}

// environmentOf is the directory holding the pyvenv.cfg this interpreter would
// find, folded the way PathKey folds it, or the empty string.
func environmentOf(source file.Source, path string) string {
	dir := filepath.Dir(path)
	for _, candidate := range []string{filepath.Dir(dir), dir} {
		if reader, err := source(filepath.Join(candidate, "pyvenv.cfg")); err == nil {
			_ = reader.Close()
			return probe.PathKey(candidate)
		}
	}
	return ""
}

// scriptTarget is the interpreter the first line of a pip script names.
//
// THREE SHAPES, each measured or read rather than guessed. "#!/usr/bin/python3"
// and Fedora's "#! /usr/bin/python3 -P", measured with probe S28 - the first word
// is the interpreter and the rest are its options. "#!/usr/bin/env python3" asks
// PATH, so PATH is asked here the same way. And a path too long for a kernel, or
// holding a space, is written by the installer as "#!/bin/sh" with an exec of
// the interpreter on the next line, in double quotes when it holds a space -
// _build_shebang in distlib/scripts.py of distlib 0.4.2, the copy pip vendors,
// read 2026-10-21 on the owner's machine in pip/_vendor/distlib of Python 3.13.
func scriptTarget(source file.Source, pathDirs []string, path string) string {
	data, err := head(source, path, 4096)
	if err != nil {
		return ""
	}
	lines := bufio.NewScanner(bytes.NewReader(data))
	if !lines.Scan() {
		return ""
	}
	first, ok := strings.CutPrefix(lines.Text(), "#!")
	if !ok {
		return ""
	}
	command := firstWord(strings.TrimSpace(first))
	switch {
	case command == "/bin/sh" && lines.Scan():
		exec, found := strings.CutPrefix(lines.Text(), "'''exec' ")
		if !found {
			return ""
		}
		return firstWord(exec)
	case filepath.Base(command) == "env":
		name := firstWord(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(first), command)))
		if hits := probe.OnPath(source, pathDirs, name); name != "" && len(hits) > 0 {
			return hits[0].Path
		}
		return ""
	}
	return command
}

// launcherTarget is the interpreter a pip.exe written by pip's installer starts.
//
// THE LAUNCHER CARRIES ITS SCRIPT AS A ZIP ARCHIVE APPENDED TO ITSELF, and the
// line starting the interpreter sits right before that archive - measured with
// probe S28 and again 2026-10-21 on the four pip.exe on the owner's machine, for
// Python 3.10, 3.12, 3.13 and 3.15: "#!C:\Python313\python.exe" and, for a path
// with a space, the path in double quotes. The launcher's own code holds "#!" as
// well, so the line is looked for before the archive and nowhere else. Where the
// archive starts is in its end record - the offset and the size of the central
// directory, APPNOTE.TXT 4.3.16 of the ZIP specification, read 2026-10-21 at
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
func launcherTarget(source file.Source, path string) string {
	data, err := head(source, path, launcherLimit)
	if err != nil {
		return ""
	}
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if end < 0 || end+20 > len(data) {
		return ""
	}
	size := int64(binary.LittleEndian.Uint32(data[end+12:]))
	offset := int64(binary.LittleEndian.Uint32(data[end+16:]))
	// Both counts are unsigned, so the archive can only start too early.
	archive := int64(end) - size - offset
	if archive < 0 {
		return ""
	}
	line := bytes.LastIndex(data[:archive], []byte("#!"))
	if line < 0 {
		return ""
	}
	command, _, _ := strings.Cut(string(data[line+2:archive]), "\n")
	return firstWord(strings.TrimSpace(strings.TrimSuffix(command, "\r")))
}

// launcherLimit bounds what is read of a launcher. pip's are about 108 kB -
// measured on the four above - so a file past this is not one.
const launcherLimit = 4 << 20

// firstWord is a command's first word: what a pair of double quotes holds, or
// everything up to the first space or tab.
func firstWord(s string) string {
	if rest, quoted := strings.CutPrefix(s, `"`); quoted {
		word, _, _ := strings.Cut(rest, `"`)
		return word
	}
	word, _, _ := strings.Cut(s, " ")
	word, _, _ = strings.Cut(word, "\t")
	return word
}

// head reads at most limit bytes of a file through the guarded port.
func head(source file.Source, path string, limit int64) ([]byte, error) {
	reader, err := source(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(io.LimitReader(reader, limit))
}
