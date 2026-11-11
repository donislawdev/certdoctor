package guard

import (
	"go/ast"
	"go/token"
	"testing"
)

// The three measures the ratchet in size_test.go added on 2026-11-11 (ADR132),
// beside length. Each is asked in BOTH directions by a probe below, and that is
// not decoration: "an else-if chain is one level" is satisfied perfectly by a
// measure that returns zero for everything, and a ceiling standing on a measure
// stuck at zero passes for ever while the code nests deeper underneath it. So
// every claim about what does NOT count is paired with a claim about what does.
//
// THE PROBES GO THROUGH measureSource, the path the tree is measured by, rather
// than calling the measures directly. A probe calling its own path would prove
// that the measure works and not that the ratchet uses it.

// depthOf reports how many blocks deep the deepest statement of a body sits.
//
// THE UNIT IS WHAT A PERSON SEES INDENTED. The body itself is level zero, and
// the body of every if, else, for, range, switch, type switch, select and
// function literal is one level deeper than the statement that opens it. Two
// shapes are deliberately NOT a level of their own:
//
//	an else-if, which reads and is drawn as one chain with the if before it -
//	counting it would push toward a switch that says less
//	a case, which gofmt draws at the indent of its switch, so the switch is the
//	level and its cases sit inside it
//
// A function literal in the header of a statement - a closure in a condition,
// a range over a call - opens its level from where it stands, so a body cannot
// hide from the count by being written there.
func depthOf(body *ast.BlockStmt) int {
	type entered struct {
		node  ast.Node
		level int
	}
	deepest := 0
	var path []entered
	ast.Inspect(body, func(n ast.Node) bool {
		// ast.Inspect calls back with nil once a node's children are done, which
		// is what keeps this path the chain of nodes above the current one.
		if n == nil {
			path = path[:len(path)-1]
			return true
		}
		level := 0
		if len(path) > 0 {
			parent := path[len(path)-1]
			level = parent.level + opens(parent.node, n)
		}
		deepest = max(deepest, level)
		path = append(path, entered{node: n, level: level})
		return true
	})
	return deepest
}

// opens is 1 when child is a block its parent draws one level deeper, and 0
// otherwise.
func opens(parent, child ast.Node) int {
	var body ast.Node
	switch p := parent.(type) {
	case *ast.IfStmt:
		if p.Else != nil && child == p.Else {
			if _, chain := p.Else.(*ast.IfStmt); chain {
				return 0
			}
			return 1
		}
		body = p.Body
	case *ast.ForStmt:
		body = p.Body
	case *ast.RangeStmt:
		body = p.Body
	case *ast.SwitchStmt:
		body = p.Body
	case *ast.TypeSwitchStmt:
		body = p.Body
	case *ast.SelectStmt:
		body = p.Body
	case *ast.FuncLit:
		body = p.Body // a closure is read indented, so it opens a level like a loop
	default:
		return 0
	}
	if child == body {
		return 1
	}
	return 0
}

// branchesOf counts the decision points of a body: one for the way straight
// through, and one more for every if, for, range, case with a condition, select
// case with a communication, && and ||.
//
// A DEFAULT IS NOT A DECISION, and neither is an else. Each is the way through
// when nothing before it matched, which the one counted for the straight way
// already is - counting them would make a switch that names its fallback look
// more tangled than one that leaves it out.
//
// A function literal's branches count toward the function it is written in,
// because a person reads them as part of it.
func branchesOf(body *ast.BlockStmt) int {
	count := 1
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			count++
		case *ast.CaseClause:
			if node.List != nil {
				count++
			}
		case *ast.CommClause:
			if node.Comm != nil {
				count++
			}
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				count++
			}
		}
		return true
	})
	return count
}

// argumentsOf counts what a caller lines up: every parameter named or unnamed,
// and a variadic tail as one. The receiver is not counted - it is written
// before the dot, not lined up in the parentheses - and neither are type
// parameters, which a caller almost never writes.
func argumentsOf(signature *ast.FuncType) int {
	if signature.Params == nil {
		return 0
	}
	count := 0
	for _, field := range signature.Params.List {
		count += max(1, len(field.Names))
	}
	return count
}

// measureOne measures the single function of a probe source the way the tree is
// measured.
func measureOne(t *testing.T, source string) sizedFunction {
	t.Helper()
	functions, _, err := measureSource("probe.go", []byte(source), false)
	if err != nil {
		t.Fatalf("the probe source did not measure: %v", err)
	}
	if len(functions) != 1 {
		t.Fatalf("the probe source holds %d functions, want 1", len(functions))
	}
	return functions[0]
}

// shapeCase is one probe source, the number it must measure, and why.
type shapeCase struct {
	what  string
	want  int
	claim string
	src   string
}

// TestTheDepthMeasureCountsWhatAPersonSeesIndented is the probe for depthOf.
func TestTheDepthMeasureCountsWhatAPersonSeesIndented(t *testing.T) {
	for _, c := range []shapeCase{
		{"a body with no blocks", 0, "a function nobody indented is zero deep",
			"package p\nfunc f() {\n\ta := 1\n\t_ = a\n}\n"},
		{"an else-if chain of four branches", 1, "a chain is drawn at one indent, so it counts once",
			"package p\nfunc f(x int) int {\n\tif x == 1 {\n\t\treturn 1\n\t} else if x == 2 {\n\t\treturn 2\n" +
				"\t} else if x == 3 {\n\t\treturn 3\n\t} else {\n\t\treturn 4\n\t}\n}\n"},
		{"two loops side by side", 1, "siblings are not nested, however many there are",
			"package p\nfunc f(xs, ys []int) {\n\tfor range xs {\n\t}\n\tfor range ys {\n\t}\n}\n"},
		{"a switch with several cases", 1, "the cases of one switch sit at one indent",
			"package p\nfunc f(x int) int {\n\tswitch x {\n\tcase 1:\n\t\treturn 1\n\tcase 2:\n\t\treturn 2\n" +
				"\tdefault:\n\t\treturn 3\n\t}\n}\n"},
		{"four blocks genuinely inside one another", 4,
			"THE OTHER HALF - without it, a measure stuck at zero would pass every case above",
			"package p\nfunc f(xs [][]int, ok bool) {\n\tfor _, row := range xs {\n\t\tfor _, n := range row {\n" +
				"\t\t\tif n > 0 {\n\t\t\t\tswitch {\n\t\t\t\tcase ok:\n\t\t\t\t\t_ = n\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n"},
		{"a loop inside the last branch of a chain", 2,
			"a chain is not a level, but what its branches hold still is",
			"package p\nfunc f(a, b bool) {\n\tif a {\n\t} else if b {\n\t\tfor {\n\t\t}\n\t}\n}\n"},
		{"a function literal inside a loop", 2, "a closure is a block a person reads indented",
			"package p\nfunc f(xs []int) {\n\tfor range xs {\n\t\tfunc() {\n\t\t\t_ = 1\n\t\t}()\n\t}\n}\n"},
		{"a closure written in an if's condition", 2,
			"a body cannot hide from the count by standing in a header",
			"package p\nfunc f(x bool) {\n\tif ok := func() bool {\n\t\tif x {\n\t\t\treturn true\n\t\t}\n" +
				"\t\treturn false\n\t}(); ok {\n\t}\n}\n"},
	} {
		if got := measureOne(t, c.src).depth; got != c.want {
			t.Errorf("%s measured %d and %d was expected.\n  %s\n"+
				"The depth ceiling is only worth what this measure is worth.", c.what, got, c.want, c.claim)
		}
	}
}

// TestTheBranchMeasureCountsEveryWayThrough is the probe for branchesOf.
func TestTheBranchMeasureCountsEveryWayThrough(t *testing.T) {
	for _, c := range []shapeCase{
		{"a body with no branch", 1, "one way through, and it is counted",
			"package p\nfunc f() {\n\t_ = 1\n}\n"},
		{"an if with an else", 2, "the else is the way through when the if did not match",
			"package p\nfunc f(x bool) int {\n\tif x {\n\t\treturn 1\n\t} else {\n\t\treturn 2\n\t}\n}\n"},
		{"one condition joined three ways", 4, "each && and || is a decision of its own",
			"package p\nfunc f(a, b, c bool) {\n\tif a && b || c {\n\t}\n}\n"},
		{"a switch of three cases and a default", 4, "every case with a condition counts, the default does not",
			"package p\nfunc f(x int) int {\n\tswitch x {\n\tcase 1:\n\t\treturn 1\n\tcase 2:\n\t\treturn 2\n" +
				"\tcase 3:\n\t\treturn 3\n\tdefault:\n\t\treturn 0\n\t}\n}\n"},
		{"a select of two receives and a default", 3, "a select case counts when it waits on something",
			"package p\nfunc f(a, b chan int) {\n\tselect {\n\tcase <-a:\n\tcase <-b:\n\tdefault:\n\t}\n}\n"},
		{"a for and a range", 3, "a loop is a decision about going round again",
			"package p\nfunc f(xs []int) {\n\tfor i := 0; i < 1; i++ {\n\t}\n\tfor range xs {\n\t}\n}\n"},
		{"an if inside a closure", 2, "a closure's branches are read as part of the function",
			"package p\nfunc f(x bool) {\n\t_ = func() {\n\t\tif x {\n\t\t}\n\t}\n}\n"},
	} {
		if got := measureOne(t, c.src).branches; got != c.want {
			t.Errorf("%s measured %d and %d was expected.\n  %s", c.what, got, c.want, c.claim)
		}
	}
}

// TestTheArgumentMeasureCountsWhatACallerLinesUp is the probe for argumentsOf.
func TestTheArgumentMeasureCountsWhatACallerLinesUp(t *testing.T) {
	for _, c := range []shapeCase{
		{"no parameters", 0, "nothing to line up",
			"package p\nfunc f() {}\n"},
		{"three named in two groups", 3, "a shared type does not make two names one argument",
			"package p\nfunc f(a, b int, c string) {}\n"},
		{"two unnamed", 2, "an unnamed parameter is still lined up",
			"package p\nfunc f(int, string) {}\n"},
		{"a variadic tail", 2, "the tail is one place in the call, however much it holds",
			"package p\nfunc f(format string, rest ...any) {}\n"},
		{"a method with one parameter", 1, "the receiver stands before the dot",
			"package p\ntype r struct{}\nfunc (x *r) f(a int) {}\n"},
		{"a generic function with one parameter", 1, "a type parameter is not lined up by the caller",
			"package p\nfunc f[T any, U any](a T) {}\n"},
	} {
		if got := measureOne(t, c.src).arguments; got != c.want {
			t.Errorf("%s measured %d and %d was expected.\n  %s", c.what, got, c.want, c.claim)
		}
	}
}
