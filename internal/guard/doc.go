// Package guard holds the structural guards: tests that check a property of the
// repository itself rather than behaviour of the program.
//
// Why they share one package. All three walk the same tree with the same parser,
// so a directory that has to be skipped is skipped once instead of in three
// places that drift apart. The loader is also the part most likely to be wrong
// in a way nobody notices - a guard that scanned nothing passes.
//
// Why this file exists. A directory holding only _test.go files is not a
// buildable package and "go build ./..." refuses it. The mutation registry
// builds the tree before running each named test, so an unbuildable package
// would report every mutation as BROKEN and the whole run would prove nothing.
// One package clause is the cheapest way to keep that path honest.
//
// What these guards deliberately do not see is listed next to each check.
package guard
