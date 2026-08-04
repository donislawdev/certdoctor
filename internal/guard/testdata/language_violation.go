package planted

// A fixture with planted violations. The word below is Polish and the rule is
// that everything in this repository is English.
//
// ONE WORD IN A COMMENT AND ONE IN A STRING LITERAL, on purpose. A scanner
// reading the syntax tree has thrown the comments away by the time it could look
// at them, and a comment is exactly where a slip like this survives longest -
// nobody runs a comment.
const proxyValue = "http://user:haslo@proxy:8080"

// The line above carries the literal. This one carries the comment: sciezka.
