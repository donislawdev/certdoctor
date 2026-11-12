package words

import "sort"

// ToolWords is what the window calls a tool and the parts of its page. The
// tools are the contract's list (internal/tool/spec), by id - the window has
// its own words for them, as it has for a kind of finding, and a test in the
// screens holds the two lists to each other in both directions.
type ToolWords struct {
	Title   string
	Summary string
	// Action is the one primary action of the tool's page.
	Action string
	// Ready is what the page says before the action was pressed.
	Ready string
	// Inputs are the words of each input, by its name.
	Inputs map[string]InputWords
}

// InputWords is what the window calls one input of a tool.
type InputWords struct {
	Label string
	Hint  string
	// Example stands in the empty box, greyed.
	Example string
}

var tools = map[string]ToolWords{
	"jwt": {
		Title: "JWT decoder",
		Summary: "Shows what a JSON Web Token says - its header, its claims and its times. The signature is not " +
			"checked: that needs the key of whoever issued it.",
		Action: "Decode",
		Ready:  "Paste a token and press Decode. It is read here, on this machine, and sent nowhere.",
		Inputs: map[string]InputWords{
			"token": {
				Label:   "Token",
				Hint:    "As it is sent - with or without Bearer in front, with or without quotes around it.",
				Example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
			},
		},
	},
}

// Tool is what the window calls the tool id, and whether it has words for it.
func Tool(id string) (ToolWords, bool) {
	w, ok := tools[id]
	return w, ok
}

// ToolIDs are the tools the window has words for, sorted.
func ToolIDs() []string {
	ids := make([]string, 0, len(tools))
	for id := range tools {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Category is the heading of a category of tools in the window's list. The
// categories are the contract's closed list; one the window cannot name is
// shown as the contract spells it.
func Category(c string) string {
	if s, ok := categories[c]; ok {
		return s
	}
	return c
}

var categories = map[string]string{
	"tokens": "Tokens",
}
