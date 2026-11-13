package words

import (
	"fmt"
	"sort"
)

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
	"cert": {
		Title: "Certificate decoder",
		Summary: "Shows what a certificate or a chain says - names, dates, key and fingerprints - and whether the " +
			"chain is complete and in order. Nothing is checked against a trust store: Diagnose does that for a server.",
		Action: "Decode",
		Ready:  "Paste a certificate or a chain and press Decode. It is read here, on this machine, and sent nowhere.",
		Inputs: map[string]InputWords{
			"certificates": {
				Label: "Certificates",
				Hint: "PEM, as a .pem or .crt file has it - one certificate or a whole chain. Base64 of one " +
					"certificate, or an x5c array, works too. A private key pasted with it is not read.",
				Example: "-----BEGIN CERTIFICATE-----",
			},
		},
	},
	"noproxy": {
		Title: "NO_PROXY tester",
		Summary: "Shows which programs go to an address through the proxy and which go to it directly under a " +
			"NO_PROXY list. Each program reads the list its own way, so one list can send curl directly and " +
			"Node.js through the proxy on the same machine.",
		Action: "Test",
		Ready: "Paste a NO_PROXY list and an address and press Test. Nothing is connected to - the answer comes " +
			"from how each program reads the list.",
		Inputs: map[string]InputWords{
			"list": {
				Label: "NO_PROXY list",
				Hint: "The value of NO_PROXY exactly as it is set, entries separated by commas. NO_PROXY= in " +
					"front of it is taken off.",
				Example: "localhost,127.0.0.1,.corp.example",
			},
			"address": {
				Label:   "Address",
				Hint:    "A URL or a host name, with its port if it has one. Without a scheme it is read as https://.",
				Example: "https://api.corp.example:8443",
			},
		},
	},
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

// InputTooLong is what a tool's input box says under itself when it refused
// what was pasted or typed into it (ADR144): the most the box takes in KiB
// and - when the command line reads more - the command that reads it from a
// file. windowBytes and lineBytes are the two limits, fileSwitch the switch
// without its dashes.
func InputTooLong(windowBytes, lineBytes int, tool, fileSwitch string) string {
	if lineBytes <= windowBytes {
		return fmt.Sprintf(T(ToolInputFull), windowBytes>>10)
	}
	return fmt.Sprintf(T(ToolInputTooLong), windowBytes>>10, lineBytes>>10, tool, fileSwitch)
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
	"certificates": "Certificates",
	"proxy":        "Proxy",
	"tokens":       "Tokens",
}
