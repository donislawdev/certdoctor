package dns

// Nameservers is what an enumeration of this machine's resolvers produced.
//
// IT CARRIES TWO LISTS AND THAT IS THE FINDING OF PROBE S7, NOT A CONVENIENCE.
// On Windows the two ways of asking answer two different questions: the registry
// says what is WRITTEN DOWN anywhere - including inactive adapters and the IPv6
// branch - while GetNetworkParams says what the stack WILL ACTUALLY USE. Measured
// on the owner's machine 2026-08-05: the registry gave three addresses, the API
// gave two, and neither was wrong.
//
// The allowed set takes the wider list and the queries take the narrower one.
// That direction is the safe one: a resolver we ask must always have been
// derived from somewhere this machine records, and a resolver recorded but not
// used costs nothing but an entry in a set.
type Nameservers struct {
	// ToAsk are the resolvers to send queries to, in the order the machine lists
	// them. Order is configuration - a resolver library tries them in this order
	// - so it is preserved rather than sorted.
	ToAsk []string
	// Known is every resolver written down anywhere on this machine. It is a
	// superset of ToAsk and exists to seed the set of places this run may
	// connect to.
	Known []string
	// From names where the list came from, in words that go into the report.
	From string
}

// merged folds the two lists into Known without losing order or duplicating.
//
// ToAsk goes in first so that the resolvers actually in use keep the front of
// the list, which is what a reader scanning the allowed set would expect to see.
func merged(toAsk, known []string) []string {
	seen := make(map[string]bool, len(toAsk)+len(known))
	out := make([]string, 0, len(toAsk)+len(known))
	for _, list := range [][]string{toAsk, known} {
		for _, address := range list {
			if address == "" || seen[address] {
				continue
			}
			seen[address] = true
			out = append(out, address)
		}
	}
	return out
}
