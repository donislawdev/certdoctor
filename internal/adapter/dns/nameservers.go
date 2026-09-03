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
	// BeyondLimit counts nameserver lines this machine records that this run
	// will not ask because the platform's own resolver would not ask them
	// either, and Repeated counts the ones naming an address already on the
	// list. Both are zero on Windows, where no such limit exists.
	//
	// THEY TRAVEL SO THAT THE TRIMMING IS NOT SILENT. A list quietly cut to
	// three reads exactly like a machine that has three, which is the shape
	// inviolable rule 1 exists to forbid - a run that did less than it looked
	// like it did. They are two numbers rather than one because they answer two
	// different questions for whoever is looking at their resolv.conf.
	BeyondLimit int
	Repeated    int
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
