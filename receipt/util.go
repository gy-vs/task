package receipt

import (
	"maps"
	"slices"
	"sort"
)

// sortedKeys returns the sorted union of keys from the given maps.
func sortedKeys[V any](ms ...map[string]V) []string {
	set := make(map[string]struct{})
	for _, m := range ms {
		for k := range m {
			set[k] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// sortStrings sorts s in place.
func sortStrings(s []string) {
	sort.Strings(s)
}
