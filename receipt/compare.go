package receipt

import (
	"fmt"
	"strings"
)

// ChangeKind describes how an element changed between two receipts.
type ChangeKind string

const (
	// ChangeAdded means the element only exists in the second receipt.
	ChangeAdded ChangeKind = "added"
	// ChangeRemoved means the element only exists in the first receipt.
	ChangeRemoved ChangeKind = "removed"
	// ChangeChanged means the element exists in both receipts but differs.
	ChangeChanged ChangeKind = "changed"
)

// Diff is the result of comparing two receipts.
type Diff struct {
	// Equal reports whether the two plans are identical. When true, all
	// other fields are empty.
	Equal bool
	// FingerprintA and FingerprintB are the compared plan fingerprints.
	FingerprintA string
	FingerprintB string
	// Includes lists include-graph differences.
	Includes []IncludeChange
	// Vars lists variable differences (including source changes).
	Vars []VarChange
	// Sources lists input source differences.
	Sources []SourceChange
	// Steps lists execution plan differences (added, removed or reordered
	// task invocations).
	Steps []StepChange
}

// IncludeChange describes a difference between two includes.
type IncludeChange struct {
	Kind ChangeKind
	A    *Include
	B    *Include
}

// VarChange describes a difference between two variables.
type VarChange struct {
	Kind ChangeKind
	Task string
	Name string
	A    *Var
	B    *Var
}

// SourceChange describes a difference between two source summaries.
type SourceChange struct {
	Kind ChangeKind
	Task string
	A    *Sources
	B    *Sources
}

// StepChange describes a difference in the execution order.
type StepChange struct {
	Kind   ChangeKind
	OrderA int
	OrderB int
	TaskA  string
	TaskB  string
}

// Compare compares two receipts. It only reads the receipts themselves:
// no tasks are executed and no remote includes are fetched. Both receipts
// must use a supported format and version, otherwise an
// [UnsupportedVersionError] is returned.
func Compare(a, b *Receipt) (*Diff, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("task: cannot compare a nil execution receipt")
	}
	if err := checkSupported(a); err != nil {
		return nil, err
	}
	if err := checkSupported(b); err != nil {
		return nil, err
	}

	d := &Diff{
		Equal:        a.Fingerprint == b.Fingerprint && a.Fingerprint != "",
		FingerprintA: a.Fingerprint,
		FingerprintB: b.Fingerprint,
	}

	d.Includes = diffIncludes(a.Includes, b.Includes)
	d.Vars = diffVars(a.Vars, b.Vars)
	d.Sources = diffSources(a.Sources, b.Sources)
	d.Steps = diffSteps(a.Plan, b.Plan)

	if !d.Equal && len(d.Includes) == 0 && len(d.Vars) == 0 &&
		len(d.Sources) == 0 && len(d.Steps) == 0 {
		// The fingerprints disagree but every element compared equal.
		// Keep Equal honest: this should not happen for well-formed
		// receipts, but never report a false negative.
		d.Equal = false
	}
	if len(d.Includes) != 0 || len(d.Vars) != 0 || len(d.Sources) != 0 || len(d.Steps) != 0 {
		d.Equal = false
	}
	return d, nil
}

func checkSupported(r *Receipt) error {
	if r.Format != FormatName {
		return &UnsupportedVersionError{Format: r.Format, Version: r.Version}
	}
	if r.Version != Version {
		return &UnsupportedVersionError{Format: r.Format, Version: r.Version}
	}
	return nil
}

func includeKey(i *Include) string {
	return strings.Join([]string{i.Parent, i.Target, i.Namespace}, "\x00")
}

func includeEqual(a, b *Include) bool {
	return a.Optional == b.Optional && a.Internal == b.Internal &&
		a.Flatten == b.Flatten && a.Source == b.Source &&
		equalSorted(a.Aliases, b.Aliases)
}

func diffIncludes(a, b []Include) []IncludeChange {
	var changes []IncludeChange
	am := make(map[string]*Include, len(a))
	bm := make(map[string]*Include, len(b))
	for i := range a {
		am[includeKey(&a[i])] = &a[i]
	}
	for i := range b {
		bm[includeKey(&b[i])] = &b[i]
	}
	for _, key := range sortedKeys(am, bm) {
		av, inA := am[key]
		bv, inB := bm[key]
		switch {
		case inA && inB:
			if !includeEqual(av, bv) {
				changes = append(changes, IncludeChange{Kind: ChangeChanged, A: av, B: bv})
			}
		case inA:
			changes = append(changes, IncludeChange{Kind: ChangeRemoved, A: av})
		default:
			changes = append(changes, IncludeChange{Kind: ChangeAdded, B: bv})
		}
	}
	return changes
}

func varKey(v *Var) string {
	return v.Task + "\x00" + v.Name
}

func varEqual(a, b *Var) bool {
	return a.Source == b.Source && a.Kind == b.Kind &&
		a.Secret == b.Secret && a.Digest == b.Digest
}

func diffVars(a, b []Var) []VarChange {
	var changes []VarChange
	am := make(map[string]*Var, len(a))
	bm := make(map[string]*Var, len(b))
	for i := range a {
		am[varKey(&a[i])] = &a[i]
	}
	for i := range b {
		bm[varKey(&b[i])] = &b[i]
	}
	for _, key := range sortedKeys(am, bm) {
		av, inA := am[key]
		bv, inB := bm[key]
		switch {
		case inA && inB:
			if !varEqual(av, bv) {
				changes = append(changes, VarChange{
					Kind: ChangeChanged, Task: bv.Task, Name: bv.Name, A: av, B: bv,
				})
			}
		case inA:
			changes = append(changes, VarChange{
				Kind: ChangeRemoved, Task: av.Task, Name: av.Name, A: av,
			})
		default:
			changes = append(changes, VarChange{
				Kind: ChangeAdded, Task: bv.Task, Name: bv.Name, B: bv,
			})
		}
	}
	return changes
}

func sourcesEqual(a, b *Sources) bool {
	return a.Method == b.Method && a.Digest == b.Digest &&
		equalSorted(a.Globs, b.Globs) && equalSorted(a.Files, b.Files)
}

func diffSources(a, b []Sources) []SourceChange {
	var changes []SourceChange
	am := make(map[string]*Sources, len(a))
	bm := make(map[string]*Sources, len(b))
	for i := range a {
		am[a[i].Task] = &a[i]
	}
	for i := range b {
		bm[b[i].Task] = &b[i]
	}
	for _, key := range sortedKeys(am, bm) {
		av, inA := am[key]
		bv, inB := bm[key]
		switch {
		case inA && inB:
			if !sourcesEqual(av, bv) {
				changes = append(changes, SourceChange{Kind: ChangeChanged, Task: key, A: av, B: bv})
			}
		case inA:
			changes = append(changes, SourceChange{Kind: ChangeRemoved, Task: key, A: av})
		default:
			changes = append(changes, SourceChange{Kind: ChangeAdded, Task: key, B: bv})
		}
	}
	return changes
}

// diffSteps computes an LCS-based diff over the task names in execution
// order, so added, removed and reordered invocations are all reported.
func diffSteps(a, b []Step) []StepChange {
	an := make([]string, len(a))
	bn := make([]string, len(b))
	for i := range a {
		an[i] = a[i].Task
	}
	for i := range b {
		bn[i] = b[i].Task
	}

	// LCS table.
	lcs := make([][]int, len(an)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(bn)+1)
	}
	for i := len(an) - 1; i >= 0; i-- {
		for j := len(bn) - 1; j >= 0; j-- {
			if an[i] == bn[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var changes []StepChange
	i, j := 0, 0
	for i < len(an) && j < len(bn) {
		if an[i] == bn[j] {
			// Same task at the same position: a different digest means
			// the task itself changed (commands, dependencies or
			// constraints).
			if a[i].Digest != b[j].Digest {
				changes = append(changes, StepChange{
					Kind:   ChangeChanged,
					OrderA: a[i].Order,
					OrderB: b[j].Order,
					TaskA:  an[i],
					TaskB:  bn[j],
				})
			}
			i++
			j++
			continue
		}
		if lcs[i+1][j] >= lcs[i][j+1] {
			changes = append(changes, StepChange{Kind: ChangeRemoved, OrderA: a[i].Order, TaskA: an[i]})
			i++
		} else {
			changes = append(changes, StepChange{Kind: ChangeAdded, OrderB: b[j].Order, TaskB: bn[j]})
			j++
		}
	}
	for ; i < len(an); i++ {
		changes = append(changes, StepChange{Kind: ChangeRemoved, OrderA: a[i].Order, TaskA: an[i]})
	}
	for ; j < len(bn); j++ {
		changes = append(changes, StepChange{Kind: ChangeAdded, OrderB: b[j].Order, TaskB: bn[j]})
	}
	return changes
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]string(nil), a...)
	cb := append([]string(nil), b...)
	sortStrings(ca)
	sortStrings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

// String renders a human-readable report of the diff.
func (d *Diff) String() string {
	if d.Equal {
		return fmt.Sprintf("Execution receipts match: plan fingerprint %s\n", d.FingerprintA)
	}

	var b strings.Builder
	b.WriteString("Execution receipts differ:\n")
	b.WriteString(fmt.Sprintf("  fingerprint a: %s\n", d.FingerprintA))
	b.WriteString(fmt.Sprintf("  fingerprint b: %s\n", d.FingerprintB))

	if len(d.Includes) != 0 {
		b.WriteString("\nIncludes:\n")
		for _, c := range d.Includes {
			switch c.Kind {
			case ChangeAdded:
				b.WriteString(fmt.Sprintf("  + include %q -> %s (from %s)\n", c.B.Namespace, c.B.Target, c.B.Parent))
			case ChangeRemoved:
				b.WriteString(fmt.Sprintf("  - include %q -> %s (from %s)\n", c.A.Namespace, c.A.Target, c.A.Parent))
			default:
				b.WriteString(fmt.Sprintf("  ~ include %q -> %s (from %s)\n", c.B.Namespace, c.B.Target, c.B.Parent))
			}
		}
	}

	if len(d.Vars) != 0 {
		b.WriteString("\nVariables:\n")
		for _, c := range d.Vars {
			scope := c.Name
			if c.Task != "" {
				scope = c.Task + " " + c.Name
			}
			switch c.Kind {
			case ChangeAdded:
				b.WriteString(fmt.Sprintf("  + var %s (source: %s)\n", scope, c.B.Source))
			case ChangeRemoved:
				b.WriteString(fmt.Sprintf("  - var %s (source: %s)\n", scope, c.A.Source))
			default:
				switch {
				case c.A.Source != c.B.Source:
					b.WriteString(fmt.Sprintf("  ~ var %s source: %s -> %s\n", scope, c.A.Source, c.B.Source))
				default:
					b.WriteString(fmt.Sprintf("  ~ var %s value changed (source: %s)\n", scope, c.B.Source))
				}
			}
		}
	}

	if len(d.Sources) != 0 {
		b.WriteString("\nSources:\n")
		for _, c := range d.Sources {
			switch c.Kind {
			case ChangeAdded:
				b.WriteString(fmt.Sprintf("  + sources of %q: %v\n", c.Task, c.B.Globs))
			case ChangeRemoved:
				b.WriteString(fmt.Sprintf("  - sources of %q: %v\n", c.Task, c.A.Globs))
			default:
				b.WriteString(fmt.Sprintf("  ~ sources of %q changed (digest: %s -> %s)\n", c.Task, c.A.Digest, c.B.Digest))
			}
		}
	}

	if len(d.Steps) != 0 {
		b.WriteString("\nExecution steps:\n")
		for _, c := range d.Steps {
			switch c.Kind {
			case ChangeAdded:
				b.WriteString(fmt.Sprintf("  + #%d %s\n", c.OrderB, c.TaskB))
			case ChangeRemoved:
				b.WriteString(fmt.Sprintf("  - #%d %s\n", c.OrderA, c.TaskA))
			default:
				b.WriteString(fmt.Sprintf("  ~ #%d %s changed (commands, dependencies or constraints differ)\n", c.OrderB, c.TaskB))
			}
		}
	}

	return b.String()
}
