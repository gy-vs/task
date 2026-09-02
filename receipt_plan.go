package task

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/go-task/task/v3/errors"
	"github.com/go-task/task/v3/internal/fingerprint"
	"github.com/go-task/task/v3/receipt"
	"github.com/go-task/task/v3/taskfile"
	"github.com/go-task/task/v3/taskfile/ast"
)

// cliVarNames are the synthetic variables Task itself derives from the
// command line. They are stored in the Taskfile vars layer, but receipt
// generation attributes them to the "cli" source.
var cliVarNames = []string{
	"CLI_ARGS",
	"CLI_ARGS_LIST",
	"CLI_FORCE",
	"CLI_SILENT",
	"CLI_VERBOSE",
	"CLI_OFFLINE",
	"CLI_ASSUME_YES",
}

// GenerateReceipt resolves the given entry tasks using the same parsing,
// variable precedence, include handling and dependency expansion logic as a
// normal run, but without executing any task command. Dynamic variables are
// evaluated exactly as they are during a run, platform conditions are
// evaluated against the current platform, aliases and wildcards are
// resolved, and dependency cycles are detected deterministically.
//
// The returned receipt is deterministic for a given commit and set of
// effective inputs: it contains no absolute paths, timestamps, raw
// environment values or raw variable values. Secret material is digested,
// not written.
func (e *Executor) GenerateReceipt(ctx context.Context, calls ...*Call) (*receipt.Receipt, error) {
	_ = ctx

	if len(calls) == 0 {
		calls = append(calls, &Call{Task: "default"})
	}

	// Mirror Run's entry validation, using the same resolution path.
	for _, call := range calls {
		t, err := e.GetTask(call)
		if err != nil {
			return nil, err
		}
		if t.Internal {
			return nil, &errors.TaskInternalError{TaskName: call.Task}
		}
	}

	p := &planner{
		e:          e,
		rootDir:    e.Dir,
		tasks:      make(map[string]*receipt.Task),
		sources:    make(map[string]*receipt.Sources),
		compiled:   make(map[string]*compiledInvocation),
		inProgress: make(map[string]bool),
	}

	// Capture Taskfile-level (global) variables once, using the same
	// compiler path as a normal run.
	p.recordGlobalVars()

	for _, call := range calls {
		p.entries = append(p.entries, call.Task)
		if err := p.visit(call, "entry"); err != nil {
			return nil, err
		}
	}

	r := &receipt.Receipt{
		Format:  receipt.FormatName,
		Version: receipt.Version,
		Entries: p.entries,
		Plan:    p.steps,
	}

	r.Includes = p.collectIncludes()

	for _, name := range sortedStringKeys(p.tasks) {
		r.Tasks = append(r.Tasks, *p.tasks[name])
	}

	// Variable records are appended while walking; dedupe by (task, name),
	// keeping the first observation from the deterministic walk, then sort.
	seenVars := make(map[string]bool)
	for _, v := range p.varRecords {
		key := v.Task + "\x00" + v.Name
		if seenVars[key] {
			continue
		}
		seenVars[key] = true
		r.Vars = append(r.Vars, v)
	}
	sort.Slice(r.Vars, func(i, j int) bool {
		if r.Vars[i].Task != r.Vars[j].Task {
			return r.Vars[i].Task < r.Vars[j].Task
		}
		return r.Vars[i].Name < r.Vars[j].Name
	})

	for _, name := range sortedStringKeys(p.sources) {
		r.Sources = append(r.Sources, *p.sources[name])
	}

	// Attach each task's structural digest to the steps that invoke it,
	// so command/constraint changes surface in step-level diffs.
	taskDigests := make(map[string]string, len(r.Tasks))
	for _, t := range r.Tasks {
		if b, err := json.Marshal(t); err == nil {
			taskDigests[t.Name] = receipt.Hash(string(b))
		}
	}
	for i := range r.Plan {
		if d, ok := taskDigests[r.Plan[i].Task]; ok {
			r.Plan[i].Digest = d
		}
	}

	r.Fingerprint = receipt.ComputeFingerprint(r)
	return r, nil
}

// compiledInvocation is a cached compilation of one task invocation.
type compiledInvocation struct {
	ct        *ast.Task
	tracker   map[string]varSource
	sensitive map[string]struct{}
}

type planner struct {
	e       *Executor
	rootDir string

	entries    []string
	steps      []receipt.Step
	tasks      map[string]*receipt.Task
	sources    map[string]*receipt.Sources
	varRecords []receipt.Var

	compiled   map[string]*compiledInvocation
	inProgress map[string]bool
}

// visit walks the plan for one task invocation, in declared dependency order
// and depth-first: dependencies first (as they happen before the task that
// requires them), then the task itself, then task calls made from its
// commands. This yields a deterministic sequence that matches the
// happens-before order of a real run.
func (p *planner) visit(call *Call, via string) error {
	orig, err := p.e.GetTask(call)
	if err != nil {
		return err
	}

	key := invocationKey(call)
	if p.inProgress[key] {
		// Dependency cycle: record it deterministically instead of
		// recursing forever (a real run would eventually fail with
		// TaskCalledTooManyTimesError).
		p.steps = append(p.steps, receipt.Step{
			Order: len(p.steps) + 1,
			Task:  orig.Task,
			Via:   via,
			Call:  callLabel(call, orig.Task),
			Cycle: true,
		})
		return nil
	}

	comp, err := p.compile(call)
	if err != nil {
		return err
	}
	ct := comp.ct

	if !shouldRunOnCurrentPlatform(ct.Platforms) {
		// A platform mismatch skips the task together with its dependencies,
		// matching RunTask.
		p.recordTask(ct, comp.sensitive)
		p.steps = append(p.steps, receipt.Step{
			Order:   len(p.steps) + 1,
			Task:    p.taskName(ct),
			Via:     via,
			Call:    callLabel(call, p.taskName(ct)),
			Skipped: "platform",
		})
		return nil
	}

	p.inProgress[key] = true
	defer delete(p.inProgress, key)

	// Dependencies run before the task itself, in declared order.
	for _, d := range ct.Deps {
		if err := p.visit(&Call{Task: d.Task, Vars: d.Vars, Indirect: true}, "dep"); err != nil {
			return err
		}
	}

	p.recordTask(ct, comp.sensitive)
	p.recordSources(ct)
	p.recordVars(p.taskName(ct), ct, comp.tracker)

	p.steps = append(p.steps, receipt.Step{
		Order:       len(p.steps) + 1,
		Task:        p.taskName(ct),
		Via:         via,
		Call:        callLabel(call, p.taskName(ct)),
		Conditional: strings.TrimSpace(ct.If) != "",
	})

	// Nested task calls made from commands run in command order, after the
	// task's dependencies. Deferred task calls are resolved lazily when the
	// task exits; their (unrendered) target is recorded on the task itself.
	for _, cmd := range ct.Cmds {
		if cmd == nil || cmd.Task == "" || cmd.Defer {
			continue
		}
		if !shouldRunOnCurrentPlatform(cmd.Platforms) {
			continue
		}
		if err := p.visit(&Call{Task: cmd.Task, Vars: cmd.Vars, Indirect: true}, "cmd"); err != nil {
			return err
		}
	}

	return nil
}

// compile compiles a task invocation through the executor's own compiler,
// capturing variable provenance while doing so. Results are cached per
// invocation so repeated references to the same task are stable and cheap.
func (p *planner) compile(call *Call) (*compiledInvocation, error) {
	key := invocationKey(call)
	if c, ok := p.compiled[key]; ok {
		return c, nil
	}

	tracker := make(map[string]varSource)
	p.e.Compiler.varSources = tracker
	ct, err := p.e.CompiledTask(call)
	p.e.Compiler.varSources = nil
	if err != nil {
		return nil, err
	}

	c := &compiledInvocation{
		ct:        ct,
		tracker:   tracker,
		sensitive: p.collectSensitive(ct, tracker),
	}
	p.compiled[key] = c
	return c, nil
}

// sensitiveSpecialVars are the special variables whose values contain
// absolute paths (or other machine-specific content). They are redacted from
// commands for both secrecy and cross-machine determinism. Other special
// variables, such as TASK or ALIAS, hold task names and must not be masked.
var sensitiveSpecialVars = map[string]bool{
	"TASK_EXE":         true,
	"ROOT_TASKFILE":    true,
	"ROOT_DIR":         true,
	"USER_WORKING_DIR": true,
	"TASK_DIR":         true,
	"TASKFILE":         true,
	"TASKFILE_DIR":     true,
}

// minSensitiveLength guards against masking very short values, which are
// unlikely to be secrets and would corrupt ordinary command text if
// replaced.
const minSensitiveLength = 4

// collectSensitive gathers values that must never appear raw in a receipt:
// secret variables, ambient environment values, path-bearing special
// variables, and everything coming from environment blocks (including
// dotenv files).
func (p *planner) collectSensitive(ct *ast.Task, tracker map[string]varSource) map[string]struct{} {
	sensitive := make(map[string]struct{})
	add := func(v any) {
		s := canonicalValue(v)
		if len(s) >= minSensitiveLength {
			sensitive[s] = struct{}{}
		}
	}
	for name, v := range ct.Vars.All() {
		src := tracker[name]
		switch {
		case v.Secret,
			src.Source == varSourceEnvironment,
			src.Source == varSourceTaskfileEnv,
			src.Source == varSourceSpecial && sensitiveSpecialVars[name]:
			add(v.Value)
		}
	}
	for _, v := range ct.Env.All() {
		add(v.Value)
	}
	return sensitive
}

// recordTask records the structural descriptor of a task, redacting all
// command text with the invocation's sensitive values.
func (p *planner) recordTask(ct *ast.Task, sensitive map[string]struct{}) {
	name := p.taskName(ct)
	if _, exists := p.tasks[name]; exists {
		return
	}

	rec := &receipt.Task{
		Name:           name,
		Aliases:        slices.Sorted(slices.Values(ct.Aliases)),
		Taskfile:       p.rel(ct.Location.Taskfile),
		Line:           ct.Location.Line,
		Dir:            p.rel(ct.Dir),
		Internal:       ct.Internal,
		Run:            cmpOr(ct.Run, p.e.Taskfile.Run, "always"),
		Method:         cmpOr(ct.Method, p.e.Taskfile.Method, "checksum"),
		Platforms:      platformIDs(ct.Platforms),
		RunsOnPlatform: shouldRunOnCurrentPlatform(ct.Platforms),
	}

	for _, d := range ct.Deps {
		if d != nil {
			rec.Deps = append(rec.Deps, d.Task)
		}
	}

	for _, cmd := range ct.Cmds {
		if cmd == nil {
			continue
		}
		platforms := platformIDs(cmd.Platforms)
		// Only report platform matching for commands that actually
		// constrain it, to avoid noise.
		runsOn := len(platforms) > 0 && shouldRunOnCurrentPlatform(cmd.Platforms)
		switch {
		case cmd.Task != "":
			rec.Cmds = append(rec.Cmds, receipt.Cmd{
				Kind:           "task",
				Task:           cmd.Task,
				Defer:          cmd.Defer,
				Conditional:    strings.TrimSpace(cmd.If) != "",
				Platforms:      platforms,
				RunsOnPlatform: runsOn,
			})
		case cmd.Cmd != "":
			rec.Cmds = append(rec.Cmds, receipt.Cmd{
				Kind:           "command",
				Command:        p.redact(cmd.Cmd, sensitive),
				Defer:          cmd.Defer,
				Conditional:    strings.TrimSpace(cmd.If) != "",
				Platforms:      platforms,
				RunsOnPlatform: runsOn,
			})
		}
	}

	p.tasks[name] = rec
}

// recordSources summarizes a task's resolved input sources using the same
// glob expansion used for fingerprinting and "for" loops.
func (p *planner) recordSources(ct *ast.Task) {
	if len(ct.Sources) == 0 {
		return
	}
	name := p.taskName(ct)
	if _, exists := p.sources[name]; exists {
		return
	}

	useGitignore := ct.UseGitignore != nil && *ct.UseGitignore
	matches, _ := fingerprint.Globs(ct.Dir, ct.Sources, useGitignore)

	files := make([]string, 0, len(matches))
	for _, m := range matches {
		rel, err := filepath.Rel(ct.Dir, m)
		if err != nil {
			rel = m
		}
		files = append(files, filepath.ToSlash(rel))
	}
	sort.Strings(files)

	globs := make([]string, 0, len(ct.Sources))
	for _, g := range ct.Sources {
		if g != nil {
			globs = append(globs, g.Glob)
		}
	}

	method := cmpOr(ct.Method, p.e.Taskfile.Method, "checksum")
	s := &receipt.Sources{
		Task:   name,
		Method: method,
		Globs:  globs,
		Files:  files,
	}
	s.Digest = receipt.Hash(slices.Concat([]string{method, "globs"}, globs, []string{"files"}, files)...)
	p.sources[name] = s
}

// taskVarSources are the variable layers that can differ between tasks;
// Taskfile-level layers are recorded once, on the global scope.
var taskVarSources = map[string]bool{
	varSourceCall:                 true,
	varSourceTaskVars:             true,
	varSourceIncludeVars:          true,
	varSourceIncludedTaskfileVars: true,
}

// recordVars records the task-specific variables that affected a task's
// resolution, with their source layer. Raw values are never written: a
// digest is recorded so receipts can still be compared for equality.
func (p *planner) recordVars(taskName string, ct *ast.Task, tracker map[string]varSource) {
	for name, v := range ct.Vars.All() {
		if name == "MATCH" {
			// MATCH is framework-injected during wildcard resolution; the
			// expanded task name already appears in the plan.
			continue
		}
		src, known := tracker[name]
		if !known {
			// Variables produced during compilation (e.g. live fingerprint
			// values) have no declaration layer; skip them.
			continue
		}
		if !taskVarSources[src.Source] {
			// Global layers are recorded once by recordGlobalVars.
			continue
		}
		kind := "static"
		if src.Dynamic {
			kind = "dynamic"
		} else if v.Ref != "" {
			kind = "ref"
		}
		p.varRecords = append(p.varRecords, receipt.Var{
			Task:   taskName,
			Name:   name,
			Source: src.Source,
			Kind:   kind,
			Secret: v.Secret,
			Digest: receipt.Hash(kind, src.Source, canonicalValue(v.Value)),
		})
	}
}

// recordGlobalVars captures Taskfile-level (global) variables once, before
// the plan walk starts.
func (p *planner) recordGlobalVars() {
	tracker := make(map[string]varSource)
	p.e.Compiler.varSources = tracker
	gv, err := p.e.Compiler.GetTaskfileVariables()
	p.e.Compiler.varSources = nil
	if err != nil {
		return
	}
	for name, v := range gv.All() {
		if name == "MATCH" {
			continue
		}
		src, known := tracker[name]
		if !known {
			continue
		}
		source := src.Source
		switch source {
		case varSourceTaskfileVars:
			if p.isCLIVar(name) {
				source = "cli"
			}
		case varSourceTaskfileEnv:
			// keep
		default:
			// Environment and special variables are ambient and not
			// recorded.
			continue
		}
		kind := "static"
		if src.Dynamic {
			kind = "dynamic"
		} else if v.Ref != "" {
			kind = "ref"
		}
		p.varRecords = append(p.varRecords, receipt.Var{
			Task:   "",
			Name:   name,
			Source: source,
			Kind:   kind,
			Secret: v.Secret || source == varSourceTaskfileEnv || source == "cli",
			Digest: receipt.Hash(kind, source, canonicalValue(v.Value)),
		})
	}
}

func (p *planner) isCLIVar(name string) bool {
	if p.e.globalVars != nil {
		if _, ok := p.e.globalVars.Get(name); ok {
			return true
		}
	}
	return slices.Contains(cliVarNames, name)
}

// collectIncludes flattens the retained Taskfile include graph into
// deterministic include records.
func (p *planner) collectIncludes() []receipt.Include {
	if p.e.taskfileGraph == nil {
		return nil
	}
	adj, err := p.e.taskfileGraph.AdjacencyMap()
	if err != nil {
		return nil
	}
	var includes []receipt.Include
	for src, targets := range adj {
		for dst, edge := range targets {
			incs, ok := edge.Properties.Data.([]*ast.Include)
			if !ok {
				continue
			}
			for _, inc := range incs {
				if inc == nil {
					continue
				}
				includes = append(includes, receipt.Include{
					Namespace: inc.Namespace,
					Parent:    p.rel(src),
					Target:    p.rel(dst),
					Source:    p.rel(inc.Taskfile),
					Optional:  inc.Optional,
					Internal:  inc.Internal,
					Flatten:   inc.Flatten,
					Aliases:   slices.Sorted(slices.Values(inc.Aliases)),
				})
			}
		}
	}
	sort.Slice(includes, func(i, j int) bool {
		if includes[i].Parent != includes[j].Parent {
			return includes[i].Parent < includes[j].Parent
		}
		if includes[i].Target != includes[j].Target {
			return includes[i].Target < includes[j].Target
		}
		return includes[i].Namespace < includes[j].Namespace
	})
	return includes
}

func (p *planner) taskName(ct *ast.Task) string {
	if ct.FullName != "" {
		return ct.FullName
	}
	return ct.Task
}

// rel converts an absolute path to a path relative to the root Taskfile
// directory. Remote URIs and non-absolute paths pass through unchanged, so
// receipts never depend on the checkout location.
func (p *planner) rel(path string) string {
	if path == "" || path == "__stdin__" {
		return path
	}
	if taskfile.IsRemoteEntrypoint(path) {
		return path
	}
	if filepath.IsAbs(path) && p.rootDir != "" {
		if rel, err := filepath.Rel(p.rootDir, path); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

// redact replaces sensitive values in a rendered command with a mask.
// Values are replaced longest-first to avoid partial overlaps, and the
// replacement is deterministic.
func (p *planner) redact(cmd string, sensitive map[string]struct{}) string {
	if len(sensitive) == 0 || cmd == "" {
		return cmd
	}
	values := make([]string, 0, len(sensitive))
	for v := range sensitive {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool {
		if len(values[i]) != len(values[j]) {
			return len(values[i]) > len(values[j])
		}
		return values[i] < values[j]
	})
	for _, v := range values {
		cmd = strings.ReplaceAll(cmd, v, "*****")
	}
	return cmd
}

// invocationKey identifies a task invocation for caching and cycle
// detection: the target name plus the sorted set of call variables.
func invocationKey(call *Call) string {
	if call == nil {
		return ""
	}
	if call.Vars == nil || call.Vars.Len() == 0 {
		return call.Task
	}
	parts := make([]string, 0, call.Vars.Len())
	for name := range call.Vars.Keys() {
		v, _ := call.Vars.Get(name)
		parts = append(parts, name+"="+canonicalVar(v))
	}
	sort.Strings(parts)
	return call.Task + "|" + strings.Join(parts, ",")
}

func canonicalVar(v ast.Var) string {
	if v.Sh != nil && *v.Sh != "" {
		return "sh:" + *v.Sh
	}
	return canonicalValue(v.Value)
}

// canonicalValue renders a variable value in a deterministic form. JSON
// encoding sorts map keys and normalizes lists.
func canonicalValue(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprint(val)
		}
		return string(b)
	}
}

func callLabel(call *Call, resolved string) string {
	if call != nil && call.Task != "" && call.Task != resolved {
		return call.Task
	}
	return ""
}

func platformIDs(platforms []*ast.Platform) []string {
	if len(platforms) == 0 {
		return nil
	}
	out := make([]string, 0, len(platforms))
	for _, p := range platforms {
		switch {
		case p.OS != "" && p.Arch != "":
			out = append(out, p.OS+"/"+p.Arch)
		case p.OS != "":
			out = append(out, p.OS)
		case p.Arch != "":
			out = append(out, "*/"+p.Arch)
		}
	}
	sort.Strings(out)
	return out
}

func cmpOr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
