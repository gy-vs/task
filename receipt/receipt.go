// Package receipt defines the machine-readable "execution receipt" produced
// for a Task run. A receipt describes how a task invocation was resolved:
// which tasks were entered, how dependencies and includes were expanded,
// which Taskfile each task came from, which variables affected resolution
// and where they came from, a summary of the input sources, and a
// fingerprint of the plan in execution order.
//
// Receipts are designed to be compared offline. The format is versioned and
// the serialized content is deterministic for a given commit and set of
// effective inputs: it never contains absolute paths, timestamps, raw
// secret values, or raw environment values. Secret values are represented
// by a digest, so two receipts can still be compared for equality.
//
// This package has no dependency on the task executor, so receipts can be
// read and compared without executing tasks or fetching remote includes.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// FormatName identifies an execution receipt file.
	FormatName = "task-execution-receipt"
	// Version is the receipt format version produced by this build.
	Version = 1
)

// Receipt is the execution receipt for one or more entry tasks.
type Receipt struct {
	// Format is always [FormatName]; it allows callers to detect the file
	// type before decoding the version.
	Format string `json:"format"`
	// Version is the receipt format version.
	Version int `json:"version"`
	// Entries are the task names as they were invoked on the command line
	// (aliases and wildcard patterns are preserved here).
	Entries []string `json:"entries"`
	// Includes describes every Taskfile include edge reached while
	// resolving the plan.
	Includes []Include `json:"includes,omitempty"`
	// Tasks describes every task that participates in the plan, uniquely
	// identified by its fully qualified name.
	Tasks []Task `json:"tasks"`
	// Vars describes the variables that affected resolution and the layer
	// each effective value came from. Environment and special variables
	// are deliberately not listed.
	Vars []Var `json:"vars,omitempty"`
	// Sources summarizes the input sources ("sources:" globs) of each
	// task that declares them.
	Sources []Sources `json:"sources,omitempty"`
	// Plan is the ordered list of task invocations, in the deterministic
	// execution order (dependencies before the task that requires them).
	Plan []Step `json:"plan"`
	// Fingerprint is a digest of the whole plan, computed in execution
	// order. Two receipts with the same fingerprint describe the same plan.
	Fingerprint string `json:"plan_fingerprint"`
}

// Include describes one edge in the Taskfile include graph.
type Include struct {
	// Namespace is the include namespace ("" for flattened includes).
	Namespace string `json:"namespace"`
	// Parent is the Taskfile that declares the include (relative path or
	// remote URI).
	Parent string `json:"parent_taskfile"`
	// Target is the included Taskfile (relative path or remote URI).
	Target string `json:"target_taskfile"`
	// Source is the include spec as written in the parent Taskfile, after
	// template interpolation.
	Source string `json:"source,omitempty"`
	// Optional is true when the include is allowed to be missing.
	Optional bool `json:"optional,omitempty"`
	// Internal is true when the include only exposes internal tasks.
	Internal bool `json:"internal,omitempty"`
	// Flatten is true when the include's tasks are not namespaced.
	Flatten bool `json:"flatten,omitempty"`
	// Aliases are the namespace aliases, if any (sorted).
	Aliases []string `json:"aliases,omitempty"`
}

// Task describes a task participating in the plan.
type Task struct {
	// Name is the fully qualified task name (including namespaces), with
	// wildcard matches expanded.
	Name string `json:"name"`
	// Aliases are the names this task can be called by (sorted).
	Aliases []string `json:"aliases,omitempty"`
	// Taskfile is the Taskfile the task is defined in (relative path or
	// remote URI).
	Taskfile string `json:"taskfile"`
	// Line is the task's line number in its Taskfile.
	Line int `json:"line,omitempty"`
	// Dir is the task's working directory, relative to the root Taskfile
	// directory when possible.
	Dir string `json:"dir,omitempty"`
	// Internal marks tasks that cannot be called directly.
	Internal bool `json:"internal,omitempty"`
	// Run is the effective run mode ("always", "once" or "when_changed").
	Run string `json:"run,omitempty"`
	// Method is the effective fingerprinting method.
	Method string `json:"method,omitempty"`
	// Platforms are the platform constraints declared on the task
	// (formatted as "os/arch", sorted).
	Platforms []string `json:"platforms,omitempty"`
	// RunsOnPlatform reports whether the platform constraints match the
	// current platform. Tasks that do not match are skipped at runtime,
	// together with their dependencies.
	RunsOnPlatform bool `json:"runs_on_platform"`
	// Deps are the fully qualified dependency task names, in declared
	// (and loop-expanded) order.
	Deps []string `json:"deps,omitempty"`
	// Cmds are the task's commands / task calls in declared order, with
	// secret and environment values redacted.
	Cmds []Cmd `json:"cmds,omitempty"`
}

// Cmd describes one command or nested task call of a task.
type Cmd struct {
	// Kind is "command" for shell commands and "task" for task calls.
	Kind string `json:"kind"`
	// Command is the rendered shell command, with secret and environment
	// values redacted. Only set for Kind == "command".
	Command string `json:"command,omitempty"`
	// Task is the fully qualified name of the called task. Only set for
	// Kind == "task".
	Task string `json:"task,omitempty"`
	// Defer marks deferred commands.
	Defer bool `json:"defer,omitempty"`
	// Conditional reports that an "if" condition guards this command; the
	// condition is evaluated at runtime and its text is not recorded.
	Conditional bool `json:"conditional,omitempty"`
	// Platforms are the command-level platform constraints (sorted).
	Platforms []string `json:"platforms,omitempty"`
	// RunsOnPlatform reports whether the command-level platform
	// constraints match the current platform. Only meaningful when
	// Platforms is non-empty.
	RunsOnPlatform bool `json:"runs_on_platform,omitempty"`
}

// Var describes a variable that affected resolution.
type Var struct {
	// Task is the fully qualified name of the task the variable applies
	// to. It is empty for Taskfile-level (global) variables.
	Task string `json:"task,omitempty"`
	// Name is the variable name.
	Name string `json:"name"`
	// Source is the layer that provided the effective value: one of
	// "cli", "taskfile-env", "taskfile-vars", "include-vars",
	// "included-taskfile-vars", "call" or "task-vars".
	Source string `json:"source"`
	// Kind is "static", "dynamic" (a "sh:" variable) or "ref".
	Kind string `json:"kind"`
	// Secret marks variables declared as secret (as well as variables
	// coming from environment blocks or the command line, which may
	// contain secrets). Raw values are never written.
	Secret bool `json:"secret,omitempty"`
	// Digest is a digest of the kind, source and resolved canonical
	// value. Values are never written, but digests let two receipts be
	// compared for equality without revealing the values.
	Digest string `json:"digest,omitempty"`
}

// Sources summarizes the resolved input sources of a task.
type Sources struct {
	// Task is the fully qualified task name.
	Task string `json:"task"`
	// Method is the fingerprinting method in effect.
	Method string `json:"method"`
	// Globs are the resolved source patterns, in declared order.
	Globs []string `json:"globs,omitempty"`
	// Files are the files matched by the globs, relative to the task
	// directory and sorted.
	Files []string `json:"files,omitempty"`
	// Digest covers the method, patterns and matched files.
	Digest string `json:"digest"`
}

// Step is one task invocation in the plan.
type Step struct {
	// Order is the 1-based position in execution order.
	Order int `json:"order"`
	// Task is the fully qualified name of the invoked task.
	Task string `json:"task"`
	// Via describes how the task was reached: "entry" for the tasks
	// passed on the command line, "dep" for a dependency, or "cmd" for a
	// nested task call.
	Via string `json:"via"`
	// Call is the name used to invoke the task (e.g. an alias), when it
	// differs from Task.
	Call string `json:"call,omitempty"`
	// Digest identifies the structural content of the invoked task
	// (its redacted commands, dependencies and constraints). Two
	// invocations of the same task with different digests execute
	// different steps.
	Digest string `json:"digest,omitempty"`
	// Conditional reports that a task-level "if" condition guards the
	// task; it is evaluated at runtime.
	Conditional bool `json:"conditional,omitempty"`
	// Skipped is set to "platform" when the task does not match the
	// current platform (it and its dependencies are not executed).
	Skipped string `json:"skipped,omitempty"`
	// Cycle reports that invoking the task again would close a dependency
	// cycle; its dependencies were not expanded again.
	Cycle bool `json:"cycle,omitempty"`
}

// UnsupportedVersionError is returned when reading or comparing a receipt
// whose format or version is not supported.
type UnsupportedVersionError struct {
	// Format is the "format" field found in the receipt, if any.
	Format string
	// Version is the "version" field found in the receipt.
	Version int
}

func (e *UnsupportedVersionError) Error() string {
	if e.Format != "" && e.Format != FormatName {
		return fmt.Sprintf("task: unsupported receipt format %q (expected %q)", e.Format, FormatName)
	}
	return fmt.Sprintf("task: unsupported receipt version %d (this build supports version %d)", e.Version, Version)
}

// Read decodes a receipt from r and validates its format and version.
func Read(r io.Reader) (*Receipt, error) {
	var rcpt Receipt
	dec := json.NewDecoder(r)
	if err := dec.Decode(&rcpt); err != nil {
		return nil, fmt.Errorf("task: failed to parse execution receipt: %w", err)
	}
	if rcpt.Format != FormatName {
		return nil, &UnsupportedVersionError{Format: rcpt.Format, Version: rcpt.Version}
	}
	if rcpt.Version != Version {
		return nil, &UnsupportedVersionError{Format: rcpt.Format, Version: rcpt.Version}
	}
	return &rcpt, nil
}

// Load reads and validates a receipt from the file at path.
func Load(path string) (*Receipt, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("task: cannot open execution receipt %q: %w", path, err)
	}
	defer f.Close()
	return Read(f)
}

// Write serializes the receipt deterministically to w.
func Write(w io.Writer, r *Receipt) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("task: failed to encode execution receipt: %w", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("task: failed to write execution receipt: %w", err)
	}
	return nil
}

// ComputeFingerprint returns a deterministic digest of the receipt's plan.
// The digest covers the entries, includes, tasks (with redacted commands),
// variables (with secret values digested), sources and the ordered plan.
// It is independent of absolute paths, map iteration order and timestamps.
func ComputeFingerprint(r *Receipt) string {
	cp := *r
	cp.Fingerprint = ""
	b, err := json.Marshal(cp)
	if err != nil {
		// All receipt types are JSON-encodable; a failure here is a bug.
		panic(fmt.Sprintf("task: failed to fingerprint execution receipt: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Hash returns a stable digest of the canonical representation of the given
// values. Values are joined with NUL bytes so components cannot bleed into
// each other.
func Hash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
