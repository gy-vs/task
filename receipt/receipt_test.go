package receipt_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-task/task/v3/receipt"
)

func sampleReceipt() *receipt.Receipt {
	return &receipt.Receipt{
		Format:  receipt.FormatName,
		Version: receipt.Version,
		Entries: []string{"default"},
		Includes: []receipt.Include{
			{
				Namespace: "lib",
				Parent:    "Taskfile.yml",
				Target:    "included/Taskfile.yml",
				Source:    "./included/Taskfile.yml",
			},
		},
		Tasks: []receipt.Task{
			{
				Name:           "build",
				Taskfile:       "Taskfile.yml",
				Run:            "always",
				Method:         "checksum",
				RunsOnPlatform: true,
				Deps:           []string{"lib:setup"},
				Cmds: []receipt.Cmd{
					{Kind: "command", Command: "echo \"hello\""},
					{Kind: "task", Task: "package"},
				},
			},
			{
				Name:           "lib:setup",
				Taskfile:       "included/Taskfile.yml",
				Run:            "always",
				Method:         "checksum",
				RunsOnPlatform: true,
				Cmds: []receipt.Cmd{
					{Kind: "command", Command: "echo \"lib setup\""},
				},
			},
		},
		Vars: []receipt.Var{
			{Task: "", Name: "SECRET_TOKEN", Source: "taskfile-vars", Kind: "dynamic", Secret: true, Digest: "aaa"},
			{Task: "build", Name: "MODE", Source: "call", Kind: "static", Digest: "bbb"},
		},
		Sources: []receipt.Sources{
			{Task: "build", Method: "checksum", Globs: []string{"src/*.txt"}, Files: []string{"src/a.txt"}, Digest: "ccc"},
		},
		Plan: []receipt.Step{
			{Order: 1, Task: "lib:setup", Via: "dep", Digest: "d1"},
			{Order: 2, Task: "build", Via: "entry", Digest: "d2"},
		},
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	t.Parallel()
	r := sampleReceipt()
	r.Fingerprint = receipt.ComputeFingerprint(r)

	var first, second bytes.Buffer
	require.NoError(t, receipt.Write(&first, r))
	require.NoError(t, receipt.Write(&second, r))
	assert.Equal(t, first.String(), second.String(), "receipt serialization must be stable across writes")

	// Fingerprint covers the plan.
	assert.Len(t, r.Fingerprint, 64, "expected a sha256 hex digest")
}

func TestReadRoundTrip(t *testing.T) {
	t.Parallel()
	r := sampleReceipt()
	r.Fingerprint = receipt.ComputeFingerprint(r)

	var buf bytes.Buffer
	require.NoError(t, receipt.Write(&buf, r))

	got, err := receipt.Read(&buf)
	require.NoError(t, err)
	assert.Equal(t, r.Fingerprint, got.Fingerprint)
	assert.Equal(t, r.Plan, got.Plan)
	assert.Equal(t, r.Tasks, got.Tasks)
}

func TestCompareEqual(t *testing.T) {
	t.Parallel()
	a := sampleReceipt()
	a.Fingerprint = receipt.ComputeFingerprint(a)
	b := sampleReceipt()
	b.Fingerprint = receipt.ComputeFingerprint(b)

	diff, err := receipt.Compare(a, b)
	require.NoError(t, err)
	assert.True(t, diff.Equal)
	assert.Empty(t, diff.Includes)
	assert.Empty(t, diff.Vars)
	assert.Empty(t, diff.Sources)
	assert.Empty(t, diff.Steps)
	assert.Contains(t, diff.String(), "match")
}

func TestCompareDetectsAllCategories(t *testing.T) {
	t.Parallel()
	a := sampleReceipt()
	a.Fingerprint = receipt.ComputeFingerprint(a)

	// A second receipt with changes in every category.
	b := sampleReceipt()
	b.Includes[0].Target = "included/other.yml"
	b.Vars[1].Digest = "changed-digest" // call var value changed
	b.Vars = append(b.Vars, receipt.Var{Name: "NEW", Source: "task-vars", Digest: "ddd"})
	b.Sources[0].Digest = "new-source-digest"
	b.Plan = append(b.Plan, receipt.Step{Order: 3, Task: "newtask", Via: "dep", Digest: "d3"})
	b.Tasks = append(b.Tasks, receipt.Task{
		Name: "newtask", Taskfile: "Taskfile.yml", Run: "always", Method: "checksum", RunsOnPlatform: true,
	})
	b.Fingerprint = receipt.ComputeFingerprint(b)

	diff, err := receipt.Compare(a, b)
	require.NoError(t, err)
	assert.False(t, diff.Equal)

	var includeChange, varChange, newVar, sourceChange, stepAdd bool
	for _, c := range diff.Includes {
		if c.B != nil && c.B.Target == "included/other.yml" {
			includeChange = true
		}
		if c.A != nil && c.A.Target == "included/Taskfile.yml" {
			includeChange = true
		}
	}
	for _, c := range diff.Vars {
		if c.Name == "MODE" && c.Kind == receipt.ChangeChanged {
			varChange = true
		}
		if c.Name == "NEW" && c.Kind == receipt.ChangeAdded {
			newVar = true
		}
	}
	for _, c := range diff.Sources {
		if c.Task == "build" && c.Kind == receipt.ChangeChanged {
			sourceChange = true
		}
	}
	for _, c := range diff.Steps {
		if c.TaskB == "newtask" && c.Kind == receipt.ChangeAdded {
			stepAdd = true
		}
	}
	assert.True(t, includeChange, "include diff expected")
	assert.True(t, varChange, "variable value diff expected")
	assert.True(t, newVar, "added variable diff expected")
	assert.True(t, sourceChange, "source diff expected")
	assert.True(t, stepAdd, "added step diff expected")

	// The human-readable report names each category.
	report := diff.String()
	for _, section := range []string{"Includes:", "Variables:", "Sources:", "Execution steps:"} {
		assert.True(t, strings.Contains(report, section), "report should contain %q", section)
	}
}

func attachStepDigests(t *testing.T, r *receipt.Receipt) {
	t.Helper()
	m := map[string]string{}
	for _, task := range r.Tasks {
		raw, err := json.Marshal(task)
		require.NoError(t, err)
		m[task.Name] = receipt.Hash(string(raw))
	}
	for i := range r.Plan {
		r.Plan[i].Digest = m[r.Plan[i].Task]
	}
}

func TestCompareDetectsChangedStep(t *testing.T) {
	t.Parallel()
	a := sampleReceipt()
	attachStepDigests(t, a)
	a.Fingerprint = receipt.ComputeFingerprint(a)

	b := sampleReceipt()
	b.Tasks[0].Cmds[0].Command = "echo \"goodbye\""
	// Recompute step digests as the executor would.
	attachStepDigests(t, b)
	b.Fingerprint = receipt.ComputeFingerprint(b)

	diff, err := receipt.Compare(a, b)
	require.NoError(t, err)
	assert.False(t, diff.Equal)
	require.Len(t, diff.Steps, 1)
	assert.Equal(t, receipt.ChangeChanged, diff.Steps[0].Kind)
	assert.Equal(t, "build", diff.Steps[0].TaskB)
}

func TestUnsupportedVersion(t *testing.T) {
	t.Parallel()

	t.Run("read", func(t *testing.T) {
		t.Parallel()
		r := sampleReceipt()
		r.Version = 999
		var buf bytes.Buffer
		require.NoError(t, receipt.Write(&buf, r))

		_, err := receipt.Read(&buf)
		var unsupported *receipt.UnsupportedVersionError
		require.ErrorAs(t, err, &unsupported)
		assert.Equal(t, 999, unsupported.Version)
		assert.Contains(t, err.Error(), "unsupported receipt version")
	})

	t.Run("compare", func(t *testing.T) {
		t.Parallel()
		a := sampleReceipt()
		b := sampleReceipt()
		b.Version = 42
		b.Fingerprint = "x"
		a.Fingerprint = receipt.ComputeFingerprint(a)

		_, err := receipt.Compare(a, b)
		var unsupported *receipt.UnsupportedVersionError
		require.ErrorAs(t, err, &unsupported)
		assert.Equal(t, 42, unsupported.Version)
	})

	t.Run("wrong format", func(t *testing.T) {
		t.Parallel()
		_, err := receipt.Read(strings.NewReader(`{"format":"something-else","version":1}`))
		var unsupported *receipt.UnsupportedVersionError
		require.ErrorAs(t, err, &unsupported)
		assert.True(t, errors.Is(err, unsupported))
	})
}

func TestCompareNilReceipts(t *testing.T) {
	t.Parallel()
	_, err := receipt.Compare(nil, sampleReceipt())
	require.Error(t, err)
}
