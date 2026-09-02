package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/go-task/task/v3"
	"github.com/go-task/task/v3/args"
	"github.com/go-task/task/v3/errors"
	"github.com/go-task/task/v3/experiments"
	"github.com/go-task/task/v3/internal/filepathext"
	"github.com/go-task/task/v3/internal/flags"
	"github.com/go-task/task/v3/internal/logger"
	"github.com/go-task/task/v3/internal/version"
	"github.com/go-task/task/v3/receipt"
	"github.com/go-task/task/v3/taskfile/ast"
)

func main() {
	if err := run(); err != nil {
		l := &logger.Logger{
			Stdout:  os.Stdout,
			Stderr:  os.Stderr,
			Verbose: flags.Verbose,
			Color:   flags.Color,
		}
		if err, ok := err.(*errors.TaskRunError); ok && flags.ExitCode {
			emitCIErrorAnnotation(err)
			l.Errf(logger.Red, "%v\n", err)
			os.Exit(err.TaskExitCode())
		}
		if err, ok := err.(errors.TaskError); ok {
			emitCIErrorAnnotation(err)
			l.Errf(logger.Red, "%v\n", err)
			os.Exit(err.Code())
		}
		emitCIErrorAnnotation(err)
		l.Errf(logger.Red, "%v\n", err)
		os.Exit(errors.CodeUnknown)
	}
	os.Exit(errors.CodeOk)
}

// emitCIErrorAnnotation emits an error annotation for supported CI providers.
func emitCIErrorAnnotation(err error) {
	if isGA, _ := strconv.ParseBool(os.Getenv("GITHUB_ACTIONS")); !isGA {
		return
	}
	if e, ok := err.(*errors.TaskRunError); ok {
		fmt.Fprintf(os.Stdout, "::error title=Task '%s' failed::%v\n", e.TaskName, e.Err)
		return
	}
	fmt.Fprintf(os.Stdout, "::error title=Task failed::%v\n", err)
}

func run() error {
	log := &logger.Logger{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Verbose: flags.Verbose,
		Color:   flags.Color,
	}

	if err := flags.Validate(); err != nil {
		return err
	}

	if err := experiments.Validate(); err != nil {
		log.Warnf("%s\n", err.Error())
	}

	if flags.Version {
		fmt.Println(version.GetVersionWithBuildInfo())
		return nil
	}

	if flags.Help {
		pflag.Usage()
		return nil
	}

	if flags.Experiments {
		return log.PrintExperiments()
	}

	if flags.Init {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		args, _, err := args.Get()
		if err != nil {
			return err
		}
		path := wd
		if len(args) > 0 {
			name := args[0]
			if filepathext.IsExtOnly(name) {
				name = filepathext.SmartJoin(filepath.Dir(name), "Taskfile"+filepath.Ext(name))
			}
			path = filepathext.SmartJoin(wd, name)
		}
		finalPath, err := task.InitTaskfile(path)
		if err != nil {
			return err
		}
		if !flags.Silent {
			if flags.Verbose {
				log.Outf(logger.Default, "%s\n", task.DefaultTaskfile)
			}
			log.Outf(logger.Green, "Taskfile created: %s\n", filepathext.TryAbsToRel(finalPath))
		}
		return nil
	}

	if flags.Completion != "" {
		script, err := task.Completion(flags.Completion)
		if err != nil {
			return err
		}
		fmt.Println(script)
		return nil
	}

	// Offline receipt comparison: read the two receipt files only. No
	// Taskfile is read, no task is executed and no remote include is
	// fetched.
	if len(flags.CompareReceipts) == 2 {
		return compareReceipts(flags.CompareReceipts[0], flags.CompareReceipts[1])
	}

	e := task.NewExecutor(
		flags.WithFlags(),
		task.WithVersionCheck(true),
	)
	if err := e.Setup(); err != nil {
		return err
	}

	if flags.ClearCache {
		cachePath := filepath.Join(e.TempDir.Remote, "remote")
		return os.RemoveAll(cachePath)
	}

	listOptions := task.NewListOptions(
		flags.List,
		flags.ListAll,
		flags.ListJson,
		flags.NoStatus,
		flags.Nested,
	)
	if listOptions.ShouldListTasks() {
		if flags.Silent {
			return e.ListTaskNames(flags.ListAll)
		}
		foundTasks, err := e.ListTasks(listOptions)
		if err != nil {
			return err
		}
		if !foundTasks {
			os.Exit(errors.CodeUnknown)
		}
		return nil
	}

	// Parse the remaining arguments
	cliArgsPreDash, cliArgsPostDash, err := args.Get()
	if err != nil {
		return err
	}
	calls, globals := args.Parse(cliArgsPreDash...)

	// If there are no calls, run the default task instead
	if len(calls) == 0 {
		calls = append(calls, &task.Call{Task: "default"})
	}

	// Merge CLI variables first (e.g. FOO=bar) so they take priority over Taskfile defaults
	e.Taskfile.Vars.Merge(globals, nil)
	// Keep the CLI variables around for execution-receipt provenance.
	e.Options(task.WithGlobalVars(globals))

	// Then ReverseMerge special variables so they're available for templating
	cliArgsPostDashQuoted, err := args.ToQuotedString(cliArgsPostDash)
	if err != nil {
		return err
	}
	specialVars := ast.NewVars()
	specialVars.Set("CLI_ARGS", ast.Var{Value: cliArgsPostDashQuoted})
	specialVars.Set("CLI_ARGS_LIST", ast.Var{Value: cliArgsPostDash})
	specialVars.Set("CLI_FORCE", ast.Var{Value: flags.Force || flags.ForceAll})
	specialVars.Set("CLI_SILENT", ast.Var{Value: flags.Silent})
	specialVars.Set("CLI_VERBOSE", ast.Var{Value: flags.Verbose})
	specialVars.Set("CLI_OFFLINE", ast.Var{Value: flags.Offline})
	specialVars.Set("CLI_ASSUME_YES", ast.Var{Value: flags.AssumeYes})
	e.Taskfile.Vars.ReverseMerge(specialVars, nil)
	if !flags.Watch {
		e.InterceptInterruptSignals()
	}

	ctx := context.Background()

	// Receipt generation: resolve the plan with the same inputs as a run,
	// write the receipt, and do not execute anything.
	if flags.Receipt != "" {
		return writeReceipt(ctx, e, flags.Receipt, calls)
	}

	if flags.Status {
		return e.Status(ctx, calls...)
	}

	return e.Run(ctx, calls...)
}

// writeReceipt generates an execution receipt for the given calls and writes
// it to path, or to stdout when path is "-".
func writeReceipt(ctx context.Context, e *task.Executor, path string, calls []*task.Call) error {
	r, err := e.GenerateReceipt(ctx, calls...)
	if err != nil {
		return err
	}

	var w io.Writer = os.Stdout
	if path != "-" {
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("task: cannot write execution receipt to %q: %w", path, err)
		}
		defer f.Close()
		w = f
	}
	if err := receipt.Write(w, r); err != nil {
		return err
	}
	if path != "-" && !flags.Silent {
		l := &logger.Logger{
			Stdout: os.Stdout,
			Stderr: os.Stderr,
			Color:  flags.Color,
		}
		l.Outf(logger.Green, "task: execution receipt written to %s\n", path)
	}
	return nil
}

// compareReceipts loads two receipts and reports whether their plans
// differ. It exits with code 1 when the plans differ so it can be used as a
// CI gate.
func compareReceipts(pathA, pathB string) error {
	a, err := receipt.Load(pathA)
	if err != nil {
		return err
	}
	b, err := receipt.Load(pathB)
	if err != nil {
		return err
	}
	diff, err := receipt.Compare(a, b)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, strings.TrimSpace(diff.String()))
	if !diff.Equal {
		os.Exit(1)
	}
	return nil
}
