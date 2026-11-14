# Project Agents.md Guide

This is a [MoonBit](https://docs.moonbitlang.com) project.

You can browse and install extra skills here:
<https://github.com/moonbitlang/skills>

## Project Structure

- MoonBit packages are organized per directory; each directory contains a
  `moon.pkg` file listing its dependencies. Each package has its files and
  blackbox test files (ending in `_test.mbt`) and whitebox test files (ending in
  `_wbtest.mbt`).

- In the toplevel directory, there is a `moon.mod` file listing module
  metadata.

## Coding convention

- MoonBit code is organized in block style, each block is separated by `///|`,
  the order of each block is irrelevant. In some refactorings, you can process
  block by block independently.

- Try to keep deprecated blocks in file called `deprecated.mbt` in each
  directory.

## Tooling

- `moon fmt` is used to format your code properly.

- `moon ide` provides project navigation helpers like `peek-def`, `outline`, and
  `find-references`. See $moonbit-agent-guide for details.

- `moon info` is used to update the generated interface of the package, each
  package has a generated interface file `.mbti`, it is a brief formal
  description of the package. If nothing in `.mbti` changes, this means your
  change does not bring the visible changes to the external package users, it is
  typically a safe refactoring.

- In the last step, run `moon info && moon fmt` to update the interface and
  format the code. Check the diffs of `.mbti` file to see if the changes are
  expected.

- Run `moon test` to check tests pass. MoonBit supports snapshot testing; when
  changes affect outputs, run `moon test --update` to refresh snapshots.

- Prefer `assert_eq` or `assert_true(pattern is Pattern(...))` for results that
  are stable or very unlikely to change. For snapshot tests that record
  structured debugging output, derive `Debug` and use `debug_inspect`, rather
  than deriving `Show` for debugging. For solid, well-defined results (e.g.
  scientific computations), prefer assertion tests. You can use
  `moon coverage analyze > uncovered.log` to see which parts of your code are
  not covered by tests.

## Errors and the published interface

MoonBit tracks the error effect and `fail(...)` raises it. A **synchronous**
function that calls a raising one has to say so in its signature
(`-> Unit raise`), but an **`async fn` does not**: the error travels through
the async runtime instead. That is what lets a guard be added to a public
async API (`bundle`, `bundle_with_files`, `pack`) without changing
`pkg.generated.mbti` and without a version bump - measured on 2026-11-14, when
the empty `--Files` path was given a message that says what is wrong and
`moon info` left the published interface untouched.

So a new `fail(...)` in a private **sync** helper needs `-> ... raise` on that
helper, and the caller either handles the error or is itself `async`, which is
exempt. Do not add `raise` to the public functions to be safe: that changes
what the users of the package have to write.

The message a user sees is the exception's own text, wrapped by the runtime
(`error: Failure(... FAILED: the message)`). That is the shape every other
refusal of the tool already has, so a new refusal does not need a special
path of its own.

## Reading the static analyzers

Two published analyzers are run over this repository, and both are worth
running:

```sh
moonx riantr/moonbit_static_analysis@latest      # actionable findings
moonx riantr/LunaFlow@latest analyze --dir .     # CFG, taint, slices
```

Neither is the last word: **`moon check` is the referee.** It is the only
thing here that says whether code is reachable and whether a value is used.
A finding the compiler does not confirm is a false positive of the analyzer,
not a defect of the code, and the code is not to be bent to satisfy it.

- **Dead code at a string slice.** `LunaFlow` reports every statement that
  returns a slice (`text[0:end]`, `p[:i]`, `p[i+1:]`, `body[0:w]`) as
  unreachable. The slice is not modelled, the statement is shredded into
  pieces, and the pieces inherit the deadness of the `return`. There are five
  such sites — cli.mbt, keystore.mbt, platform.mbt twice and progress.mbt —
  and every one of them is now run by a test: the directory of a path, the
  passphrase of a file, the signing key of a key file, the name of a file and
  the truncated line of the bar. The compiler reports no unreachable code
  anywhere.
- **Taint sinks with an index that is in bounds.** `LunaFlow` reports an
  index derived from untrusted input as a sink (`args[i]`, `text[i * 2]`,
  `p[i]`, `text[i]`). The tool says itself that the observed index was inside
  the array. The bounds are provable from the loop condition.
- **A parameter of a `#cfg` stub.** `moonbit_static_analysis` reports a
  parameter of a stub that does nothing as unused. Mark it with a leading
  underscore (`_timeout_ms`): that is the convention the compiler
  understands, it silences the analyzer without changing the interface, and
  it says "deliberately unused" where a `let _ =` would only hide it.
