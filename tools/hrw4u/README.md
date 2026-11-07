# HRW4U - Header Rewrite for You

[![Apache License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)

HRW4U is a domain-specific language and compiler toolchain for Apache Traffic Server's `header_rewrite` plugin, providing a more readable and maintainable alternative to writing header rewrite rules directly.

## Tools Overview

### `hrw4u` - Forward Compiler
Compiles HRW4U source files into Apache Traffic Server `header_rewrite` configuration.

**Input**: Human-readable HRW4U syntax
**Output**: Native `header_rewrite` plugin rules

### `u4wrh` - Reverse Compiler
Decompiles existing `header_rewrite` rules back into HRW4U source code.

**Input**: Native `header_rewrite` plugin rules
**Output**: Human-readable HRW4U syntax

## Requirements

- **Python 3.12+** (uses modern type annotations and performance features)
- **ANTLR4** for grammar parsing
- **uv** (for Python environment management)

## Development Setup

### 1. Clone and Setup Environment
```bash
git clone https://github.com/apache/trafficserver.git
cd trafficserver/tools/hrw4u

# Install uv if not already installed
# See: https://docs.astral.sh/uv/getting-started/installation/

# Create virtual environment and install dependencies
uv sync --all-extras
```

### 2. Build the Package
```bash
# Generate parsers and build packages
make

# Create distributable wheel
make package
```

### 3. Install for Development
```bash
# Install in development mode
uv pip install -e .

# Or install the built wheel
uv pip install dist/hrw4u-*.whl
```

## Testing

```bash
# Run all tests
make test

# Run specific test categories
uv run pytest -m examples    # Documentation examples
uv run pytest -m conds       # Condition tests
uv run pytest -m ops         # Operator tests
uv run pytest -m reverse     # Reverse compilation tests
```

## Usage

### Forward Compilation (hrw4u)

```bash
# Compile HRW4U source to header_rewrite rules
hrw4u input.hrw4u > output.conf

# From stdin
cat input.hrw4u | hrw4u > output.conf

# Show parse tree (debugging)
hrw4u --ast input.hrw4u

# Enable debug output
hrw4u --debug input.hrw4u
```

**Options:**
- `--hrw` - Produce header_rewrite output (default)
- `--ast` - Show ANTLR parse tree
- `--debug` - Enable debug tracing

### Typed IR for hrw4u.so

`--output ir` compiles the same source to the Typed IR that `hrw4u.so`
(`plugins/experimental/hrw4u`) runs, instead of `header_rewrite` rules.

```bash
# Compile HRW4U source to Typed IR
hrw4u --output ir input.hrw4u > output.ir

# Call the functions hrw4u.so and an extension bind, declared by the manifests hrw4u-extern prints
hrw4u-extern hrw4u.so > cripts.ext.hrw4u
hrw4u-extern hrw4u_ext_example_ua.so > example_ua.ext.hrw4u
hrw4u --output ir --ir-version 1.1 --extern cripts.ext.hrw4u --extern example_ua.ext.hrw4u ua.hrw4u > ua.ir
```

**Options:**
- `--output ir` - Produce Typed IR for `hrw4u.so` (experimental)
- `--ir-version {1.0,1.1}` - The highest IR version `--output ir` may write (default: 1.0); a program is written at the
  lowest version that has what it uses. Calls to declared functions and `INSTANCE_VARS` need 1.1
- `--extern FILE` - A manifest `hrw4u-extern` printed, declaring the functions a script may call; repeatable, read in
  order. A manifest holds `extern` declarations only, and a name declared twice is an error

A script calls a declared function for its value. The call is either the whole right-hand
side of an `=` or `+=` whose target takes a string, where the function returns `string`, or
a `{...}` hole in a string, where it may return any of the three types:

```
SEND_RESPONSE {
    inbound.resp.X-B64 = cripts::Crypto::Base64::Encode("{inbound.req.X-Raw}");
    inbound.resp.X-Enc = "v={cripts::Crypto::Base64::Encode(\"{inbound.req.X-Raw}\")}";
}
```

- An argument is a string, a number, `true`, `false`, an instance variable, or a call to a
  declared function, of the type the declaration names. A bare reference is refused: write
  `inbound.req.X-Raw` as `"{inbound.req.X-Raw}"`.
- A call cannot be a statement of its own, a condition, or an argument of a builtin or a
  procedure.
- In a hole, a string argument is written with `\"` escapes, an `int64` or `bool` result is
  written into the string as `fmt` writes any value, and `with NORM` applies to the result.
  The hole is parsed on its own with the grammar, as [String interpolation](#string-interpolation)
  says; ANTLR lexer modes are the follow-up. An `INSTANCE_VARS` initializer refuses every hole,
  and a condition function's string argument, as in `access("{...}")`, is not interpolated.
- A `pure` function runs in any hook, a `load` one only in an `INSTANCE_VARS`
  initializer; one with an effect cannot be called yet.

`INSTANCE_VARS` declares string variables that `hrw4u.so` sets once, when it loads the
rule, from a string or a call to a declared `pure` or `load` function:

```
INSTANCE_VARS {
    secret: string = cripts::Crypto::Hex::Decode(cripts::File::Line::Read("secret.hex"));
}

SEND_REQUEST {
    outbound.req.X-Sign = cripts::Crypto::Base64::Encode(cripts::Crypto::HMAC::SHA256::Sign(secret, "{outbound.url.path}"));
}
```

- The initializer cannot read the transaction or another instance variable.
- A hook reads the variable by name, as a value or an argument, or as `"{secret}"` in a
  string. It cannot be assigned, or read in a condition, yet.
- A name declared twice, or in both `VARS` and `INSTANCE_VARS`, is an error.

Neither calls nor `INSTANCE_VARS` have a `header_rewrite` spelling, so only `--output ir`
compiles them.

### Reverse Compilation (u4wrh)

```bash
# Decompile header_rewrite rules to HRW4U source
u4wrh rules.conf > output.hrw4u

# From stdin
cat rules.conf | u4wrh > output.hrw4u

# Show parse tree (debugging)
u4wrh --ast rules.conf

# Enable debug output
u4wrh --debug rules.conf
```

**Options:**
- `--hrw4u` - Produce HRW4U source output (default)
- `--ast` - Show ANTLR parse tree
- `--debug` - Enable debug tracing

## Example

**HRW4U Source** (`example.hrw4u`):
```
REMAP {
    if inbound.ip in {10.0.0.0/8, 192.168.0.0/16} {
        inbound.req.X-IP = "{inbound.ip}";
    }
}
```

**Generated header_rewrite rules**:
```bash
hrw4u example.hrw4u
```
```
cond %{REMAP_PSEUDO_HOOK} [AND]
cond %{IP:CLIENT} {10.0.0.0/8,192.168.0.0/16}
    set-header X-IP "%{IP:CLIENT}"
```

**Generated hrw4u script from header_rewrite rules**:
```bash
hrw4u example.hrw4u | u4wrh
```
```
REMAP {
    if inbound.ip in {10.0.0.0/8, 192.168.0.0/16} {
        inbound.req.X-IP = "{inbound.ip}";
    }
}
```

Passing the output from hrw4u back into u4wrh brings back the original script again!

### String interpolation

A `{...}` in a string is a hole, and its value is put there. `{{...}}` is literal brace
text, `%{...}` is passed to `header_rewrite` as written, and a `{` that closes no hole,
`{}` among them, is text.

- A hole without `(` is a name: a symbol, a variable or an instance variable, with optional
  value modifiers, as in `"{inbound.url.path with NORM}"`.
- A hole with `(` is a call, with optional value modifiers: a builtin such as
  `"{random(100)}"`, or a declared function, which only `--output ir` compiles.

The STRING token keeps a hole as text. A scanner finds each hole's bounds, and a hole that
holds a call is parsed on its own with the grammar's `interpolation` rule, so its arguments
are what a call's are anywhere else. A hole without one is not parsed: its name goes to the
symbol lookup as written, because IDENT cannot spell every header name (`"{inbound.req.X~Foo}"`
is one), and a hole that compiles in IR 1.0 must keep its meaning, since a minor version only
adds. The follow-up is ANTLR lexer modes, an f-string-like STRING, which can give a hole's
name a token of its own as wide as an HTTP header name.

## Build System

The project uses a hybrid build system:

- **GNU Make** - Grammar generation and package building
- **pyproject.toml** - Modern Python packaging configuration
- **ANTLR4** - Grammar compilation to Python parsers

### Key Make Targets

```bash
make           # Build everything (default)
make clean     # Remove build artifacts
make test      # Run test suite
make package   # Create distributable wheel
```

## Releasing apple-hrw4u to Apple Internal PyPI

The package publishes automatically as part of every regular ATS release on
release branches. The publish call lives in master's `apple/rio.sh` so
future release branches inherit it at branch-cut time. Pipelines opt in
explicitly by passing `--hrw4u` to `apple/rio.sh`; only
`release-{branch}-publish-regular` does. Variant (asan/debug), breakfix,
PRB, and intpr pipelines do not pass `--hrw4u`, so they skip the publish.
Breakfix auto-publish is tracked separately in
[rdar://179386187](rdar://179386187) because the wheel version needs to
include the BREAK_FIX segment.

### Auto-publish path (the canonical flow)

When `release-{branch}-publish-regular` runs, the build step is:

```
./apple/rio.sh --build --branch <branch> --release --hrw4u --number ${BUILD_PARAM_build_number}
```

`apple/rio.sh`:

1. Reads `BUILD_NUMBER` from the Rio build parameter and `VERSION` from
   `CMakeLists.txt`. Builds the ATS RPM. Stages the RPM with
   `ci stage-lib --label rpm`. Pushes the
   `bazinga/<VERSION>/<BUILD_NUMBER>.<COMMITS>.el9` tag if invoked with
   `--tagbuild` (release branches do; master does not).
2. After tagging, if `--hrw4u` was passed, invokes
   `apple/publish-hrw4u.sh --version <VERSION> --build-number <BUILD_NUMBER>`.
   Pipelines that should not publish (variant/breakfix/PRB/intpr) simply
   omit the flag.

`apple/publish-hrw4u.sh`:

3. Composes `PKG_VERSION="${VERSION}.${BUILD_NUMBER}rc0"` (e.g.
   `10.2.0.22rc0`), writes it to `pyproject.toml` via
   `scripts/sync_version.py`, runs `make package`, and stages the built
   wheel with `ci stage-lib --label wheel`.
4. The `rc0` suffix makes the wheel a PEP 440 release candidate. `pip` and
   `pipx` exclude pre-releases from default resolution, so consumers must
   opt in via `pip install --pre apple-hrw4u` or pin the exact version.

After the build step completes, Rio's `package.freeform.publish` (defined
in `rio.yml`) takes over. Labeled artifacts are routed to their target
Artifactory repositories:

* `--label rpm` -> `yum:cdn-edge` (the existing bazinga RPM publish path,
  required: build fails if no RPM is staged)
* `--label wheel` -> `apple-pypi-release-local` (the new PyPI publish
  path, marked `optional: true` so master release runs without a wheel
  do not fail)

No Rio secret is required for either upload. Rio authenticates to
Artifactory using the project's APS group / `sandboxPerms.allowRio`
default credentials. The `apple-hrw4u` namespace already has
`sandboxPerms.allowRio` set, so first-pipeline-publish succeeds without
any namespace configuration changes. Rio also signs each published
artifact (verified via the `pie.ci.signedJWT` property attached to
existing Rio-published wheels in `apple-pypi-release-local`).

### Promoting an RC to a final release

The auto-publish path always produces an `rc0` wheel. To promote a specific
build to an official (non-prerelease) version, drop the `rc0` suffix and
publish manually, typically via the `hrw4u-backport-release` skill.

PEP 440 ordering for a given `<VERSION>.<BUILD_NUMBER>` pair, low to high:

1. `10.2.0.22rc0` -- the auto-published RC for build 22
2. `10.2.0.22rc1` -- a later RC of the same build (manual republish)
3. `10.2.0.22` -- the official / final release of build 22
4. `10.2.0.22.post0` -- a post-release patch on top of the final

`pip install apple-hrw4u` (no version specifier) picks the highest non-pre
version available. Once `10.2.0.22` exists alongside `10.2.0.22rc0`, the RC
is no longer the default; consumers needing the RC must use `--pre` or pin
the exact `==10.2.0.22rc0`.

### Yanking a bad publish

PyPI is immutable; there is no "delete." Use the `yank-hrw4u` skill to mark a
bad version as yanked on Apple's internal Artifactory. Yanked versions still
install for explicit pins but are excluded from `pip install apple-hrw4u`
without a version specifier.

### Verifying the publish script before merging

`bash -n apple/publish-hrw4u.sh` catches shell syntax errors. For
functional changes that require running it, push to a branch and let
the pipeline exercise it end to end; there is no production-safe
local invocation.

## Project Structure

```
tools/hrw4u/
├── src/                  # Python source code
│   ├── common.py        # Shared utilities and patterns
│   ├── types.py         # Type definitions and dataclasses
│   ├── symbols.py       # Symbol resolution engine
│   └── ...              # Additional modules
├── scripts/             # Command-line entry points
│   ├── hrw4u           # Forward compiler script
│   └── u4wrh           # Reverse compiler script
├── grammar/             # ANTLR4 grammar definitions
├── tests/               # Comprehensive test suite
└── pyproject.toml       # Modern Python package configuration
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for details.

---

*Part of the [Apache Traffic Server](https://trafficserver.apache.org/) project.*
