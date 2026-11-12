# Prism VM - runs hrw4u programs natively

## Status

Prism is meant to become a bytecode machine for performance, but this branch only has an interpreter that runs the
`.ir` the hrw4u compiler writes with `--output ir`.

## hrw4u support

This branch supports only part of hrw4u. `prism-vm-support.sandbox.yaml` names the sections, functions, conditions, operators and
modifiers prism.so refuses; pass it as `--sandbox` to the compiler that writes the `.ir` to get those as compile errors
instead of load-time failures. The policy cannot say which hooks a builtin runs in, so a builtin in a hook the compiler
allows but prism.so does not is refused only when prism.so loads the `.ir`. `docs/hrw4u-support.md` lists, by
`.hrw4u` category, each spelling, the `header_rewrite` it compiles to, and whether prism.so runs it; for functions,
conditions and operators, also in which hooks.

## libcripts

Prism depends heavily on libcripts. These commits on this branch must go upstream; once upstream has them, rebase onto
it and drop them here. They sit just below the first prism commit, 42d43868f7.

```
# Repeated header field lines
5b550e9d21 Cripts: join duplicate header field lines on read
  -> waiting sec-master is published

# Client address
1572bc50b7 cripts: report the client address the core reports
  -> PR#14045

# Server::Request, readable at READ_RESPONSE
15574c7d99 cripts: read the request to the origin after it is sent
  -> after PR#14037

# Unit test helper
df38bb6bcb cripts: let the test transaction hold a client response
  -> PR#14037 will cover this

# Server::URL
dd85227508 cripts: read the URL of the request to the origin
  -> waiting Reset() in sec-master is published
```

## hrw4u

The Typed IR emitter in `tools/hrw4u` comes from work-9's `asf-master-hrw4u-cripts-interp` (`2e0f4daa57..0474390b29`).
These commits on this branch change what the compiler already does and must go upstream; once upstream has them, drop
them here. They sit just above 140cd551dc.

When PR#14038 is merged, this branch will pick it too.

```
# String holes
1518129460 hrw4u: find string holes with a scanner, parse a call with the grammar

# Scoped spellings
3acee6bfb9 hrw4u: name the response of set-redirect
e0c50b551f hrw4u: name the URL of remove_query and keep_query

# Procedures
4624ab1f52 hrw4u: substitute $param in function arguments, refuse braces in key lists
```

### Installing this PR's `hrw4u` compiler

No package index has this branch's compiler, and `apple-pypi-integration-local` keeps a package for only 24 hours, so
build the wheel from the PR. It needs `antlr` and `uv` on `PATH` (`brew install antlr uv` on macOS):

```
gh pr checkout https://github.pie.apple.com/ats/trafficserver/pull/1377
cd tools/hrw4u
PIP_INDEX_URL=https://pypi.apple.com/simple make package
uv tool install --reinstall --python 3.13 dist/apple_hrw4u-*.whl
```

`make package` sets up `.venv` with `uv` itself. `python -m build` then installs the build backend with pip into a
separate environment, which goes to pypi.org unless `PIP_INDEX_URL` says otherwise. The wheel's version is always
`0.0.0+placeholder.do.not.publish`, so without `--reinstall` uv keeps whichever wheel it installed first. `hrw4u` lands
in `~/.local/bin`; `uv tool update-shell` puts that on `PATH`. It can replace `tools/hrw4u/.venv/bin/hrw4u` in the steps
below, but it is a copy of the wheel: after a change under `tools/hrw4u`, build and install the wheel again.

## Akamai G2O

G2O, written in hrw4u as the `Apple::G2O` procedures in `plugins/experimental/prism/procedures/Apple/G2O.hrw4u`, is the
first target and runs on this branch. `g2o.ir` and `g2o_kat.ir` in `tests/uranium_tests/pluginTest/prism/` are compiled
from the `.hrw4u` files next to them, which use those procedures, and `g2o.test.yaml` there checks the signatures in
traffic_server. They use the `prism::` functions bound in `plugins/experimental/prism/src/cripts_bindings.cc`. The procedures
are installed in `share/trafficserver/hrw4u/procedures/`, `prism-vm-support.sandbox.yaml` in `share/trafficserver/hrw4u/`, and
`prism.ext.hrw4u`, the `extern` manifest of those calls that the build writes with `hrw4u-extern`, in
`share/trafficserver/hrw4u/extern/`; bazinga-trafficserver-plugins-builtin ships them with prism.so.

### Compiling G2O and running it on prism

`<build>` is this tree's build directory, configured with `ENABLE_CRIPTS`, `ENABLE_URTEST` and `ENABLE_PRISM`
(`BUILD_EXPERIMENTAL_PLUGINS` makes `ENABLE_PRISM` default on, but only on the first configure); without them
`prism.so` or `urtest.sh` is not built. Steps 1 and 2 run from the top of the tree.

1. Build and install, which builds `prism.so` and its manifest, then set up the compiler, which needs `antlr` and `uv`
   on `PATH`:

   ```
   cmake --build <build> -t install
   make -C tools/hrw4u setup-deps
   ```

   After a change under `tools/hrw4u`, run `make -C tools/hrw4u gen` again; `.venv/bin/hrw4u` runs what it generates.

2. Compile both programs. `INSTANCE_VARS` and calls to the `prism::` functions need IR 1.1, and the compiler writes 1.0 by
   default; without `--ir-version 1.1` the instance variables are not declared, so the procedures also fail with
   unknown symbols and bare references.

   ```
   tools/hrw4u/.venv/bin/hrw4u --output ir --ir-version 1.1 \
     --extern <build>/plugins/experimental/prism/prism.ext.hrw4u \
     --sandbox plugins/experimental/prism/prism-vm-support.sandbox.yaml \
     --procedures-path plugins/experimental/prism/procedures \
     tests/uranium_tests/pluginTest/prism/g2o.hrw4u:tests/uranium_tests/pluginTest/prism/g2o.ir \
     tests/uranium_tests/pluginTest/prism/g2o_kat.hrw4u:tests/uranium_tests/pluginTest/prism/g2o_kat.ir
   ```

   `git status` must show no change to the two `.ir` files.

3. Run them in traffic_server:

   ```
   cd <build>/tests
   ./urtest.sh --no-run-in-container -v -k g2o
   ```
