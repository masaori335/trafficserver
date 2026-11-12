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
in `~/.local/bin`; `uv tool update-shell` puts that on `PATH`. It runs the wheel's copy of `tools/hrw4u`, not the
tree: after a change under `tools/hrw4u`, build and install the wheel again.

#### on lab box

```
sudo env UV_TOOL_DIR=/opt/hrw4u/tools UV_TOOL_BIN_DIR=/opt/hrw4u/bin \
  UV_PYTHON_INSTALL_DIR=/opt/hrw4u/python UV_LINK_MODE=copy \
  "$(command -v uv)" tool install --force ./apple_hrw4u-10.2.2.dev12+intpr.1377.sec20261112.ee8eee902-py3-none-any.whl
```

## Akamai G2O

G2O, written in hrw4u as the `Apple::G2O` procedures in `plugins/experimental/prism/procedures/Apple/G2O.hrw4u`, is the
first target and runs on this branch. `g2o.ir` and `g2o_kat.ir` in `tests/uranium_tests/pluginTest/prism/` are compiled
from the `.hrw4u` files next to them, which use those procedures, and `g2o.test.yaml` there checks the signatures in
traffic_server. They use the `prism::` functions bound in `plugins/experimental/prism/src/cripts_bindings.cc`. The procedures
are installed in `share/trafficserver/hrw4u/procedures/`, `prism-vm-support.sandbox.yaml` in `share/trafficserver/hrw4u/`, and
`prism.ext.hrw4u`, the `extern` manifest of those calls that the build writes with `hrw4u-extern`, in
`share/trafficserver/hrw4u/extern/`; bazinga-trafficserver-plugins-builtin ships them with prism.so.

### Compiling G2O and running it on prism

These steps run on a host with bazinga-trafficserver and bazinga-trafficserver-plugins-builtin of the same version, and
the compiler installed as above. The packages install in `/opt/bazinga`, whose `etc/trafficserver` is the config
directory.

1. Compile the program into the config directory. `INSTANCE_VARS` and calls to the `prism::` functions need IR 1.1, and
   the compiler writes 1.0 by default; without `--ir-version 1.1` the instance variables are not declared, so the
   procedures also fail with unknown symbols and bare references. The manifest comes from the same build as the
   installed prism.so, so the compiler checks the calls against the prism.so that runs them.

   ```
   hrw4u --output ir --ir-version 1.1 \
     --extern /opt/bazinga/share/trafficserver/hrw4u/extern/prism.ext.hrw4u \
     --sandbox /opt/bazinga/share/trafficserver/hrw4u/prism-vm-support.sandbox.yaml \
     --procedures-path /opt/bazinga/share/trafficserver/hrw4u/procedures \
     g2o.hrw4u:/opt/bazinga/etc/trafficserver/g2o.ir
   ```

   `g2o.hrw4u` is a copy of `tests/uranium_tests/pluginTest/prism/g2o.hrw4u` with your nonce in place of `my-nonce`;
   `procedures/Apple/G2O.hrw4u` says what a nonce may hold.

2. Write the secret in hex, on the first line, to `/opt/bazinga/etc/trafficserver/g2o_secret.hex`.
   `prism::File::FirstLine` reads a relative path from the config directory, unless it names a file in `/opt/bazinga`,
   where traffic_server runs.

3. Add the remap rule to `/opt/bazinga/etc/trafficserver/remap.config` and run `traffic_ctl config reload`. prism.so
   refuses a relative `.ir` path:

   ```
   map http://g2o.example/ https://origin.example/ @plugin=prism.so @pparam=/opt/bazinga/etc/trafficserver/g2o.ir
   ```

### Rebuilding the test `.ir` files

`g2o.ir` and `g2o_kat.ir` are compiled against this tree's build instead. `<build>` is configured with `ENABLE_CRIPTS`,
`ENABLE_URTEST` and `ENABLE_PRISM` (`BUILD_EXPERIMENTAL_PLUGINS` makes `ENABLE_PRISM` default on, but only on the first
configure); without them `prism.so` or `urtest.sh` is not built. Run from the top of the tree; the compiler needs
`antlr` and `uv` on `PATH`. After a change under `tools/hrw4u`, run `make -C tools/hrw4u gen` again before compiling;
`.venv/bin/hrw4u` runs what it generates.

```
cmake --build <build> -t install
make -C tools/hrw4u setup-deps
tools/hrw4u/.venv/bin/hrw4u --output ir --ir-version 1.1 \
  --extern <build>/plugins/experimental/prism/prism.ext.hrw4u \
  --sandbox plugins/experimental/prism/prism-vm-support.sandbox.yaml \
  --procedures-path plugins/experimental/prism/procedures \
  tests/uranium_tests/pluginTest/prism/g2o.hrw4u:tests/uranium_tests/pluginTest/prism/g2o.ir \
  tests/uranium_tests/pluginTest/prism/g2o_kat.hrw4u:tests/uranium_tests/pluginTest/prism/g2o_kat.ir
```

`git status` must show no change to the two `.ir` files. Then run them in traffic_server:

```
cd <build>/tests
./urtest.sh --no-run-in-container -v -k g2o
```
