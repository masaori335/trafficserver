#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""The uranium tests run the compiler's output, so the checked-in .ir must be what the compiler produces."""
from __future__ import annotations

from pathlib import Path

import pytest
from test_cli import run_hrw4u

_URANIUM_DIR = Path("../../tests/uranium_tests/pluginTest/hrw4u")
_EXTERNS = ("tests/data/extern/cripts.ext.hrw4u",)
_PROCEDURES = "../../plugins/experimental/hrw4u/procedures"
_SCRIPTS = ("g2o", "g2o_kat", "hex_fault", "hmac", "instance_vars")


@pytest.mark.parametrize("name", _SCRIPTS)
def test_uranium_ir_is_the_compiler_output(name: str) -> None:
    externs = [arg for path in _EXTERNS for arg in ("--extern", path)]
    result = run_hrw4u(
        ["--output", "ir", "--ir-version", "1.1", *externs, "--procedures-path", _PROCEDURES,
         str(_URANIUM_DIR / f"{name}.hrw4u")])
    assert result.returncode == 0, result.stderr
    assert result.stdout == (_URANIUM_DIR / f"{name}.ir").read_text()
