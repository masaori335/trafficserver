#
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

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "sync_version.py"


def run(version: str, pyproject_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--version", version, "--pyproject",
         str(pyproject_path)],
        capture_output=True,
        text=True,
    )


@pytest.fixture
def pyproject(tmp_path: Path) -> Path:
    p = tmp_path / "pyproject.toml"
    p.write_text(
        textwrap.dedent(
            """\
            [build-system]
            requires = ["setuptools>=65.0", "wheel"]

            [project]
            name = "apple-hrw4u"
            version = "0.0.0"
            description = "HRW4U is a transpiler"
            """))
    return p


def test_replaces_release_candidate_version(pyproject: Path) -> None:
    result = run("10.2.0.22rc0", pyproject)
    assert result.returncode == 0, result.stderr
    content = pyproject.read_text()
    assert 'version = "10.2.0.22rc0"' in content
    assert 'name = "apple-hrw4u"' in content
    assert 'description = "HRW4U is a transpiler"' in content


def test_replaces_arbitrary_pep440_version(pyproject: Path) -> None:
    result = run("10.0.6.post3", pyproject)
    assert result.returncode == 0, result.stderr
    assert 'version = "10.0.6.post3"' in pyproject.read_text()


def test_idempotent_when_version_already_set(pyproject: Path) -> None:
    pyproject.write_text(pyproject.read_text().replace('"0.0.0"', '"10.2.0.22rc0"'))
    before = pyproject.read_text()
    result = run("10.2.0.22rc0", pyproject)
    assert result.returncode == 0, result.stderr
    assert pyproject.read_text() == before


def test_fails_when_no_version_field(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text('[project]\nname = "foo"\n')
    result = run("1.0.0", p)
    assert result.returncode != 0
    assert "version" in result.stderr.lower()


def test_only_replaces_first_match(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    # A pinned dep below the [project] table happens to look like a version
    # assignment under TOML inline-table syntax. Make sure the script targets
    # the [project].version field, not the dependency.
    p.write_text(
        textwrap.dedent(
            """\
            [project]
            name = "apple-hrw4u"
            version = "0.0.0"
            dependencies = [
                "pyyaml>=6.0,<7.0",
            ]
            """))
    result = run("11.0.0.5rc0", p)
    assert result.returncode == 0, result.stderr
    content = p.read_text()
    assert 'version = "11.0.0.5rc0"' in content
    assert "pyyaml>=6.0,<7.0" in content
