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

import pytest

from hrw4u.features import CALL_VALUE, check_target, ir_version_for, parse_ir_version, version_line


@pytest.mark.parametrize("text, version", [("1.0", (1, 0)), ("1.1", (1, 1))])
def test_parses_the_versions_hrw4u_so_reads(text, version):
    assert parse_ir_version(text) == version


@pytest.mark.parametrize("text", ["1.2", "2.0", "1", "v1.1"])
def test_refuses_another_version(text):
    with pytest.raises(ValueError, match=f"unknown IR version '{text}' \\(1.0, 1.1\\)"):
        parse_ir_version(text)


def test_version_line():
    assert version_line((1, 0)) == "hrw4u-ir 1.0"
    assert version_line((1, 1)) == "hrw4u-ir 1.1"


def test_a_program_needs_the_highest_version_its_features_do():
    assert ir_version_for(set()) == (1, 0)
    assert ir_version_for({CALL_VALUE}) == (1, 1)


def test_a_call_needs_ir_1_1():
    check_target(CALL_VALUE, (1, 1))
    with pytest.raises(ValueError) as err:
        check_target(CALL_VALUE, (1, 0))
    assert str(err.value) == "'a call to a library function' needs IR 1.1; the target is 1.0 (--ir-version)"


def test_a_call_has_no_conf_spelling():
    with pytest.raises(ValueError) as err:
        check_target(CALL_VALUE, None)
    assert str(err.value) == "'a call to a library function' has no .conf spelling; compile with --output ir"
