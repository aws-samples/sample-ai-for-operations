# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The demo engine builds its statements from validated names."""

import pytest

from network_flow_insight.demo import duck


def test_statement_helpers_build_the_expected_text():
    assert duck._create_schema_sql("nfi") == "CREATE SCHEMA IF NOT EXISTS nfi"
    assert duck._create_table_sql("nfi.flow_logs", "SELECT 1") == "CREATE TABLE nfi.flow_logs AS SELECT 1"
    assert duck._ctas_sql("nfi.agg_1", "SELECT 2") == "CREATE OR REPLACE TABLE nfi.agg_1 AS SELECT 2"
    assert duck._count_sql("nfi.agg_1") == "SELECT COUNT(*) FROM nfi.agg_1"
    assert duck._count_sql("agg_1") == "SELECT COUNT(*) FROM agg_1"


@pytest.mark.parametrize(
    "bad", ["t; drop table x", "a.b.c; --", "x y", "a..b", "", "a.", ".b", "t'", "t\"", "a-b", "1abc"]
)
def test_statement_helpers_reject_unsafe_names(bad):
    with pytest.raises(ValueError):
        duck._create_schema_sql(bad)
    with pytest.raises(ValueError):
        duck._create_table_sql(bad, "SELECT 1")
    with pytest.raises(ValueError):
        duck._ctas_sql(bad, "SELECT 1")
    with pytest.raises(ValueError):
        duck._count_sql(bad)
