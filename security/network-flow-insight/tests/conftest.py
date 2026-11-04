# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import pytest

from network_flow_insight.config import Settings
from network_flow_insight.demo import estate as E
from network_flow_insight.demo.generator import generate
from network_flow_insight.demo.runner import build_analysis, build_backend

pytest_plugins: list[str] = []


@pytest.fixture(scope="session")
def estates(tmp_path_factory):
    """One generated estate per tier, shared by the whole session (generation is deterministic)."""
    return {t: generate(tmp_path_factory.mktemp(f"estate-{t}"), t) for t in ("basic", "enhanced", "full")}


@pytest.fixture
def settings():
    return Settings(aws_region=E.REGION)


@pytest.fixture
def make_analysis(estates, settings):
    from network_flow_insight.analysis import Analysis

    def factory(tier="full", **kw):
        est = estates[tier]
        s = kw.pop("settings", settings)
        return Analysis(s, build_backend(est, s, **kw)), est

    return factory


@pytest.fixture
def full(make_analysis):
    return make_analysis("full")


@pytest.fixture(scope="session")
def full_findings(estates):
    s = Settings(aws_region=E.REGION)
    from network_flow_insight.analysis import Analysis

    est = estates["full"]
    a = Analysis(s, build_backend(est, s))
    return a, est, a.describe(*E.WINDOW_B)


__all__ = ["build_analysis"]
