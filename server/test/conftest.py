from collections import defaultdict
from html import escape
from pathlib import Path

import pytest
from flask import Flask, request as flask_request


def pytest_addoption(parser):
    parser.addoption(
        "--route-coverage",
        metavar="DIRECTORY",
        default=None,
        help="Write an HTML report showing API endpoints reached by passing tests",
    )


def pytest_configure(config):
    if not config.getoption("route_coverage"):
        return

    config._tatou_route_hits = defaultdict(set)
    config._tatou_passed_tests = set()
    config._tatou_current_test = None
    config._tatou_original_dispatch = Flask.dispatch_request

    def record_dispatch(app):
        endpoint = flask_request.endpoint
        if endpoint and config._tatou_current_test:
            config._tatou_route_hits[endpoint].add(config._tatou_current_test)
        return config._tatou_original_dispatch(app)

    Flask.dispatch_request = record_dispatch


def pytest_runtest_setup(item):
    if hasattr(item.config, "_tatou_route_hits"):
        item.config._tatou_current_test = item.nodeid


def pytest_runtest_teardown(item):
    if hasattr(item.config, "_tatou_route_hits"):
        item.config._tatou_current_test = None


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if hasattr(item.config, "_tatou_route_hits") and report.when == "call" and report.passed:
        item.config._tatou_passed_tests.add(item.nodeid)


def pytest_sessionfinish(session, exitstatus):
    config = session.config
    if not hasattr(config, "_tatou_route_hits"):
        return

    from server import app

    endpoint_rules = defaultdict(list)
    for rule in app.url_map.iter_rules():
        if rule.rule == "/healthz" or rule.rule.startswith("/api/"):
            methods = ", ".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
            endpoint_rules[rule.endpoint].append(f"{methods} {rule.rule}")

    rows = []
    covered = 0
    for endpoint in sorted(endpoint_rules):
        passing_tests = sorted(
            config._tatou_route_hits[endpoint] & config._tatou_passed_tests
        )
        if passing_tests:
            covered += 1
        paths = "<br>".join(escape(path) for path in sorted(endpoint_rules[endpoint]))
        tests = "<br>".join(escape(test) for test in passing_tests) or "—"
        state = "Covered" if passing_tests else "Not covered"
        rows.append(
            f"<tr><td>{escape(endpoint)}</td><td>{paths}</td>"
            f"<td class='{state.lower().replace(' ', '-')}'>{state}</td>"
            f"<td>{tests}</td></tr>"
        )

    total = len(endpoint_rules)
    result = "passed" if exitstatus == 0 else f"did not pass (pytest exit {exitstatus})"
    report_dir = Path(config.getoption("route_coverage"))
    report_dir.mkdir(parents=True, exist_ok=True)
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Tatou API route coverage</title>
<style>body{{font:16px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.55rem;text-align:left;vertical-align:top}}
th{{background:#eee}}.covered{{color:#12602f;font-weight:bold}}.not-covered{{color:#a11;font-weight:bold}}
td:last-child{{font-size:.85rem;overflow-wrap:anywhere}}</style></head><body>
<h1>Tatou API route coverage</h1>
<p><strong>{covered}/{total} endpoint handlers exercised by passing tests.</strong>
Full test suite: {escape(result)}.</p>
<table><thead><tr><th>Endpoint</th><th>Methods and paths</th><th>Status</th><th>Passing tests that reached it</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
    (report_dir / "index.html").write_text(html, encoding="utf-8")


def pytest_unconfigure(config):
    if hasattr(config, "_tatou_original_dispatch"):
        Flask.dispatch_request = config._tatou_original_dispatch
