# test/unit/spiderfoot/test_api_scan_data_regression.py
"""Regression tests for scan-data API endpoints (bug-hunt pass)."""
import pytest

from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app


@pytest.fixture
def db_path(tmp_path):
    # A real file (not :memory:) so the seeding handle and the request's
    # get_db() handle share the same database.
    return str(tmp_path / "regression.db")


@pytest.fixture
def app(db_path):
    app = create_app(config={'__database': db_path, '__modules__': {}})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_scan_with_error(db_path, scan_id="regr-scan-1"):
    dbh = SpiderFootDb({'__database': db_path})
    dbh.scanInstanceCreate(scan_id, "Regression Scan", "example.com")
    dbh.scanLogEvent(scan_id, "ERROR", "deliberate test error", component="sfp_test")
    return scan_id


class TestScanErrorsRegression:
    def test_scanerrors_returns_seeded_error_without_limit(self, client, db_path):
        """Regression: the route read `limit` as None and passed it to
        scanErrors(), which requires an int and raised TypeError — caught by
        the bare except — so /api/scanerrors ALWAYS returned []. With the fix
        (limit defaults to 0/int) the seeded error must come back."""
        scan_id = _seed_scan_with_error(db_path)
        resp = client.get(f'/api/scanerrors?id={scan_id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) >= 1, "scanerrors returned [] — the limit-coercion regression is back"

    def test_scanerrors_honours_explicit_limit(self, client, db_path):
        """A string limit from the query string must be coerced to int, not
        raise TypeError and get swallowed."""
        scan_id = _seed_scan_with_error(db_path)
        resp = client.get(f'/api/scanerrors?id={scan_id}&limit=10')
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_scanerrors_bad_limit_does_not_500(self, client, db_path):
        """A non-numeric limit must degrade to 0, not crash."""
        scan_id = _seed_scan_with_error(db_path)
        resp = client.get(f'/api/scanerrors?id={scan_id}&limit=notanumber')
        assert resp.status_code == 200


class TestScanEventResultsRegression:
    def test_scaneventresults_accepts_filterfp_without_error(self, client, db_path):
        """Regression: `filterfp` was passed into the `srcModule` positional
        slot of scanResultEvent(). Sending filterfp=1 must not crash and must
        return a JSON list (empty is fine — no events seeded)."""
        dbh = SpiderFootDb({'__database': db_path})
        dbh.scanInstanceCreate("regr-scan-2", "Regression Scan 2", "example.com")
        resp = client.get('/api/scaneventresults?id=regr-scan-2&filterfp=1')
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
