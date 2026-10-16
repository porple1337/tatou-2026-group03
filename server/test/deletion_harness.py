from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text


@contextmanager
def deletion_api(user_id=1):
    scratch_root = Path(__file__).resolve().parents[1] / "fuzz" / "results"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="tatou-fuzz-", dir=scratch_root) as directory:
        with patch.dict("os.environ", {"STORAGE_DIR": directory}):
            from server import create_app
            app = create_app()
        app.config.update(TESTING=True, SECRET_KEY="local-fuzz-fixture-only")
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
        app.config["_ENGINE"] = engine
        document = Path(directory) / "owner.pdf"
        original = b"%PDF-1.4\nDisposable fuzz fixture\n%%EOF\n"
        document.write_bytes(original)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE Documents (id INTEGER PRIMARY KEY, name TEXT, path TEXT, ownerid INTEGER)"))
            conn.execute(text("INSERT INTO Documents VALUES (1, 'owner.pdf', :path, 1)"), {"path": str(document)})
        token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth").dumps(
            {"uid": user_id, "login": "fixture", "email": "fixture@example.test"}
        )
        headers = {"Authorization": f"Bearer {token}"}

        def unchanged():
            with engine.connect() as conn:
                assert conn.execute(text("SELECT COUNT(*) FROM Documents WHERE id=1 AND ownerid=1")).scalar_one() == 1
            assert document.read_bytes() == original

        try:
            yield app.test_client(), headers, unchanged, engine, document
        finally:
            engine.dispose()
