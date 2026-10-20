import hashlib
import io

import pytest
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, event, text
from sqlalchemy.pool import StaticPool
from werkzeug.security import generate_password_hash

import server as server_module
from rmap_method import RMAPCompletion


@pytest.fixture
def api(tmp_path, monkeypatch):
    storage = tmp_path / "storage"
    monkeypatch.setenv("STORAGE_DIR", str(storage))
    monkeypatch.setenv("SECRET_KEY", "route-tests-only-secret")
    app = server_module.create_app()
    app.config["TESTING"] = True

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(engine, "connect")
    def sqlite_functions(dbapi_connection, _):
        dbapi_connection.create_function(
            "HEX", 1, lambda value: value.hex().upper() if value is not None else None
        )
        dbapi_connection.create_function(
            "UNHEX", 1, lambda value: bytes.fromhex(value) if value is not None else None
        )

    @event.listens_for(engine, "before_cursor_execute", retval=True)
    def last_insert_id(_conn, _cursor, statement, parameters, _context, _executemany):
        return statement.replace("LAST_INSERT_ID()", "last_insert_rowid()"), parameters

    app.config["_ENGINE"] = engine
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Users (
                id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                hpassword TEXT NOT NULL, login TEXT NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL,
                ownerid INTEGER NOT NULL, creation TEXT DEFAULT CURRENT_TIMESTAMP,
                sha256 BLOB NOT NULL, size INTEGER NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY, documentid INTEGER NOT NULL,
                link TEXT UNIQUE NOT NULL, intended_for TEXT, secret TEXT NOT NULL,
                method TEXT NOT NULL, position TEXT, path TEXT NOT NULL
            )
        """))
        conn.execute(
            text("INSERT INTO Users VALUES (1, :email, :password, :login)"),
            {
                "email": "owner@example.test",
                "password": generate_password_hash("owner-password"),
                "login": "owner",
            },
        )
        conn.execute(
            text("INSERT INTO Users VALUES (2, :email, :password, :login)"),
            {
                "email": "other@example.test",
                "password": generate_password_hash("other-password"),
                "login": "other",
            },
        )

    document = storage / "files" / "1" / "owner.pdf"
    document.parent.mkdir(parents=True)
    pdf_bytes = b"%PDF-1.4\nroute test fixture\n%%EOF\n"
    document.write_bytes(pdf_bytes)
    version = storage / "files" / "1" / "version.pdf"
    version.write_bytes(pdf_bytes)
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO Documents (id, name, path, ownerid, sha256, size)
                VALUES (1, 'owner.pdf', :path, 1, :digest, :size)
            """),
            {"path": str(document), "digest": hashlib.sha256(pdf_bytes).digest(), "size": len(pdf_bytes)},
        )
        conn.execute(
            text("""
                INSERT INTO Versions
                    (id, documentid, link, intended_for, secret, method, position, path)
                VALUES (1, 1, 'existing-version', 'recipient', 'fixture-secret',
                        'fixture-method', '', :path)
            """),
            {"path": str(version)},
        )

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def headers(user_id=1, login="owner"):
        token = serializer.dumps(
            {"uid": user_id, "login": login, "email": f"{login}@example.test"}
        )
        return {"Authorization": f"Bearer {token}"}

    yield app, app.test_client(), engine, storage, document, headers
    engine.dispose()


def test_create_user_and_login_routes(api):
    _, client, engine, _, _, _ = api
    created = client.post(
        "/api/create-user",
        json={"email": "new@example.test", "login": "new", "password": "new-password"},
    )
    assert created.status_code == 201
    assert created.get_json()["email"] == "new@example.test"
    with engine.connect() as conn:
        stored = conn.execute(
            text("SELECT hpassword FROM Users WHERE email = 'new@example.test'")
        ).scalar_one()
    assert stored != "new-password"

    logged_in = client.post(
        "/api/login", json={"email": "new@example.test", "password": "new-password"}
    )
    assert logged_in.status_code == 200
    assert logged_in.get_json()["token_type"] == "bearer"
    assert client.post(
        "/api/login", json={"email": "new@example.test", "password": "wrong"}
    ).status_code == 401


def test_upload_document_route(api):
    _, client, engine, storage, _, headers = api
    assert client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(b"not a PDF"), "bad.pdf")},
        headers=headers(),
    ).status_code == 400

    response = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(b"%PDF-1.4\nnew\n%%EOF\n"), "new.pdf")},
        headers=headers(),
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    document_id = response.get_json()["id"]
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT ownerid, path FROM Documents WHERE id = :id"), {"id": document_id}
        ).one()
    assert row.ownerid == 1
    assert row.path.startswith(str(storage))
    assert row.path.endswith(".pdf")


def test_document_and_version_listing_routes(api):
    _, client, _, _, _, headers = api
    docs = client.get("/api/list-documents", headers=headers())
    assert docs.status_code == 200
    assert [item["id"] for item in docs.get_json()["documents"]] == [1]

    versions = client.get("/api/list-versions/1", headers=headers())
    assert versions.status_code == 200
    assert [item["link"] for item in versions.get_json()["versions"]] == ["existing-version"]
    assert client.get("/api/list-versions?id=1", headers=headers()).status_code == 200

    all_versions = client.get("/api/list-all-versions", headers=headers())
    assert all_versions.status_code == 200
    assert [item["link"] for item in all_versions.get_json()["versions"]] == ["existing-version"]

    # A second valid user must not see the owner's documents or versions.
    other = headers(2, "other")
    assert client.get("/api/list-documents", headers=other).get_json() == {"documents": []}
    assert client.get("/api/list-versions/1", headers=other).get_json() == {"versions": []}
    assert client.get("/api/list-all-versions", headers=other).get_json() == {"versions": []}


def test_get_document_and_public_version_routes(api):
    _, client, _, _, document, headers = api
    response = client.get("/api/get-document/1", headers=headers())
    assert response.status_code == 200
    assert response.data == document.read_bytes()
    assert response.headers["Cache-Control"].startswith("private")
    assert client.get("/api/get-document?id=1", headers=headers()).status_code == 200
    assert client.get("/api/get-document/1", headers=headers(2, "other")).status_code == 404

    version = client.get("/api/get-version/existing-version")
    assert version.status_code == 200
    assert version.data == document.read_bytes()
    assert client.get("/api/get-version/no-such-link").status_code == 404


def test_rmap_get_link_issues_one_disposable_version(api, monkeypatch):
    app, client, engine, storage, _, _ = api
    link = "a" * 32

    class CompletedHandshake:
        def complete(self, message):
            assert message == {"payload": "test-message-2"}
            return RMAPCompletion("Test_Group", link, {"payload": "encrypted-response"})

    app.extensions["rmap_service"] = CompletedHandshake()
    monkeypatch.setenv("RMAP_SOURCE_DOCUMENT_ID", "1")
    monkeypatch.setenv("RMAP_WATERMARK_METHOD", "fixture-method")
    monkeypatch.setenv("RMAP_WATERMARK_KEY", "fixture-key")
    monkeypatch.setattr(server_module.WMUtils, "is_watermarking_applicable", lambda **_: True)
    monkeypatch.setattr(
        server_module.WMUtils, "apply_watermark", lambda **_: b"%PDF-1.4\nRMAP fixture\n%%EOF\n"
    )

    response = client.post("/api/rmap-get-link", json={"payload": "test-message-2"})
    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.get_json() == {"payload": "encrypted-response"}
    assert (storage / "rmap_versions" / f"{link}.pdf").is_file()
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT documentid, intended_for, link FROM Versions WHERE link = :link"),
            {"link": link},
        ).one()
    assert (row.documentid, row.intended_for, row.link) == (1, "Test_Group", link)


def test_create_and_read_watermark_routes(api, monkeypatch):
    _, client, engine, _, _, headers = api
    monkeypatch.setattr(server_module.WMUtils, "is_watermarking_applicable", lambda **_: True)
    monkeypatch.setattr(
        server_module.WMUtils, "apply_watermark", lambda **_: b"%PDF-1.4\nwatermark fixture\n%%EOF\n"
    )
    monkeypatch.setattr(server_module.WMUtils, "read_watermark", lambda **_: "fixture-secret")
    body = {
        "method": "fixture-method", "intended_for": "reader",
        "secret": "fixture-secret", "key": "fixture-key",
    }
    assert client.post(
        "/api/create-watermark/1", json=body, headers=headers(2, "other")
    ).status_code == 404
    created = client.post("/api/create-watermark/1", json=body, headers=headers())
    assert created.status_code == 201, created.get_data(as_text=True)
    link = created.get_json()["link"]
    with engine.connect() as conn:
        assert conn.execute(
            text("SELECT COUNT(*) FROM Versions WHERE link = :link"), {"link": link}
        ).scalar_one() == 1

    assert client.post(
        "/api/read-watermark/1",
        json={"method": "fixture-method", "key": "fixture-key"},
        headers=headers(2, "other"),
    ).status_code == 404
    read = client.post(
        "/api/read-watermark/1",
        json={"method": "fixture-method", "key": "fixture-key"},
        headers=headers(),
    )
    # The current API uses 201 for this read operation.
    assert read.status_code == 201
    assert read.get_json()["secret"] == "fixture-secret"


def test_plugin_and_method_listing_routes(api):
    _, client, _, _, _, headers = api

    before = client.get("/api/get-watermarking-methods")
    assert before.status_code == 200

    # Without a token, the request is rejected as unauthenticated.
    unauthenticated = client.post(
        "/api/load-plugin", json={"filename": "anything.pkl"}
    )
    assert unauthenticated.status_code == 401

    # Even an authenticated user cannot load a plugin in this version.
    disabled = client.post(
        "/api/load-plugin",
        json={"filename": "anything.pkl"},
        headers=headers(),
    )
    assert disabled.status_code == 403
    assert disabled.get_json() == {"error": "Plugin loading is disabled"}

    # The rejected request must not change the registered methods.
    after = client.get("/api/get-watermarking-methods")
    assert after.status_code == 200
    assert after.get_json() == before.get_json()
    assert after.get_json()["count"] == len(after.get_json()["methods"])
