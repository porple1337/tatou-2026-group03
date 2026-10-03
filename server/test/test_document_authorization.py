from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text

from server import create_app


def _bearer_token(app, *, user_id: int, login: str) -> str:
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps(
        {"uid": user_id, "login": login, "email": f"{login}@example.test"}
    )
    return f"Bearer {token}"


def test_user_cannot_delete_another_users_document(tmp_path):
    """A valid token must not authorize deletion of another user's document."""
    app = create_app()
    app.config.update(TESTING=True, STORAGE_DIR=tmp_path)

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE Documents (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    ownerid INTEGER NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO Documents (id, name, path, ownerid)
                VALUES (:id, :name, :path, :ownerid)
                """
            ),
            {
                "id": 42,
                "name": "owner-document.pdf",
                "path": str(tmp_path / "owner-document.pdf"),
                "ownerid": 1,
            },
        )

    app.config["_ENGINE"] = engine
    client = app.test_client()

    response = client.delete(
        "/api/delete-document/42",
        headers={"Authorization": _bearer_token(app, user_id=2, login="other-user")},
    )

    assert response.status_code == 404
    assert response.get_json() == {"error": "document not found"}

    with engine.connect() as conn:
        remaining = conn.execute(
            text("SELECT COUNT(*) FROM Documents WHERE id = :id"), {"id": 42}
        ).scalar_one()

    assert remaining == 1
