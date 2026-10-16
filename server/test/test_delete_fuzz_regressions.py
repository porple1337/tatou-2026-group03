import pytest
from sqlalchemy import text

from deletion_harness import deletion_api


@pytest.mark.parametrize("body", [True, [1], "1", 1])
def test_non_object_json_returns_client_error_without_side_effect(body):
    with deletion_api() as (client, headers, unchanged, _, __):
        response = client.post("/api/delete-document", json=body, headers=headers)
        assert response.status_code == 400
        unchanged()


@pytest.mark.parametrize("value", [True, False, 1.0, 1.5])
def test_coercible_non_integer_id_cannot_delete_owner_document(value):
    with deletion_api() as (client, headers, unchanged, _, __):
        response = client.post("/api/delete-document", json={"id": value}, headers=headers)
        assert response.status_code == 400
        unchanged()


@pytest.mark.parametrize("value", [2**64, 2**100])
def test_out_of_range_id_rejected_before_database(value):
    with deletion_api() as (client, headers, unchanged, _, __):
        response = client.post("/api/delete-document", json={"id": value}, headers=headers)
        assert response.status_code == 400
        unchanged()


@pytest.mark.parametrize("source", ["path", "query", "documentid", "body"])
def test_other_user_remains_unable_to_delete(source):
    with deletion_api(user_id=2) as (client, headers, unchanged, _, __):
        if source == "path":
            response = client.delete("/api/delete-document/1", headers=headers)
        elif source == "body":
            response = client.post("/api/delete-document", json={"id": 1}, headers=headers)
        else:
            key = "id" if source == "query" else "documentid"
            response = client.delete("/api/delete-document", query_string={key: 1}, headers=headers)
        assert response.status_code == 404
        unchanged()


def test_owner_can_still_delete_document():
    with deletion_api() as (client, headers, _, engine, document):
        response = client.delete("/api/delete-document/1", headers=headers)
        assert response.status_code == 200
        assert not document.exists()
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM Documents WHERE id=1")).scalar_one() == 0
