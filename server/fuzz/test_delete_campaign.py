import json
from hypothesis import example, given, settings, strategies as st
from deletion_harness import deletion_api

campaign = settings(max_examples=250, deadline=None, database=None)
scalar = st.one_of(st.none(), st.booleans(), st.integers(),
                   st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=80))
non_objects = st.one_of(scalar, st.lists(scalar, max_size=5))


def rejected(body, *, user_id=1, status=400):
    with deletion_api(user_id) as (client, headers, unchanged, _, __):
        response = client.post("/api/delete-document", data=json.dumps(body),
                               content_type="application/json", headers=headers)
        assert response.status_code == status, response.get_data(as_text=True)
        assert response.is_json
        unchanged()


@campaign
@example(True)
@example([1])
@given(non_objects)
def test_json_body_must_be_object(body):
    rejected(body)


@campaign
@example(True)
@example(1.0)
@given(st.one_of(st.booleans(), st.floats(min_value=0, max_value=3,
                                        allow_nan=False, allow_infinity=False)))
def test_boolean_and_float_ids_are_not_document_identifiers(value):
    rejected({"id": value})


@campaign
@given(st.integers(min_value=2**64, max_value=2**100))
def test_oversized_ids_rejected_before_database(value):
    rejected({"id": value})


@campaign
@given(st.sampled_from(["path", "query", "documentid", "body"]),
       st.sampled_from(["POST", "DELETE"]))
def test_other_user_cannot_delete(source, verb):
    with deletion_api(2) as (client, headers, unchanged, _, __):
        if source == "path":
            response = client.delete("/api/delete-document/1", headers=headers)
        elif source == "body":
            response = client.open("/api/delete-document", method=verb, json={"id": 1}, headers=headers)
        else:
            key = "id" if source == "query" else "documentid"
            response = client.open("/api/delete-document", method=verb, query_string={key: "1"}, headers=headers)
        assert response.status_code == 404
        unchanged()
