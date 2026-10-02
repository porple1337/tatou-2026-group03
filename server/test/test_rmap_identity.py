"""FIA_UID.2: reject an unregistered identity during RMAP initiation."""

import pytest

from rmap.client import RMAPClient
from rmap.keygen import generate_keypair
from server import create_app


@pytest.fixture
def rmap_setup(tmp_path, monkeypatch):
    # Generate disposable keys exclusively for this test.
    server_key = generate_keypair(
        "Test Server", "server@example.invalid"
    )
    client_key = generate_keypair(
        "Registered_Test_Group", "client@example.invalid"
    )

    server_private = tmp_path / "server_private.asc"
    server_public = tmp_path / "server_public.asc"
    client_private = tmp_path / "client_private.asc"
    identities_dir = tmp_path / "identities"
    identities_dir.mkdir()

    server_private.write_text(str(server_key), encoding="utf-8")
    server_public.write_text(str(server_key.pubkey), encoding="utf-8")
    client_private.write_text(str(client_key), encoding="utf-8")

    # The filename stem determines the registered identity.
    (identities_dir / "Registered_Test_Group.asc").write_text(
        str(client_key.pubkey), encoding="utf-8"
    )

    monkeypatch.setenv("RMAP_SERVER_PRIVATE_KEY", str(server_private))
    monkeypatch.setenv("RMAP_SERVER_PUBLIC_KEY", str(server_public))
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(identities_dir))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.delenv("RMAP_SERVER_PASSPHRASE", raising=False)

    app = create_app()
    app.config["TESTING"] = True

    return app.test_client(), client_private, server_public


def test_rmap_rejects_unregistered_identity(rmap_setup):
    http_client, client_private, server_public = rmap_setup
    print("\nFIA_UID.2: identity registration at RMAP initiation")
    print("Environment: isolated Flask test client, real RMAP encryption, temporary keys")

    def protocol_client(identity):
        return RMAPClient(
            identity=identity,
            client_private_key_path=str(client_private),
            server_public_key_path=str(server_public),
        )

    def assert_registered_identity_works(label):
        print(f"\n{label}")
        print("POST /api/rmap-initiate | identity=Registered_Test_Group")
        registered = protocol_client("Registered_Test_Group")
        response = http_client.post(
            "/api/rmap-initiate",
            json=registered.build_msg1(),
        )

        print(f"Expected HTTP 200; received HTTP {response.status_code}")
        assert response.status_code == 200, response.get_data(as_text=True)
        body = response.get_json()
        assert isinstance(body, dict)
        assert set(body) == {"payload"}

        # Decrypt the challenge and validate the echoed client nonce.
        nonce_client, nonce_server = registered.process_resp1(body)
        assert nonce_client == registered.nonceClient
        assert type(nonce_server) is int
        assert 0 <= nonce_server < 2**64
        print("PASS: challenge decrypted, client nonce matched, server nonce is uint64")

    # Positive control: the keys and encryption setup work.
    assert_registered_identity_works("[1/3] Registered identity: positive control")

    # Same encryption setup, but this identity is not registered.
    unregistered = protocol_client("Unregistered_Test_Group")
    print("\n[2/3] Unregistered identity: same keys, different identity name")
    print("POST /api/rmap-initiate | identity=Unregistered_Test_Group")
    response = http_client.post(
        "/api/rmap-initiate",
        json=unregistered.build_msg1(),
    )

    print(f"Expected HTTP 400; received HTTP {response.status_code}")
    print(f"Response: {response.get_data(as_text=True).strip()}")
    assert response.status_code == 400, response.get_data(as_text=True)
    assert response.get_json() == {
        "error": "Invalid RMAP Message 1"
    }
    print("PASS: unregistered identity rejected; no challenge payload returned")

    # Confirm rejection did not leave initiation generally unusable.
    assert_registered_identity_works("[3/3] Registered identity still works after rejection")
    print("\nScope: initiation only; full handshake and document access are not tested.")
