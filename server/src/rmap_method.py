from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from rmap import RMAPError, RMAPServer


class RMAPConfigurationError(RuntimeError):
    """Raised when RMAP key files or client identities are unavailable."""


class RMAPMessageError(ValueError):
    """Raised when a request is not a valid RMAP wire message."""


@dataclass(frozen=True)
class RMAPCompletion:
    """
    Result of a valid RMAP Message 2.

    `link` is for the server's internal PDF/database work.
    `response` is the encrypted Response 2 object sent to the client.
    """

    identity: str
    link: str
    response: dict[str, str]


class RMAPService:
    """
    Thin wrapper around the course RMAP library.

    It handles the protocol only. Flask/database/PDF creation belongs in
    server.py.
    """

    _LINK_PATTERN = re.compile(r"[0-9a-f]{32}")

    def __init__(
        self,
        *,
        server_public_key: str | Path,
        server_private_key: str | Path,
        client_keys_dir: str | Path,
        passphrase: str | None = None,
    ) -> None:
        public_key_path = Path(server_public_key)
        private_key_path = Path(server_private_key)
        identities_path = Path(client_keys_dir)

        self._validate_paths(
            public_key_path,
            private_key_path,
            identities_path,
        )

        self._server = RMAPServer(
            server_public_key_path=str(public_key_path),
            server_private_key_path=str(private_key_path),
            passphrase=passphrase,
            # Section 5 specifies the bare 32-character link.
            linkPrefix="",
            verbose=False,
        )

        # Registers Group_01.asc as identity "Group_01", etc.
        self._server.loadIdentities(str(identities_path))

        # The RMAP server keeps handshake state in memory.
        self._lock = Lock()

    def initiate(self, message: object) -> dict[str, str]:
        """
        Process RMAP Message 1.

        Input:
            {"payload": "<encrypted PGP message>"}

        Output:
            {"payload": "<encrypted Response 1>"}
        """
        wire_message = self._validate_message(message)

        with self._lock:
            _identity, response = self._server.receiveMsg1(wire_message)

        return dict(response)

    def complete(self, message: object) -> RMAPCompletion:
        """
        Process RMAP Message 2.

        The caller must create and record the watermarked PDF before it sends
        `completion.response` to the client.
        """
        wire_message = self._validate_message(message)

        with self._lock:
            identity, link, response = self._server.receiveMsg2(wire_message)

        if not isinstance(identity, str) or not identity:
            raise RMAPMessageError("RMAP returned an invalid identity")

        if not isinstance(link, str) or not self._LINK_PATTERN.fullmatch(link):
            raise RMAPMessageError("RMAP returned an invalid link")

        return RMAPCompletion(
            identity=identity,
            link=link,
            response=dict(response),
        )

    @staticmethod
    def _validate_message(message: object) -> dict[str, str]:
        """
        Require exactly the Section 5 RMAP wire format:

        {"payload": "<base64 PGP armor body>"}
        """
        if not isinstance(message, Mapping):
            raise RMAPMessageError("Request body must be a JSON object")

        if set(message.keys()) != {"payload"}:
            raise RMAPMessageError(
                "Request body must contain only the 'payload' field"
            )

        payload = message.get("payload")
        if not isinstance(payload, str) or not payload.strip():
            raise RMAPMessageError(
                "'payload' must be a non-empty string"
            )

        return {"payload": payload}

    @staticmethod
    def _validate_paths(
        public_key_path: Path,
        private_key_path: Path,
        identities_path: Path,
    ) -> None:
        if not public_key_path.is_file():
            raise RMAPConfigurationError(
                f"Server public key not found: {public_key_path}"
            )

        if not private_key_path.is_file():
            raise RMAPConfigurationError(
                f"Server private key not found: {private_key_path}"
            )

        if not identities_path.is_dir():
            raise RMAPConfigurationError(
                f"Client key directory not found: {identities_path}"
            )

        if not any(identities_path.glob("*.asc")):
            raise RMAPConfigurationError(
                f"No client public keys found in: {identities_path}"
            )


__all__ = [
    "RMAPCompletion",
    "RMAPConfigurationError",
    "RMAPError",
    "RMAPMessageError",
    "RMAPService",
]