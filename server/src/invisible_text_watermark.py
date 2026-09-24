from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Final

import fitz  # PyMuPDF

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class InvisibleTextWatermark(WatermarkingMethod):
    name: Final[str] = "invisible-text-v1"

    _MAGIC: Final[str] = "TATOU-WM1:"
    _CONTEXT: Final[bytes] = b"tatou:invisible-text:v1:"

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds an authenticated watermark as invisible text "
            "on every page of the PDF. Position is ignored."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        try:
            data = load_pdf_bytes(pdf)

            with fitz.open(stream=data, filetype="pdf") as document:
                return document.page_count > 0 and not document.needs_pass

        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:

        if not secret:
            raise ValueError("Secret must be a non-empty string")

        if not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        record = self._create_record(secret, key)

        try:
            with fitz.open(stream=data, filetype="pdf") as document:

                if document.page_count == 0:
                    raise WatermarkingError("PDF contains no pages")

                # Put the watermark on every page.
                for page in document:
                    page.insert_text(
                        fitz.Point(20, 20),
                        record,
                        fontsize=1,
                        fontname="helv",
                        render_mode=3,  # invisible text
                        overlay=True,
                    )

                return document.tobytes(
                    garbage=3,
                    deflate=True,
                )

        except WatermarkingError:
            raise
        except Exception as exc:
            raise WatermarkingError(
                "Failed to add invisible watermark"
            ) from exc

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:

        if not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        try:
            with fitz.open(stream=data, filetype="pdf") as document:

                for page in document:
                    text = page.get_text("text")

                    match = re.search(
                        rf"{re.escape(self._MAGIC)}([A-Za-z0-9_\-=]+)",
                        text,
                    )

                    if match:
                        return self._read_record(
                            match.group(1),
                            key,
                        )

        except InvalidKeyError:
            raise
        except Exception as exc:
            raise SecretNotFoundError(
                "Could not read watermark"
            ) from exc

        raise SecretNotFoundError(
            "No invisible watermark found"
        )

    def _create_record(
        self,
        secret: str,
        key: str,
    ) -> str:

        secret_bytes = secret.encode("utf-8")

        mac = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret_bytes,
            hashlib.sha256,
        ).hexdigest()

        payload = {
            "v": 1,
            "secret": base64.b64encode(
                secret_bytes
            ).decode("ascii"),
            "mac": mac,
        }

        payload_bytes = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")

        encoded = base64.urlsafe_b64encode(
            payload_bytes
        ).decode("ascii")

        return self._MAGIC + encoded

    def _read_record(
        self,
        encoded: str,
        key: str,
    ) -> str:

        try:
            payload_bytes = base64.urlsafe_b64decode(
                encoded.encode("ascii")
            )

            payload = json.loads(payload_bytes)

            secret_bytes = base64.b64decode(
                payload["secret"]
            )

            stored_mac = payload["mac"]

        except Exception as exc:
            raise SecretNotFoundError(
                "Malformed watermark"
            ) from exc

        expected_mac = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret_bytes,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            stored_mac,
            expected_mac,
        ):
            raise InvalidKeyError(
                "Incorrect watermark key"
            )

        return secret_bytes.decode("utf-8")