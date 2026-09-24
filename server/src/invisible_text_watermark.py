from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import ClassVar, Final

import pymupdf as fitz

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class InvisibleTextWatermark(WatermarkingMethod):
    """
    Watermarking method that embeds an authenticated secret as
    invisible text inside the PDF page content.

    The watermark is inserted on every page. It is not visible when
    rendering the PDF, but can be extracted again using read_secret().
    """

    name: ClassVar[str] = "invisible-text-v1"

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
        """
        Return True if the PDF can be opened, contains at least one page,
        and does not require a password.
        """
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
        """
        Embed the secret as invisible text on every page.

        The secret is stored together with an HMAC-SHA256 value so that
        read_secret() can detect whether the correct key was provided.
        """

        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        record = self._create_record(secret, key)

        try:
            with fitz.open(stream=data, filetype="pdf") as document:

                if document.page_count == 0:
                    raise WatermarkingError("PDF contains no pages")

                if document.needs_pass:
                    raise WatermarkingError(
                        "Password-protected PDFs are not supported"
                    )

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
        """
        Locate the invisible watermark and return the embedded secret.

        Raises InvalidKeyError if the watermark exists but the key
        does not match.
        """

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        try:
            with fitz.open(stream=data, filetype="pdf") as document:

                if document.needs_pass:
                    raise WatermarkingError(
                        "Password-protected PDFs are not supported"
                    )

                for page in document:
                    text = page.get_text("text")

                    match = re.search(
                        rf"{re.escape(self._MAGIC)}"
                        rf"([A-Za-z0-9_\-=]+)",
                        text,
                    )

                    if match:
                        return self._read_record(
                            match.group(1),
                            key,
                        )

        except InvalidKeyError:
            raise

        except SecretNotFoundError:
            raise

        except WatermarkingError:
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
        """
        Create the encoded watermark record.

        Format:

            TATOU-WM1:<base64url(JSON)>

        The JSON contains:
            version
            secret
            HMAC
        """

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
            sort_keys=True,
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
        """
        Decode and verify a watermark record.
        """

        try:
            payload_bytes = base64.urlsafe_b64decode(
                encoded.encode("ascii")
            )

            payload = json.loads(
                payload_bytes.decode("utf-8")
            )

            if payload.get("v") != 1:
                raise SecretNotFoundError(
                    "Unsupported watermark version"
                )

            encoded_secret = payload.get("secret")
            stored_mac = payload.get("mac")

            if not isinstance(encoded_secret, str):
                raise SecretNotFoundError(
                    "Malformed watermark"
                )

            if not isinstance(stored_mac, str):
                raise SecretNotFoundError(
                    "Malformed watermark"
                )

            secret_bytes = base64.b64decode(
                encoded_secret
            )

        except SecretNotFoundError:
            raise

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

        try:
            return secret_bytes.decode("utf-8")

        except UnicodeDecodeError as exc:
            raise SecretNotFoundError(
                "Watermark contains invalid secret data") from exc