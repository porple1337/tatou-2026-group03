from typing import Final
import base64
import hashlib

import pymupdf

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from watermarking_method import (
    PdfSource,
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


MAX_SECRET_LENGTH = 1024
MAX_KEY_LENGTH = 256
MIN_KEY_LENGTH = 8

MAX_PDF_SIZE = 10 * 1024 * 1024
MAX_PDF_PAGES = 500


class OmarWatermark(WatermarkingMethod):
    name: Final[str] = "omar-watermark"

    _MAGIC: Final[bytes] = b"\n%%WM-OMAR-AESSIV:v1\n"
    _CONTEXT: Final[bytes] = b"tatou:omar-watermark:v1"

    @staticmethod
    def get_usage() -> str:
        return (
            "Encrypts and authenticates the secret using AES-SIV. "
            "The position parameter is ignored."
        )

    @staticmethod
    def _validate_inputs(secret: str, key: str) -> None:
        if not isinstance(secret, str):
            raise ValueError("Secret must be a string")

        if not secret:
            raise ValueError("Secret must not be empty")

        if len(secret) > MAX_SECRET_LENGTH:
            raise ValueError("Secret is too long")

        OmarWatermark._validate_key(key)

    @staticmethod
    def _validate_key(key: str) -> None:
        if not isinstance(key, str):
            raise ValueError("Key must be a string")

        if len(key) < MIN_KEY_LENGTH:
            raise ValueError("Key is too short")

        if len(key) > MAX_KEY_LENGTH:
            raise ValueError("Key is too long")

    @staticmethod
    def _load_and_validate_pdf(pdf: PdfSource) -> bytes:
        data = load_pdf_bytes(pdf)

        if len(data) > MAX_PDF_SIZE:
            raise ValueError("PDF is too large")

        try:
            doc = pymupdf.open(
                stream=data,
                filetype="pdf",
            )
        except Exception as exc:
            raise ValueError("Could not open PDF") from exc

        try:
            if doc.needs_pass:
                raise ValueError(
                    "Password-protected PDFs are not supported"
                )

            if doc.page_count == 0:
                raise ValueError("PDF contains no pages")

            if doc.page_count > MAX_PDF_PAGES:
                raise ValueError("PDF contains too many pages")

        finally:
            doc.close()

        return data

    @classmethod
    def _derive_key(
        cls,
        key: str,
        original_pdf: bytes,
    ) -> bytes:
        pdf_hash = hashlib.sha256(original_pdf).digest()

        salt = hashlib.sha256(
            cls._CONTEXT + pdf_hash
        ).digest()[:16]

        kdf = Scrypt(
            salt=salt,
            length=64,
            n=2**14,
            r=8,
            p=1,
        )

        return kdf.derive(key.encode("utf-8"))

    @classmethod
    def _associated_data(
        cls,
        original_pdf: bytes,
    ) -> list[bytes]:
        pdf_hash = hashlib.sha256(original_pdf).digest()

        return [
            cls._CONTEXT,
            pdf_hash,
        ]

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        self._validate_inputs(secret, key)

        data = self._load_and_validate_pdf(pdf)

        if self._MAGIC in data:
            raise WatermarkingError(
                "PDF already contains an Omar watermark"
            )

        encryption_key = self._derive_key(
            key,
            data,
        )

        cipher = AESSIV(encryption_key)

        ciphertext = cipher.encrypt(
            secret.encode("utf-8"),
            self._associated_data(data),
        )

        encoded_payload = base64.urlsafe_b64encode(
            ciphertext
        )

        return (
            data
            + self._MAGIC
            + encoded_payload
            + b"\n"
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        try:
            data = self._load_and_validate_pdf(pdf)
        except (ValueError, TypeError):
            return False

        return self._MAGIC not in data

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:
        self._validate_key(key)

        data = load_pdf_bytes(pdf)

        marker_index = data.rfind(self._MAGIC)

        if marker_index == -1:
            raise SecretNotFoundError(
                "No Omar watermark found"
            )

        original_pdf = data[:marker_index]

        payload_start = (
            marker_index + len(self._MAGIC)
        )

        payload_end = data.find(
            b"\n",
            payload_start,
        )

        if payload_end == -1:
            payload_end = len(data)

        encoded_payload = data[
            payload_start:payload_end
        ].strip()

        if not encoded_payload:
            raise SecretNotFoundError(
                "Watermark payload is empty"
            )

        try:
            ciphertext = base64.b64decode(
                encoded_payload,
                altchars=b"-_",
                validate=True,
            )
        except Exception as exc:
            raise SecretNotFoundError(
                "Watermark payload is malformed"
            ) from exc

        encryption_key = self._derive_key(
            key,
            original_pdf,
        )

        cipher = AESSIV(encryption_key)

        try:
            plaintext = cipher.decrypt(
                ciphertext,
                self._associated_data(original_pdf),
            )
        except InvalidTag as exc:
            raise InvalidKeyError(
                "Incorrect key or modified watermark"
            ) from exc

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WatermarkingError(
                "Decrypted watermark is not valid UTF-8"
            ) from exc


__all__ = ["OmarWatermark"]