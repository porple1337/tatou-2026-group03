from __future__ import annotations

import base64
import hashlib
import hmac
import json

try:
    import pymupdf
except ImportError:
    import fitz as pymupdf

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class erik_watermark(WatermarkingMethod):
    name = "erik-watermark"

    ATTACHMENT_NAME = "erik_watermark.json"
    CONTEXT = b"tatou:erik-watermark:v1:"

    @staticmethod
    def get_usage() -> str:
        return "Stores an HMAC-protected watermark as a PDF attachment."

    def add_watermark(self, pdf, secret, key, position=None) -> bytes:
        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        doc = None
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")

            if self.ATTACHMENT_NAME in doc.embfile_names():
                raise WatermarkingError("PDF already contains an Erik watermark")

            secret_bytes = secret.encode("utf-8")
            mac = hmac.new(
                key.encode("utf-8"),
                self.CONTEXT + secret_bytes,
                hashlib.sha256,
            ).hexdigest()

            payload = {
                "version": 1,
                "secret": base64.b64encode(secret_bytes).decode("ascii"),
                "mac": mac,
            }

            doc.embfile_add(
                self.ATTACHMENT_NAME,
                json.dumps(payload).encode("utf-8"),
                filename=self.ATTACHMENT_NAME,
                desc="Erik watermark",
            )

            return doc.tobytes(deflate=True)

        except (ValueError, WatermarkingError):
            raise
        except Exception as exc:
            raise WatermarkingError("Could not add watermark") from exc
        finally:
            if doc is not None:
                doc.close()

    def is_watermark_applicable(self, pdf, position=None) -> bool:
        doc = None
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")

            return (
                doc.is_pdf
                and not doc.needs_pass
                and self.ATTACHMENT_NAME not in doc.embfile_names()
            )
        except Exception:
            return False
        finally:
            if doc is not None:
                doc.close()

    def read_secret(self, pdf, key) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        doc = None
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")

            if self.ATTACHMENT_NAME not in doc.embfile_names():
                raise SecretNotFoundError("No Erik watermark found")

            raw_payload = doc.embfile_get(self.ATTACHMENT_NAME)
            payload = json.loads(raw_payload.decode("utf-8"))

            secret_bytes = base64.b64decode(payload["secret"], validate=True)
            stored_mac = payload["mac"]

            expected_mac = hmac.new(
                key.encode("utf-8"),
                self.CONTEXT + secret_bytes,
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(stored_mac, expected_mac):
                raise InvalidKeyError("Incorrect key or altered watermark")

            return secret_bytes.decode("utf-8")

        except (InvalidKeyError, SecretNotFoundError, ValueError):
            raise
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SecretNotFoundError("Invalid watermark payload") from exc
        except Exception as exc:
            raise WatermarkingError("Could not read watermark") from exc
        finally:
            if doc is not None:
                doc.close()