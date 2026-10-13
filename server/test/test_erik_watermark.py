import base64
import json

import pymupdf
import pytest

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
)
from watermarking_methods.erik_watermark import erik_watermark

@pytest.fixture
def method():
    return erik_watermark()

@pytest.fixture
def pdf_bytes():
    with pymupdf.open() as doc:
        for text in ("First page content", "Second page content"):
            page = doc.new_page()
            page.insert_text((72, 72), text)
        return doc.tobytes()


@pytest.mark.parametrize("secret", ["test-secret", "Hemlighet: åäö 🔒"])
def test_watermark_preserves_content_and_secret(method, pdf_bytes, secret):
    output = method.add_watermark(pdf_bytes, secret=secret, key="test-key")

    assert isinstance(output, bytes)
    assert method.read_secret(output, key="test-key") == secret

    with pymupdf.open(stream=pdf_bytes, filetype="pdf") as original:
        expected_text = [page.get_text() for page in original]

    with pymupdf.open(stream=output, filetype="pdf") as result:
        assert result.page_count == 2
        assert [page.get_text() for page in result] == expected_text


@pytest.mark.parametrize("field", ["secret", "key"])
@pytest.mark.parametrize("invalid", ["", None, 123, b"bytes"])
def test_add_rejects_invalid_credentials(method, pdf_bytes, field, invalid):
    arguments = {"secret": "test-secret", "key": "test-key"}
    arguments[field] = invalid

    with pytest.raises(ValueError):
        method.add_watermark(pdf_bytes, **arguments)


@pytest.mark.parametrize("invalid", ["", None, 123, b"bytes"])
def test_read_rejects_invalid_key(method, pdf_bytes, invalid):
    output = method.add_watermark(
        pdf_bytes, secret="test-secret", key="test-key"
    )

    with pytest.raises(ValueError):
        method.read_secret(output, key=invalid)


def test_invalid_pdf_is_rejected(method):
    with pytest.raises(ValueError):
        method.add_watermark(
            b"not a PDF", secret="test-secret", key="test-key"
        )

    with pytest.raises(ValueError):
        method.read_secret(b"not a PDF", key="test-key")

    assert method.is_watermark_applicable(b"not a PDF") is False


def test_watermark_cannot_be_added_twice(method, pdf_bytes):
    assert method.is_watermark_applicable(pdf_bytes) is True

    output = method.add_watermark(
        pdf_bytes, secret="test-secret", key="test-key"
    )

    assert method.is_watermark_applicable(output) is False

    with pytest.raises(WatermarkingError):
        method.add_watermark(
            output, secret="another-secret", key="test-key"
        )


def test_read_rejects_document_without_watermark(method, pdf_bytes):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(pdf_bytes, key="test-key")


def test_read_rejects_wrong_key(method, pdf_bytes):
    output = method.add_watermark(
        pdf_bytes, secret="test-secret", key="correct-key"
    )

    with pytest.raises(InvalidKeyError):
        method.read_secret(output, key="wrong-key")


@pytest.mark.parametrize("field", ["secret", "mac"])
def test_read_rejects_tampered_watermark(method, pdf_bytes, field):
    output = method.add_watermark(
        pdf_bytes, secret="test-secret", key="test-key"
    )

    with pymupdf.open(stream=output, filetype="pdf") as doc:
        payload = json.loads(doc.embfile_get(method.ATTACHMENT_NAME))

        if field == "secret":
            payload["secret"] = base64.b64encode(b"altered-secret").decode("ascii")
        else:
            # Change one character, guaranteeing a different MAC.
            mac = payload["mac"]
            payload["mac"] = ("0" if mac[0] != "0" else "1") + mac[1:]

        doc.embfile_del(method.ATTACHMENT_NAME)
        doc.embfile_add(
            method.ATTACHMENT_NAME,
            json.dumps(payload).encode("utf-8"),
            filename=method.ATTACHMENT_NAME,
        )
        tampered_pdf = doc.tobytes()

    with pytest.raises(InvalidKeyError):
        method.read_secret(tampered_pdf, key="test-key")