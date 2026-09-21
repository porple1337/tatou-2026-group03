import pymupdf
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

class erik_watermark(WatermarkingMethod):
    @staticmethod
    def get_usage() -> str:
        return "usage"
    
    def add_watermark(
        self,
        pdf,
        secret,
        key,
        position=None,
    ) -> bytes:
        pdf_bytes = load_pdf_bytes(pdf)

        return
        
    def is_watermark_applicable(
        self,
        pdf,
        position=None,
    ) -> bool:

        return

    def read_secret(self, pdf, key) -> str:

        return