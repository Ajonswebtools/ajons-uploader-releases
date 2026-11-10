"""Shared constants for Ajons uploader."""
BASE_URL = "https://mcp.ajonswebtools.com"
CHUNK = 8 * 1024 * 1024
STORE_SERVICE = "com.ajonswebtools.ajons-uploader"
UPLOADER_VERSION = "1.1.5"


class UploadError(Exception):
    pass


UploadNetworkError = UploadError