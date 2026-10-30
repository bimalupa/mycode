"""Microsoft 365 (OneDrive / SharePoint) connector via Microsoft Graph, app-only auth.

Required app permission: Files.ReadWrite.All (or Sites.Selected for a scoped SharePoint site).
Files are streamed into memory only; nothing is written to local disk.
"""
from urllib.parse import quote

import msal
import requests

from .config import settings

GRAPH = "https://graph.microsoft.com/v1.0"


class GraphClient:
    def __init__(self):
        if not settings.m365_enabled:
            raise RuntimeError("Set M365_TENANT_ID, M365_CLIENT_ID and M365_CLIENT_SECRET in .env")
        self.app = msal.ConfidentialClientApplication(
            settings.m365_client_id,
            authority=f"https://login.microsoftonline.com/{settings.m365_tenant_id}",
            client_credential=settings.m365_client_secret,
        )

    def _headers(self) -> dict:
        token = self.app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in token:
            raise RuntimeError(f"Graph auth failed: {token.get('error_description', token)}")
        return {"Authorization": f"Bearer {token['access_token']}"}

    def _folder_url(self, drive_id: str, folder: str) -> str:
        folder = folder.strip("/")
        return (f"{GRAPH}/drives/{drive_id}/root" if not folder
                else f"{GRAPH}/drives/{drive_id}/root:/{quote(folder)}:")

    def list_files(self, drive_id: str, folder: str = "") -> list[dict]:
        r = requests.get(f"{self._folder_url(drive_id, folder)}/children", headers=self._headers(), timeout=30)
        r.raise_for_status()
        return [{"id": i["id"], "name": i["name"], "size": i.get("size", 0)}
                for i in r.json().get("value", []) if "file" in i]

    def download(self, drive_id: str, item_id: str) -> bytes:
        r = requests.get(f"{GRAPH}/drives/{drive_id}/items/{item_id}/content", headers=self._headers(), timeout=120)
        r.raise_for_status()
        return r.content

    def upload(self, drive_id: str, folder: str, name: str, data: bytes) -> str:
        path = f"{folder.strip('/')}/{name}".strip("/")
        r = requests.put(f"{GRAPH}/drives/{drive_id}/root:/{quote(path)}:/content",
                         headers=self._headers(), data=data, timeout=120)
        r.raise_for_status()
        return r.json().get("webUrl", "")
