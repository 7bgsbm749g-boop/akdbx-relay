"""Minimal Cloudflare DNS client for ACME DNS-01 TXT records (stdlib urllib)."""

from __future__ import annotations

import asyncio
import datetime
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

# Upper bound on pages read when listing TXT records (100 records per page).
MAX_LIST_PAGES = 50


@dataclass(frozen=True)
class TxtRecord:
    id: str
    name: str
    content: str
    comment: str
    created: datetime.datetime | None


def _parse_time(value: object) -> datetime.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


class CloudflareError(Exception):
    """A Cloudflare API call failed. The message never contains the token."""


class CloudflareDNS:
    def __init__(self, api: str, token: str, zone_id: str, timeout: float = 30.0) -> None:
        self.api = api.rstrip("/")
        self._token = token
        self.zone_id = zone_id
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"CloudflareDNS(api={self.api!r}, zone_id={self.zone_id!r})"

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{self.api}/zones/{self.zone_id}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "akdbx-relay",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            codes = ""
            try:
                err = json.loads(exc.read().decode("utf-8"))
                codes = ",".join(str(e.get("code")) for e in err.get("errors", []))
            except Exception:
                pass
            raise CloudflareError(f"Cloudflare API {method} returned HTTP {exc.code} {codes}".strip()) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise CloudflareError(f"Cloudflare API {method} failed: {type(exc).__name__}") from None
        if not payload.get("success"):
            codes = ",".join(str(e.get("code")) for e in payload.get("errors", []))
            raise CloudflareError(f"Cloudflare API {method} was not successful {codes}".strip())
        return payload

    def create_txt_sync(self, name: str, content: str, comment: str) -> str:
        payload = self._request(
            "POST",
            "/dns_records",
            {"type": "TXT", "name": name, "content": content, "ttl": 60, "proxied": False,
             "comment": comment},
        )
        record_id = payload.get("result", {}).get("id")
        if not isinstance(record_id, str) or not record_id:
            raise CloudflareError("Cloudflare API returned no record id")
        return record_id

    def delete_txt_sync(self, record_id: str) -> None:
        try:
            self._request("DELETE", f"/dns_records/{record_id}")
        except CloudflareError as exc:
            if "HTTP 404" in str(exc):
                return  # already gone
            raise

    def list_txt_sync(self, name: str | None = None) -> list[TxtRecord]:
        """TXT records in the zone (only those named `name`, if given)."""
        out: list[TxtRecord] = []
        for page in range(1, MAX_LIST_PAGES + 1):
            query = {"type": "TXT", "per_page": "100", "page": str(page)}
            if name is not None:
                query["name"] = name
            payload = self._request("GET", "/dns_records?" + urllib.parse.urlencode(query))
            for rec in payload.get("result") or []:
                if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
                    continue
                out.append(TxtRecord(
                    id=rec["id"],
                    name=str(rec.get("name") or ""),
                    content=str(rec.get("content") or ""),
                    comment=str(rec.get("comment") or ""),
                    created=_parse_time(rec.get("created_on")),
                ))
            info = payload.get("result_info") or {}
            total_pages = info.get("total_pages") if isinstance(info, dict) else None
            if not isinstance(total_pages, int) or page >= total_pages:
                break
        return out

    async def create_txt(self, name: str, content: str, comment: str) -> str:
        return await asyncio.to_thread(self.create_txt_sync, name, content, comment)

    async def list_txt(self, name: str | None = None) -> list[TxtRecord]:
        return await asyncio.to_thread(self.list_txt_sync, name)

    async def delete_txt(self, record_id: str) -> None:
        await asyncio.to_thread(self.delete_txt_sync, record_id)
