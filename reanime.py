#!/usr/bin/env python3
import asyncio
import hashlib
import json
import os
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE = "https://reanime.to"
FLIX = "https://flixcloud.cc"
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": _UA, "Accept": "application/json, */*"}
_DECRYPT_MJS = str(Path(__file__).parent / "decrypt.mjs")

_client: Optional[httpx.AsyncClient] = None

# API Key Configuration
API_KEYS: dict[str, dict] = {}  # key -> {name, created_at, rate_limit}
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin-secret-key-change-me")


@asynccontextmanager
async def lifespan(_app):
    global _client
    _client = httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(20.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        headers=HEADERS,
        follow_redirects=True,
    )
    yield
    await _client.aclose()


app = FastAPI(title="ReAnime Scraper", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def _get(path: str, params: dict = None, base: str = BASE) -> Any:
    r = await _client.get(f"{base}{path}", params=params)
    if r.status_code == 404:
        raise HTTPException(404, detail="Not found")
    if not r.is_success:
        raise HTTPException(r.status_code, detail=r.text[:300])
    return r.json()


def _anilist_from_anime(anime: dict) -> Optional[int]:
    if not anime:
        return None
    if anime.get("anilist"):
        return int(anime["anilist"])
    for key in ("extra_large", "large", "medium"):
        url = (anime.get("cover_image") or {}).get(key, "")
        m = re.search(r"/bx(\d+)-", url)
        if m:
            return int(m.group(1))
    return None


async def _decrypt_embed(html: bytes) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "node", _DECRYPT_MJS, "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=html), timeout=20.0)
    except asyncio.TimeoutError:
        proc.kill()
        raise HTTPException(504, detail="Decrypt subprocess timed out")
    if proc.returncode != 0:
        raise HTTPException(502, detail=f"Decrypt error: {stderr.decode()[:300]}")
    return json.loads(stdout)


async def get_stream_url(access_id: str, v: int = 2) -> dict:
    r = await _client.get(f"{FLIX}/e/{access_id}?v={v}", headers={**HEADERS, "Referer": f"{BASE}/"})
    if not r.is_success:
        raise HTTPException(r.status_code, detail=f"Embed fetch failed: {r.status_code}")
    return await _decrypt_embed(r.content)


async def _servers(slug: str, ep: int, anilist_id: Optional[int] = None) -> dict:
    watch = await _get(f"/api/watch/{slug}/{ep}")
    aid = anilist_id or _anilist_from_anime(watch.get("anime"))

    flix: dict = {}
    if aid:
        try:
            flix = await _get(f"/api/flix/{aid}/{ep}")
        except HTTPException:
            pass

    links = list(watch.get("episode_links") or [])
    if flix.get("success") and flix.get("servers"):
        seen = {s.get("$id") for s in links}
        for s in flix["servers"]:
            if s.get("$id") not in seen:
                links.append(s)

    _order = {"HD-2": 0, "HD-1": 1}
    _sort = lambda lst: sorted(lst, key=lambda s: _order.get(s.get("serverName", ""), 9))

    return {
        "sub":         _sort([s for s in links if s.get("dataType") in ("sub", "s-sub")]),
        "dub":         _sort([s for s in links if s.get("dataType") in ("dub", "s-dub")]),
        "anime":       watch.get("anime"),
        "current":     watch.get("current"),
        "duration":    watch.get("duration"),
        "intro_start": watch.get("intro_start"),
        "intro_end":   watch.get("intro_end"),
        "outro_start": watch.get("outro_start"),
        "outro_end":   watch.get("outro_end"),
        "anilist_id":  aid,
    }


# --- Auth Dependencies ---

def verify_api_key(x_api_key: str = Header(None)) -> str:
    """Verify API key and return the key if valid."""
    if not x_api_key:
        raise HTTPException(401, detail="Missing API key. Include 'x-api-key' header.")
    if x_api_key not in API_KEYS:
        raise HTTPException(401, detail="Invalid API key.")
    return x_api_key


def verify_admin_key(x_admin_key: str = Header(None, alias="x-admin-key")) -> bool:
    """Verify admin key for management endpoints."""
    if not x_admin_key or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(403, detail="Invalid or missing admin key.")
    return True


# --- Admin Endpoints ---

class CreateKeyRequest(BaseModel):
    name: str
    rate_limit: int = 100


@app.post("/admin/keys", tags=["admin"])
async def create_api_key(req: CreateKeyRequest, _: bool = Depends(verify_admin_key)):
    """Create a new API key (requires admin key in x-admin-key header)."""
    key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
    display_key = f"rean_{key_hash}"
    
    API_KEYS[display_key] = {
        "name": req.name,
        "created_at": asyncio.get_event_loop().time(),
        "rate_limit": req.rate_limit,
    }
    
    return {
        "key": display_key,
        "name": req.name,
        "rate_limit": req.rate_limit,
        "message": "Save this key! It won't be shown again."
    }


@app.get("/admin/keys", tags=["admin"])
async def list_api_keys(_: bool = Depends(verify_admin_key)):
    """List all API keys (admin only, doesn't show full keys)."""
    return {
        "keys": [{"key": k, **v} for k, v in API_KEYS.items()],
        "count": len(API_KEYS)
    }


@app.delete("/admin/keys/{key}", tags=["admin"])
async def delete_api_key(key: str, _: bool = Depends(verify_admin_key)):
    """Delete an API key (admin only)."""
    if key in API_KEYS:
        del API_KEYS[key]
        return {"message": "Key deleted successfully"}
    raise HTTPException(404, detail="Key not found")


@app.get("/admin/gen-key", tags=["admin"])
async def generate_display_key(name: str = "default", _: bool = Depends(verify_admin_key)):
    """Quick endpoint to generate a key with GET request."""
    key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
    display_key = f"rean_{key_hash}"
    
    API_KEYS[display_key] = {
        "name": name,
        "created_at": asyncio.get_event_loop().time(),
        "rate_limit": 100,
    }
    
    return {
        "key": display_key,
        "name": name,
        "message": "Save this key!"
    }


# --- Public Endpoints ---

@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "ReAnime API - Include 'x-api-key' header in requests",
        "docs": "/docs",
        "admin": "GET /admin/gen-key?key=<admin_key>&name=<name>"
    }


@app.get("/search", dependencies=[Depends(verify_api_key)])
async def search(
    q: str = Query(..., min_length=1),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return await _get("/api/search", {"q": q, "limit": limit, "offset": offset})


@app.get("/home", dependencies=[Depends(verify_api_key)])
async def home(limit: int = Query(20, ge=1, le=100)):
    latest, top = await asyncio.gather(
        _get("/api/home/latest-aired", {"limit": limit}),
        _get("/api/top/anime", {"period": "week", "limit": limit}),
    )
    return {"latest_aired": latest, "top_weekly": top}


@app.get("/top", dependencies=[Depends(verify_api_key)])
async def top(
    period: str = Query("week", pattern="^(day|week|month)$"),
    limit: int = Query(20, ge=1, le=100),
):
    return await _get("/api/top/anime", {"period": period, "limit": limit})


@app.get("/schedule", dependencies=[Depends(verify_api_key)])
async def schedule():
    return await _get("/api/schedule")


@app.get("/info/{slug}", dependencies=[Depends(verify_api_key)])
async def anime_info(slug: str):
    meta, eps = await asyncio.gather(
        _get(f"/api/watch/{slug}/1"),
        _get(f"/api/episodes/{slug}"),
    )
    anime = meta.get("anime") or {}
    anilist_id = _anilist_from_anime(anime)
    ep_list = eps if isinstance(eps, list) else eps.get("data", eps.get("episodes", []))
    return {**anime, "episodes": ep_list, "anilist_id": anilist_id}


@app.get("/episodes/{slug}", dependencies=[Depends(verify_api_key)])
async def episodes(slug: str):
    data = await _get(f"/api/episodes/{slug}")
    return data if isinstance(data, list) else data.get("data", data.get("episodes", data))


@app.get("/servers/{slug}/{episode}", dependencies=[Depends(verify_api_key)])
async def servers(slug: str, episode: int, anilist_id: Optional[int] = Query(None)):
    return await _servers(slug, episode, anilist_id)


@app.get("/stream/from-link", dependencies=[Depends(verify_api_key)])
async def stream_from_link(link: str = Query(...)):
    m = re.search(r"/e/([^?#\s]+)\?v=(\d+)", link)
    if not m:
        raise HTTPException(400, detail="Expected URL: https://flixcloud.cc/e/{id}?v={1|2}")
    return await get_stream_url(m.group(1), int(m.group(2)))


@app.get("/stream/{access_id}", dependencies=[Depends(verify_api_key)])
async def stream(access_id: str, v: int = Query(2, ge=1, le=2)):
    return await get_stream_url(access_id, v)


@app.get("/thumbnails/{anilist_id}", dependencies=[Depends(verify_api_key)])
async def thumbnails(anilist_id: int):
    return await _get(f"/api/thumbnails/{anilist_id}")


@app.get("/recommendations/{slug}", dependencies=[Depends(verify_api_key)])
async def recommendations(slug: str):
    return await _get(f"/api/anime/{slug}/recommendations")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("reanime:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), workers=1, reload=False)