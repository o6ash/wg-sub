"""Read a public Telegram channel and return WireGuard profile texts.

The session stays on this machine. Nothing here is committed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from wgsub.parse import Profile, parse_blob


@dataclass
class Hit:
    profile: Profile
    message_id: int


async def collect_channel(api_id: int, api_hash: str, session: str, channel: str, limit: int, cap: int) -> list[Profile]:
    from telethon import TelegramClient
    from telethon.sessions import StringSession

    client = TelegramClient(StringSession(session), api_id, api_hash)
    await client.connect()
    try:
        entity = await client.get_entity(channel)
        hits: list[Hit] = []
        seen = set()
        async for message in client.iter_messages(entity, limit=limit):
            blobs = []
            if message.message:
                blobs.append((message.message, ""))
            name = ""
            if message.file and message.file.name:
                suffix = Path(message.file.name).suffix.lower()
                if suffix in {".conf", ".txt", ".ini"}:
                    try:
                        data = await client.download_media(message, bytes)
                    except Exception:
                        data = None
                    if data:
                        blobs.append((data.decode("utf-8", "replace"), Path(message.file.name).stem))
            for text, fallback in blobs:
                for profile in parse_blob(text, fallback or name):
                    key = profile.identity()
                    if key in seen:
                        continue
                    seen.add(key)
                    if not profile.name and fallback:
                        profile.name = fallback
                    hits.append(Hit(profile, message.id))
                    if len(hits) >= cap:
                        return [hit.profile for hit in hits]
        return [hit.profile for hit in hits]
    finally:
        await client.disconnect()


def load_env(path: str) -> dict[str, str]:
    env = {}
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


async def collect_topic(
    api_id: int,
    api_hash: str,
    session: str,
    group: str,
    topic_id: int,
    since,
    limit: int = 400,
) -> list[Profile]:
    from telethon import TelegramClient
    from telethon.sessions import StringSession

    client = TelegramClient(StringSession(session), api_id, api_hash)
    await client.connect()
    try:
        entity = await client.get_entity(group)
        hits: list[Hit] = []
        seen = set()
        async for message in client.iter_messages(entity, reply_to=topic_id, limit=limit):
            if message.date < since:
                break
            blobs = []
            if message.message:
                blobs.append((message.message, ""))
            if message.file and message.file.name:
                suffix = Path(message.file.name).suffix.lower()
                if suffix in {".conf", ".txt", ".ini"}:
                    try:
                        data = await client.download_media(message, bytes)
                    except Exception:
                        data = None
                    if data:
                        blobs.append((data.decode("utf-8", "replace"), Path(message.file.name).stem))
            for text, fallback in blobs:
                for profile in parse_blob(text, fallback):
                    key = profile.identity()
                    if key in seen:
                        continue
                    seen.add(key)
                    if not profile.name and fallback:
                        profile.name = fallback
                    hits.append(Hit(profile, message.id))
        return [hit.profile for hit in hits]
    finally:
        await client.disconnect()


def collect(env_path: str, channel: str, limit: int, cap: int) -> list[Profile]:
    env = load_env(env_path)
    return asyncio.run(
        collect_channel(
            int(env["TELEGRAM_API_ID"]),
            env["TELEGRAM_API_HASH"],
            env["TELEGRAM_SESSION"],
            channel,
            limit,
            cap,
        )
    )
