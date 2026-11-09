"""Telegram public channels via Telethon (official MTProto client API).

Setup once:
  1. my.telegram.org -> API development tools -> create app -> TELEGRAM_API_ID / TELEGRAM_API_HASH in .env
  2. python run.py telegram-login     (enter the phone code once; creates data/telegram.session)
  3. list channel usernames in sources.yaml -> telegram.channels
Only public channels you list are read. The account never posts or joins anything.
"""
from __future__ import annotations

from datetime import timezone

from ..config import DATA_DIR, env
from ..models import Post
from . import CollectContext, NotConfigured

SESSION = str(DATA_DIR / "telegram")


def make_client():
    from telethon.sync import TelegramClient  # optional dependency
    api_id, api_hash = env("TELEGRAM_API_ID"), env("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        raise NotConfigured("TELEGRAM_API_ID / TELEGRAM_API_HASH not set in .env")
    return TelegramClient(SESSION, int(api_id), api_hash)


def message_to_post(msg, channel: str, title: str, reliability: str, local: bool) -> Post | None:
    text = (getattr(msg, "message", None) or "").strip()
    if not text:
        return None
    return Post(source="telegram", source_name=f"Telegram: {title}", native_id=f"{channel}/{msg.id}",
                url=f"https://t.me/{channel}/{msg.id}", text=text[:4000],
                created_at=msg.date.astimezone(timezone.utc), author=channel, reliability=reliability,
                is_local=local, engagement={"views": getattr(msg, "views", None) or 0})


class TelegramCollector:
    name = "telegram"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        channels = self.cfg.get("channels", [])
        if not channels:
            raise NotConfigured("no channels listed under telegram.channels in sources.yaml")
        client = make_client()
        client.connect()
        try:
            if not client.is_user_authorized():
                raise NotConfigured("Telegram session not logged in — run: python run.py telegram-login")
            out = []
            for ch in channels:
                name = ch["username"] if isinstance(ch, dict) else str(ch)
                rel = ch.get("reliability", "D") if isinstance(ch, dict) else "D"
                local = bool(ch.get("local", False)) if isinstance(ch, dict) else False
                entity = client.get_entity(name)
                title = getattr(entity, "title", name)
                for msg in client.iter_messages(entity, limit=int(self.cfg.get("per_channel_limit", 200))):
                    if msg.date.astimezone(timezone.utc) < ctx.since:
                        break
                    p = message_to_post(msg, name, title, rel, local)
                    if p:
                        out.append(p)
            return out
        finally:
            client.disconnect()
