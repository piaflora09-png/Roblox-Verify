import asyncio
import os
import secrets
import sqlite3
import time
import urllib.parse
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import aiohttp
import discord
from aiohttp import web
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


DISCORD_TOKEN = require_env("DISCORD_TOKEN")
GUILD_ID = int(require_env("GUILD_ID"))
VERIFIED_ROLE_ID = int(require_env("VERIFIED_ROLE_ID"))

ROBLOX_CLIENT_ID = require_env("ROBLOX_CLIENT_ID")
ROBLOX_CLIENT_SECRET = require_env("ROBLOX_CLIENT_SECRET")
ROBLOX_REDIRECT_URI = require_env("ROBLOX_REDIRECT_URI")

WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("PORT") or os.getenv("WEB_PORT") or "8080")
DB_PATH = os.getenv("DB_PATH", "verify.db")

BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML_PATH = BASE_DIR / "index.html"

ROBLOX_AUTHORIZE_URL = "https://apis.roblox.com/oauth/v1/authorize"
ROBLOX_TOKEN_URL = "https://apis.roblox.com/oauth/v1/token"
ROBLOX_USERINFO_URL = "https://apis.roblox.com/oauth/v1/userinfo"
STATE_TTL_SECONDS = 900  # 15 minutes


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        db_file = Path(self.path)
        if db_file.parent and str(db_file.parent) not in ("", "."):
            db_file.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = asyncio.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verified_users (
                    discord_id INTEGER PRIMARY KEY,
                    roblox_id INTEGER NOT NULL,
                    roblox_username TEXT NOT NULL,
                    verified_at INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    discord_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )

    async def create_state(self, discord_id: int) -> str:
        state = secrets.token_urlsafe(32)
        now = int(time.time())
        cutoff = now - STATE_TTL_SECONDS
        async with self.lock:
            with self.conn:
                self.conn.execute(
                    "DELETE FROM oauth_states WHERE created_at < ?", (cutoff,)
                )
                self.conn.execute(
                    "INSERT INTO oauth_states (state, discord_id, created_at) VALUES (?, ?, ?)",
                    (state, discord_id, now),
                )
        return state

    async def consume_state(self, state: str) -> Optional[int]:
        now = int(time.time())
        cutoff = now - STATE_TTL_SECONDS
        async with self.lock:
            with self.conn:
                self.conn.execute(
                    "DELETE FROM oauth_states WHERE created_at < ?", (cutoff,)
                )
                row = self.conn.execute(
                    "SELECT discord_id FROM oauth_states WHERE state = ?", (state,)
                ).fetchone()
                if not row:
                    return None
                self.conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
                return int(row["discord_id"])

    async def upsert_verified(
        self, discord_id: int, roblox_id: int, roblox_username: str
    ) -> None:
        now = int(time.time())
        async with self.lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO verified_users (discord_id, roblox_id, roblox_username, verified_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(discord_id) DO UPDATE SET
                        roblox_id = excluded.roblox_id,
                        roblox_username = excluded.roblox_username,
                        verified_at = excluded.verified_at
                    """,
                    (discord_id, roblox_id, roblox_username, now),
                )

    async def get_by_discord_id(self, discord_id: int) -> Optional[sqlite3.Row]:
        async with self.lock:
            return self.conn.execute(
                "SELECT * FROM verified_users WHERE discord_id = ?", (discord_id,)
            ).fetchone()

    async def delete_by_discord_id(self, discord_id: int) -> bool:
        async with self.lock:
            with self.conn:
                cur = self.conn.execute(
                    "DELETE FROM verified_users WHERE discord_id = ?", (discord_id,)
                )
                return cur.rowcount > 0

    def close(self) -> None:
        self.conn.close()


def build_authorize_url(state: str) -> str:
    query = urlencode(
        {
            "client_id": ROBLOX_CLIENT_ID,
            "redirect_uri": ROBLOX_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile",
            "state": state,
        }
    )
    return f"{ROBLOX_AUTHORIZE_URL}?{query}"


def get_base_public_url() -> str:
    parsed = urllib.parse.urlparse(ROBLOX_REDIRECT_URI)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/"
    return "/"


def redirect_to_index(**params: str) -> web.HTTPFound:
    filtered = {k: v for k, v in params.items() if v is not None}
    base = get_base_public_url()
    location = f"{base}?{urlencode(filtered)}" if filtered else base
    raise web.HTTPFound(location=location)


class VortexVerifyBot(commands.Bot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.members = True
        super().__init__(command_prefix="!", intents=intents)
        self.db = Database(DB_PATH)
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.web_runner: Optional[web.AppRunner] = None

    async def apply_verified_state(
        self, discord_id: int, roblox_username: str
    ) -> tuple[bool, str]:
        guild = self.get_guild(GUILD_ID)
        if guild is None:
            try:
                guild = await self.fetch_guild(GUILD_ID)
            except discord.HTTPException:
                guild = None

        if guild is None:
            return False, "Bot is not in the configured Discord server."

        member = guild.get_member(discord_id)
        if member is None:
            try:
                member = await guild.fetch_member(discord_id)
            except discord.HTTPException:
                member = None

        if member is None:
            return False, "Could not find your member profile in the Discord server."

        role = guild.get_role(VERIFIED_ROLE_ID)
        role_assigned = False
        if role is not None:
            try:
                await member.add_roles(role, reason="Verified via Roblox OAuth 2.0")
                role_assigned = True
            except discord.Forbidden:
                role_assigned = False

        try:
            await member.edit(
                nick=roblox_username[:32], reason="Verified via Roblox OAuth 2.0"
            )
        except discord.Forbidden:
            pass

        if role_assigned:
            return True, "Verified role and nickname updated."
        return (
            True,
            "Verified, but I lacked permission to add the Verified role. Check bot role hierarchy.",
        )

    async def handle_index(self, request: web.Request) -> web.Response:
        if INDEX_HTML_PATH.exists():
            return web.FileResponse(INDEX_HTML_PATH)
        return web.Response(
            status=200,
            text="Vortex Verify server is running.",
            content_type="text/plain",
        )

    async def handle_oauth_callback(self, request: web.Request) -> web.Response:
        if "error" in request.query:
            err = request.query.get("error", "access_denied")
            desc = request.query.get("error_description", "")
            msg = f"Authorization cancelled or failed ({err}). {desc}".strip()
            raise redirect_to_index(status="error", message=msg)

        code = request.query.get("code")
        state = request.query.get("state")
        if not code or not state:
            raise redirect_to_index(
                status="error",
                message="Missing authorization code or state parameter.",
            )

        discord_id = await self.db.consume_state(state)
        if discord_id is None:
            raise redirect_to_index(
                status="error",
                message="Invalid or expired verification link. Run /verify again in Discord.",
            )

        if self.http_session is None:
            raise redirect_to_index(
                status="error",
                message="HTTP client is unavailable on the server.",
            )

        token_payload = {
            "client_id": ROBLOX_CLIENT_ID,
            "client_secret": ROBLOX_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
        }
        async with self.http_session.post(
            ROBLOX_TOKEN_URL, data=token_payload
        ) as token_resp:
            if token_resp.status != 200:
                raise redirect_to_index(
                    status="error",
                    message="Failed to exchange Roblox authorization code.",
                )
            token_data = await token_resp.json()

        access_token = token_data.get("access_token")
        if not access_token:
            raise redirect_to_index(
                status="error",
                message="Roblox did not return an access token.",
            )

        headers = {"Authorization": f"Bearer {access_token}"}
        async with self.http_session.get(
            ROBLOX_USERINFO_URL, headers=headers
        ) as info_resp:
            if info_resp.status != 200:
                raise redirect_to_index(
                    status="error",
                    message="Failed to fetch Roblox user profile.",
                )
            userinfo = await info_resp.json()

        raw_sub = userinfo.get("sub")
        if raw_sub is None:
            raise redirect_to_index(
                status="error",
                message="Missing Roblox user ID in userinfo response.",
            )

        roblox_id = int(raw_sub)
        roblox_username = str(
            userinfo.get("preferred_username")
            or userinfo.get("nickname")
            or userinfo.get("name")
            or f"User_{roblox_id}"
        )

        await self.db.upsert_verified(discord_id, roblox_id, roblox_username)
        _, status_msg = await self.apply_verified_state(discord_id, roblox_username)

        raise redirect_to_index(
            status="success",
            username=roblox_username,
            roblox_id=str(roblox_id),
            message=status_msg,
        )

    async def _start_web_server(self) -> None:
        parsed = urllib.parse.urlparse(ROBLOX_REDIRECT_URI)
        callback_path = parsed.path or "/oauth/roblox/callback"

        app = web.Application()
        app.router.add_get("/", self.handle_index)
        app.router.add_get("/index.html", self.handle_index)
        app.router.add_get(callback_path, self.handle_oauth_callback)

        self.web_runner = web.AppRunner(app)
        await self.web_runner.setup()
        site = web.TCPSite(self.web_runner, WEB_HOST, WEB_PORT)
        await site.start()
        print(
            f"Web server listening on http://{WEB_HOST}:{WEB_PORT} "
            f"(index: /, callback: {callback_path})"
        )

    async def setup_hook(self) -> None:
        self.http_session = aiohttp.ClientSession()
        await self._start_web_server()

        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)

    async def close(self) -> None:
        if self.web_runner is not None:
            await self.web_runner.cleanup()
        if self.http_session is not None and not self.http_session.closed:
            await self.http_session.close()
        self.db.close()
        await super().close()


bot = VortexVerifyBot()


@bot.tree.command(
    name="verify", description="Sign in with Roblox OAuth 2.0 to verify your account"
)
async def verify(interaction: discord.Interaction) -> None:
    state = await bot.db.create_state(interaction.user.id)
    auth_url = build_authorize_url(state)

    embed = discord.Embed(
        title="Verify with Roblox",
        color=discord.Color.purple(),
        description=(
            "Click **Authorize on Roblox** below to sign in and link your Roblox account. "
            "This link expires in 15 minutes."
        ),
    )
    view = discord.ui.View()
    view.add_item(
        discord.ui.Button(
            label="Authorize on Roblox", style=discord.ButtonStyle.link, url=auth_url
        )
    )
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@bot.tree.command(
    name="whois", description="Look up a verified user's linked Roblox account"
)
@app_commands.describe(member="Discord member to check (defaults to you)")
async def whois(
    interaction: discord.Interaction, member: Optional[discord.Member] = None
) -> None:
    target = member or interaction.user
    row = await bot.db.get_by_discord_id(target.id)
    if row is None:
        await interaction.response.send_message(
            f"**{target.display_name}** is not verified in the database.",
            ephemeral=True,
        )
        return

    roblox_id = int(row["roblox_id"])
    roblox_username = str(row["roblox_username"])
    verified_at = int(row["verified_at"])
    await interaction.response.send_message(
        f"**{target.display_name}** -> **[{roblox_username}](https://www.roblox.com/users/{roblox_id}/profile)** "
        f"(ID: `{roblox_id}`, verified <t:{verified_at}:R>).",
        ephemeral=True,
    )


@bot.tree.command(
    name="unverify", description="Remove your saved Roblox verification record"
)
async def unverify(interaction: discord.Interaction) -> None:
    removed = await bot.db.delete_by_discord_id(interaction.user.id)
    if interaction.guild and isinstance(interaction.user, discord.Member):
        role = interaction.guild.get_role(VERIFIED_ROLE_ID)
        if role and role in interaction.user.roles:
            try:
                await interaction.user.remove_roles(role, reason="User unverified")
            except discord.Forbidden:
                pass

    if removed:
        await interaction.response.send_message(
            "Your Roblox verification record has been removed.", ephemeral=True
        )
    else:
        await interaction.response.send_message(
            "No saved verification record found for your account.", ephemeral=True
        )


@bot.event
async def on_member_join(member: discord.Member) -> None:
    if member.guild.id != GUILD_ID:
        return
    row = await bot.db.get_by_discord_id(member.id)
    if row is None:
        return

    role = member.guild.get_role(VERIFIED_ROLE_ID)
    if role is not None:
        try:
            await member.add_roles(role, reason="Restoring verified Roblox role on rejoin")
        except discord.Forbidden:
            pass

    try:
        await member.edit(
            nick=str(row["roblox_username"])[:32],
            reason="Restoring verified Roblox nickname on rejoin",
        )
    except discord.Forbidden:
        pass


@bot.event
async def on_ready() -> None:
    if bot.user:
        print(f"Logged in as {bot.user} (ID: {bot.user.id})")


if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)
