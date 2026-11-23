import os
import secrets
import sqlite3
import threading
import urllib.parse
import requests
from flask import Flask, request, render_template, redirect
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
ROBLOX_CLIENT_ID = os.getenv("ROBLOX_CLIENT_ID")
ROBLOX_CLIENT_SECRET = os.getenv("ROBLOX_CLIENT_SECRET")

# Defaults directly to your live Render URL so it never falls back to example.com
BASE_URL = os.getenv("BASE_URL", "https://roblox-verify-621p.onrender.com").rstrip("/")
ROBLOX_REDIRECT_URI = os.getenv(
    "ROBLOX_REDIRECT_URI",
    f"{BASE_URL}/oauth/roblox/callback"
).strip()

VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")  # Optional: numeric Discord Role ID
DB_PATH = os.getenv("DB_PATH", "verified_users.db")

# In-memory state store: { state_token: {"discord_id": int, "guild_id": int} }
pending_states = {}

# --- Database Setup ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verified_users (
                discord_id TEXT PRIMARY KEY,
                roblox_id TEXT NOT NULL,
                roblox_username TEXT NOT NULL,
                roblox_display_name TEXT
            )
        """)
        conn.commit()

def save_verified_user(discord_id: str, roblox_id: str, username: str, display_name: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO verified_users (discord_id, roblox_id, roblox_username, roblox_display_name)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET
                roblox_id=excluded.roblox_id,
                roblox_username=excluded.roblox_username,
                roblox_display_name=excluded.roblox_display_name
        """, (str(discord_id), str(roblox_id), username, display_name))
        conn.commit()

def get_verified_user(discord_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT roblox_id, roblox_username, roblox_display_name FROM verified_users WHERE discord_id = ?",
            (str(discord_id),)
        )
        return cur.fetchone()

# --- Discord Bot Setup ---
intents = discord.Intents.default()
intents.members = True  # Required to assign roles and update nicknames

class VerifyBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        await self.tree.sync()
        print("Slash commands synced.")

bot = VerifyBot()

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print(f"Using Redirect URI: {ROBLOX_REDIRECT_URI}")

def build_oauth_url(discord_id: int, guild_id: int | None) -> str:
    state = secrets.token_urlsafe(24)
    pending_states[state] = {
        "discord_id": discord_id,
        "guild_id": guild_id
    }
    params = {
        "client_id": ROBLOX_CLIENT_ID,
        "redirect_uri": ROBLOX_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile",
        "state": state,
    }
    return f"https://apis.roblox.com/oauth/v1/authorize?{urllib.parse.urlencode(params)}"

@bot.tree.command(name="verify", description="Link your Roblox account to your Discord profile")
async def verify_command(interaction: discord.Interaction):
    if not ROBLOX_CLIENT_ID:
        await interaction.response.send_message(
            "Bot configuration error: `ROBLOX_CLIENT_ID` is missing.",
            ephemeral=True
        )
        return

    auth_url = build_oauth_url(
        discord_id=interaction.user.id,
        guild_id=interaction.guild.id if interaction.guild else None
    )

    embed = discord.Embed(
        title="Roblox Account Verification",
        description=(
            "Click the button below to authorize with Roblox and link your account to this server."
        ),
        color=discord.Color.blurple()
    )
    view = discord.ui.View()
    view.add_item(discord.ui.Button(label="Authorize on Roblox", url=auth_url, style=discord.ButtonStyle.link))

    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

@bot.tree.command(name="whois", description="Check a member's linked Roblox account")
@app_commands.describe(member="The Discord member to look up")
async def whois_command(interaction: discord.Interaction, member: discord.Member | None = None):
    target = member or interaction.user
    record = get_verified_user(str(target.id))
    if not record:
        await interaction.response.send_message(
            f"**{target.display_name}** has not verified their Roblox account yet.",
            ephemeral=True
        )
        return

    roblox_id, username, display_name = record
    embed = discord.Embed(
        title=f"Roblox Profile — {target.display_name}",
        color=discord.Color.green()
    )
    embed.add_field(name="Username", value=f"[{username}](https://www.roblox.com/users/{roblox_id}/profile)", inline=True)
    embed.add_field(name="Display Name", value=display_name or username, inline=True)
    embed.add_field(name="Roblox ID", value=str(roblox_id), inline=True)
    await interaction.response.send_message(embed=embed)

async def apply_discord_updates(discord_id: int, guild_id: int | None, roblox_username: str):
    if not guild_id:
        return
    guild = bot.get_guild(guild_id)
    if not guild:
        return
    member = guild.get_member(discord_id)
    if not member:
        try:
            member = await guild.fetch_member(discord_id)
        except discord.NotFound:
            return

    # Update nickname to Roblox username (if bot has permission & higher role)
    try:
        await member.edit(nick=roblox_username[:32])
    except discord.Forbidden:
        print(f"Missing permission to change nickname for {member}")

    # Assign Verified Role if configured
    if VERIFIED_ROLE_ID and VERIFIED_ROLE_ID.isdigit():
        role = guild.get_role(int(VERIFIED_ROLE_ID))
        if role:
            try:
                await member.add_roles(role, reason="Roblox OAuth 2.0 Verification")
            except discord.Forbidden:
                print(f"Missing permission to assign role {role.name}")

# --- Flask Web Server ---
app = Flask(__name__)

@app.route("/")
def home():
    return render_template(
        "index.html",
        status="online",
        title="Vortex Verify",
        message="Roblox–Discord OAuth 2.0 Verification Service is running.",
        username=None,
        roblox_id=None,
        avatar_url=None,
        error=None
    )

@app.route("/health")
def health():
    return {"status": "ok", "redirect_uri": ROBLOX_REDIRECT_URI}, 200

@app.route("/oauth/roblox/callback")
def roblox_callback():
    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "Authorization was cancelled or denied.")
        return render_template(
            "index.html",
            status="error",
            title="Verification Failed",
            message=desc,
            username=None,
            roblox_id=None,
            avatar_url=None,
            error=error
        ), 400

    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state or state not in pending_states:
        return render_template(
            "index.html",
            status="error",
            title="Invalid or Expired Session",
            message="This verification link has expired or was already used. Please run /verify in Discord again.",
            username=None,
            roblox_id=None,
            avatar_url=None,
            error="invalid_state"
        ), 400

    session_data = pending_states.pop(state)
    discord_id = session_data["discord_id"]
    guild_id = session_data["guild_id"]

    # 1. Exchange authorization code for access token
    token_resp = requests.post(
        "https://apis.roblox.com/oauth/v1/token",
        data={
            "client_id": ROBLOX_CLIENT_ID,
            "client_secret": ROBLOX_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": ROBLOX_REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15
    )

    if token_resp.status_code != 200:
        return render_template(
            "index.html",
            status="error",
            title="Token Exchange Failed",
            message="Could not verify authorization code with Roblox. Check your Client Secret and Redirect URI.",
            username=None,
            roblox_id=None,
            avatar_url=None,
            error=token_resp.text
        ), 400

    access_token = token_resp.json().get("access_token")

    # 2. Fetch Roblox user profile via OpenID userinfo
    userinfo_resp = requests.get(
        "https://apis.roblox.com/oauth/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15
    )

    if userinfo_resp.status_code != 200:
        return render_template(
            "index.html",
            status="error",
            title="Profile Lookup Failed",
            message="Authenticated with Roblox, but could not retrieve your profile details.",
            username=None,
            roblox_id=None,
            avatar_url=None,
            error=userinfo_resp.text
        ), 400

    profile = userinfo_resp.json()
    roblox_id = profile.get("sub")
    roblox_username = profile.get("preferred_username") or profile.get("name") or f"User_{roblox_id}"
    roblox_display_name = profile.get("name") or roblox_username
    avatar_url = profile.get("picture")

    # 3. Save to SQLite & update Discord roles/nickname
    save_verified_user(str(discord_id), str(roblox_id), roblox_username, roblox_display_name)

    if bot.loop and bot.is_ready():
        bot.loop.create_task(apply_discord_updates(discord_id, guild_id, roblox_username))

    return render_template(
        "index.html",
        status="success",
        title="Verification Complete!",
        message="Your Roblox account has been linked to Discord. You can now close this tab.",
        username=roblox_username,
        roblox_id=roblox_id,
        avatar_url=avatar_url,
        error=None
    )

def run_discord_bot():
    if not DISCORD_TOKEN:
        print("WARNING: DISCORD_TOKEN is not set. Bot will not start.")
        return
    bot.run(DISCORD_TOKEN)

if __name__ == "__main__":
    init_db()
    bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
    bot_thread.start()

    port = int(os.getenv("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
