"""Per-user OAuth 2.0 manager.

Coordinates between the UserTokenStore and the existing OAuthConfig
infrastructure to implement a per-user Authorization Code flow for
Jira DC and Confluence DC.

Design:
- One OAuthConfig per service holds the *app* credentials (client_id +
  client_secret). It never holds a user token — those live in UserTokenStore.
- get_valid_token() looks up the store, refreshes silently if needed.
- start_authorization() returns the Jira/Confluence consent URL.
- handle_callback() exchanges the code and persists the token.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time

from mcp_atlassian.utils.oauth import OAuthConfig

from .token_store import TokenRecord, UserTokenStore

logger = logging.getLogger("mcp-atlassian.oauth.manager")

# In-memory CSRF state: state_token -> {username, service, expires_at}
# TTL: 10 minutes — enough for a human to complete the browser auth flow.
_STATE_TTL = 600

_SERVICES = ("jira", "confluence")


class OAuthManager:
    """Manages per-user OAuth 2.0 tokens for Jira DC and Confluence DC."""

    def __init__(
        self,
        jira_app_config: OAuthConfig | None,
        confluence_app_config: OAuthConfig | None,
        store: UserTokenStore,
    ) -> None:
        self._app_configs: dict[str, OAuthConfig | None] = {
            "jira": jira_app_config,
            "confluence": confluence_app_config,
        }
        self._store = store
        self._state_cache: dict[str, dict[str, object]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_valid_token(self, username: str, service: str) -> str | None:
        """Return a valid access token for the user, refreshing if needed.

        Returns None when the user has never authorized or the token cannot
        be refreshed (user must re-authorize).
        """
        record = self._store.get(username, service)
        if record is None:
            return None

        if not record.is_expired:
            return record.access_token

        # Token is expired — attempt a silent refresh.
        refreshed = self._refresh(username, service, record)
        if refreshed:
            return refreshed

        # Refresh failed — remove stale record so the error is "oauth_required",
        # not a confusing 401 from Jira.
        logger.warning(
            f"Token refresh failed for {username}/{service} — removing stale record"
        )
        self._store.delete(username, service)
        return None

    def start_authorization(self, username: str, service: str) -> str:
        """Generate and return the Jira/Confluence consent URL for this user."""
        app_config = self._get_app_config(service)
        state = secrets.token_urlsafe(32)
        self._state_cache[state] = {
            "username": username,
            "service": service,
            "expires_at": time.time() + _STATE_TTL,
        }
        # Prune expired states to keep the dict small.
        self._prune_states()
        url = app_config.get_authorization_url(state)
        logger.info(f"Started OAuth authorization for {username}/{service}")
        return url

    def handle_callback(self, code: str | None, state: str | None) -> bool:
        """Exchange the authorization code for tokens and persist them.

        Returns True on success, False on any failure.
        """
        if not code or not state:
            logger.warning("OAuth callback received without code or state")
            return False

        entry = self._consume_state(state)
        if entry is None:
            logger.warning(f"OAuth callback: unknown or expired state '{state}'")
            return False

        username = str(entry["username"])
        service = str(entry["service"])
        app_config = self._get_app_config(service)

        # Clone the app config so we don't mutate the shared instance.
        exchange_config = self._clone_app_config(app_config)
        ok = exchange_config.exchange_code_for_tokens(code)
        if not ok or not exchange_config.access_token:
            logger.error(f"Token exchange failed for {username}/{service}")
            return False

        expires_at = exchange_config.expires_at or (time.time() + 3600)
        self._store.upsert(
            username=username,
            service=service,
            access_token=exchange_config.access_token,
            refresh_token=exchange_config.refresh_token,
            expires_at=expires_at,
            base_url=app_config.base_url or "",
        )
        logger.info(f"OAuth token stored for {username}/{service}")
        return True

    def revoke(self, username: str, service: str) -> None:
        """Remove the stored token, forcing re-authorization on next use."""
        self._store.delete(username, service)

    def is_configured(self, service: str) -> bool:
        return self._app_configs.get(service) is not None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls, store: UserTokenStore | None = None) -> "OAuthManager":
        """Create an OAuthManager from environment variables.

        Expected env vars (per service):
          JIRA_URL, JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET,
          JIRA_OAUTH_CALLBACK_URL, JIRA_OAUTH_SCOPE (optional, default WRITE)
          CONFLUENCE_URL, CONFLUENCE_OAUTH_CLIENT_ID, ...
        """
        if store is None:
            db_path = os.getenv("TOKEN_STORE_PATH", "/data/tokens.db")
            store = UserTokenStore(db_path)

        jira_config = cls._build_app_config("jira")
        confluence_config = cls._build_app_config("confluence")

        if jira_config is None and confluence_config is None:
            raise ValueError(
                "ATLASSIAN_PER_USER_OAUTH=true requires at least one of "
                "JIRA_OAUTH_CLIENT_ID or CONFLUENCE_OAUTH_CLIENT_ID to be set."
            )

        return cls(
            jira_app_config=jira_config,
            confluence_app_config=confluence_config,
            store=store,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_app_config(service: str) -> OAuthConfig | None:
        prefix = service.upper()
        client_id = os.getenv(f"{prefix}_OAUTH_CLIENT_ID")
        client_secret = os.getenv(f"{prefix}_OAUTH_CLIENT_SECRET")
        callback_url = os.getenv(f"{prefix}_OAUTH_CALLBACK_URL", "")
        scope = os.getenv(f"{prefix}_OAUTH_SCOPE", "WRITE")
        base_url = os.getenv(f"{prefix}_URL", "")

        if not client_id or not client_secret:
            logger.info(f"No OAuth app config for {service} — service will be skipped")
            return None

        if not callback_url:
            logger.warning(
                f"{prefix}_OAUTH_CALLBACK_URL not set — OAuth flow will fail for {service}"
            )

        config = OAuthConfig(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=callback_url,
            scope=scope,
            base_url=base_url or None,
        )
        logger.info(
            f"OAuth app config loaded for {service}: client_id={client_id[:8]}..., "
            f"base_url={base_url}"
        )
        return config

    def _get_app_config(self, service: str) -> OAuthConfig:
        config = self._app_configs.get(service)
        if config is None:
            raise ValueError(f"OAuth not configured for service '{service}'")
        return config

    @staticmethod
    def _clone_app_config(src: OAuthConfig) -> OAuthConfig:
        """Return a fresh OAuthConfig with the same app credentials but no tokens."""
        return OAuthConfig(
            client_id=src.client_id,
            client_secret=src.client_secret,
            redirect_uri=src.redirect_uri,
            scope=src.scope,
            base_url=src.base_url,
        )

    def _refresh(
        self, username: str, service: str, record: TokenRecord
    ) -> str | None:
        """Attempt a silent token refresh. Returns new access token or None."""
        if not record.refresh_token:
            logger.info(
                f"No refresh token for {username}/{service} — re-authorization required"
            )
            return None

        app_config = self._get_app_config(service)
        temp = OAuthConfig(
            client_id=app_config.client_id,
            client_secret=app_config.client_secret,
            redirect_uri=app_config.redirect_uri,
            scope=app_config.scope,
            base_url=record.base_url or app_config.base_url,
            refresh_token=record.refresh_token,
            access_token=record.access_token,
            expires_at=record.expires_at,
        )
        ok = temp.refresh_access_token()
        if not ok or not temp.access_token:
            return None

        expires_at = temp.expires_at or (time.time() + 3600)
        self._store.upsert(
            username=username,
            service=service,
            access_token=temp.access_token,
            refresh_token=temp.refresh_token,
            expires_at=expires_at,
            base_url=record.base_url,
        )
        logger.info(f"Token refreshed for {username}/{service}")
        return temp.access_token

    def _consume_state(self, state: str) -> dict[str, object] | None:
        entry = self._state_cache.pop(state, None)
        if entry and time.time() < float(str(entry["expires_at"])):
            return entry
        return None

    def _prune_states(self) -> None:
        now = time.time()
        expired = [s for s, e in self._state_cache.items() if now >= float(str(e["expires_at"]))]
        for s in expired:
            del self._state_cache[s]
