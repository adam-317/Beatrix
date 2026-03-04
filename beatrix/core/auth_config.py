"""
BEATRIX Authentication Configuration

Provides a unified way to manage authentication credentials for scanning.
Supports multiple credential sources:

1. YAML config file (~/.beatrix/auth.yaml or --auth-config)
2. CLI flags (--cookie, --header, --token, --user/--pass)
3. Environment variables (BEATRIX_AUTH_*)

Credentials flow through the entire kill chain:
- Nuclei gets -H flags for authenticated template scanning
- IDOR scanner gets user1/user2 sessions for access control testing
- All HTTP scanners get auth headers on their httpx clients
- Crawler gets cookies for authenticated crawling

Config file format (~/.beatrix/auth.yaml):
---
# Global auth applied to all targets
global:
  headers:
    Authorization: "Bearer eyJ..."
  cookies:
    session: "abc123"
    csrf_token: "xyz789"

# Per-target auth (overrides global)
targets:
  "example.com":
    headers:
      Authorization: "Bearer target-specific-token"
    cookies:
      session: "target-session"

  "api.example.com":
    headers:
      X-API-Key: "key-123"

# IDOR testing requires two different user sessions
idor:
  user1:
    cookies:
      session: "user1-session-cookie"
    headers:
      Authorization: "Bearer user1-token"
  user2:
    cookies:
      session: "user2-session-cookie"
    headers:
      Authorization: "Bearer user2-token"
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AuthCredentials:
    """
    Resolved authentication credentials for a scan.

    This is the final, merged result of all credential sources
    (config file + CLI + env vars), ready to be consumed by scanners.
    """
    # HTTP headers to inject (e.g., Authorization, X-API-Key)
    headers: Dict[str, str] = field(default_factory=dict)

    # Cookies to inject
    cookies: Dict[str, str] = field(default_factory=dict)

    # Basic auth (username:password)
    basic_auth: Optional[Tuple[str, str]] = None

    # Bearer token (convenience — also added to headers)
    bearer_token: Optional[str] = None

    # Login credentials — Beatrix performs the login and captures the session
    login_url: Optional[str] = None        # e.g. https://kick.com/login
    login_username: Optional[str] = None   # email or username
    login_password: Optional[str] = None   # password
    login_method: Optional[str] = None     # "form" | "json" | "auto" (default: auto)
    login_username_field: Optional[str] = None  # form field name (default: auto-detect)
    login_password_field: Optional[str] = None  # form field name (default: auto-detect)

    # IDOR: second user credentials for access control testing
    idor_user1: Optional["AuthCredentials"] = None
    idor_user2: Optional["AuthCredentials"] = None

    @property
    def has_auth(self) -> bool:
        """Whether any authentication is configured."""
        return bool(self.headers or self.cookies or self.basic_auth or self.bearer_token)

    @property
    def has_login_creds(self) -> bool:
        """Whether login credentials are provided (needs auto-login)."""
        return bool(self.login_username and self.login_password)

    @property
    def has_idor_accounts(self) -> bool:
        """Whether two accounts are configured for IDOR testing."""
        return self.idor_user1 is not None and self.idor_user2 is not None

    def merged_headers(self) -> Dict[str, str]:
        """Get all headers including bearer token."""
        h = dict(self.headers)
        if self.bearer_token and "Authorization" not in h:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if self.basic_auth:
            import base64
            creds = base64.b64encode(
                f"{self.basic_auth[0]}:{self.basic_auth[1]}".encode()
            ).decode()
            if "Authorization" not in h:
                h["Authorization"] = f"Basic {creds}"
        return h

    def cookie_header(self) -> Optional[str]:
        """Build a Cookie header string from cookies dict."""
        if not self.cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def all_headers(self) -> Dict[str, str]:
        """Get all headers including cookies as Cookie header."""
        h = self.merged_headers()
        cookie_str = self.cookie_header()
        if cookie_str:
            h["Cookie"] = cookie_str
        return h

    def nuclei_header_flags(self) -> List[str]:
        """Build nuclei -H flags for authenticated scanning."""
        flags = []
        for key, val in self.merged_headers().items():
            flags.extend(["-H", f"{key}: {val}"])
        cookie_str = self.cookie_header()
        if cookie_str:
            flags.extend(["-H", f"Cookie: {cookie_str}"])
        return flags


class AuthConfigLoader:
    """
    Loads and merges authentication from all sources.

    Priority (highest to lowest):
    1. CLI flags (--cookie, --header, --token)
    2. Environment variables (BEATRIX_AUTH_*)
    3. Per-target config from auth.yaml
    4. Global config from auth.yaml
    """

    DEFAULT_CONFIG_PATH = Path.home() / ".beatrix" / "auth.yaml"

    @classmethod
    def load(
        cls,
        target: str,
        config_path: Optional[str] = None,
        cli_cookies: Optional[List[str]] = None,
        cli_headers: Optional[List[str]] = None,
        cli_token: Optional[str] = None,
        cli_user: Optional[str] = None,
        cli_password: Optional[str] = None,
        login_user: Optional[str] = None,
        login_pass: Optional[str] = None,
        login_url: Optional[str] = None,
    ) -> AuthCredentials:
        """
        Load and merge credentials from all sources for a target.

        Args:
            target: Target domain/URL being scanned
            config_path: Path to auth config YAML (default: ~/.beatrix/auth.yaml)
            cli_cookies: Cookies from CLI (format: "name=value")
            cli_headers: Headers from CLI (format: "Name: Value")
            cli_token: Bearer token from CLI
            cli_user: Username for basic auth
            cli_password: Password for basic auth
            login_user: Username/email for auto-login
            login_pass: Password for auto-login
            login_url: Login page URL (optional, auto-detected if omitted)

        Returns:
            Merged AuthCredentials ready for use
        """
        creds = AuthCredentials()

        # 1. Load from config file (lowest priority)
        file_path = Path(config_path) if config_path else cls.DEFAULT_CONFIG_PATH
        if file_path.exists():
            file_creds = cls._load_config_file(file_path, target)
            creds = cls._merge(creds, file_creds)

        # 2. Environment variables
        env_creds = cls._load_env_vars()
        creds = cls._merge(creds, env_creds)

        # 3. CLI flags (highest priority)
        cli_creds = cls._parse_cli_args(
            cookies=cli_cookies,
            headers=cli_headers,
            token=cli_token,
            user=cli_user,
            password=cli_password,
            login_user=login_user,
            login_pass=login_pass,
            login_url=login_url,
        )
        creds = cls._merge(creds, cli_creds)

        return creds

    @classmethod
    def _load_config_file(cls, path: Path, target: str) -> AuthCredentials:
        """Load credentials from YAML config file."""
        try:
            import yaml
        except ImportError:
            # PyYAML not installed — try raw parsing
            return cls._load_config_file_raw(path, target)

        try:
            data = yaml.safe_load(path.read_text())
            if not isinstance(data, dict):
                return AuthCredentials()
        except Exception:
            return AuthCredentials()

        return cls._parse_config_data(data, target)

    @classmethod
    def _load_config_file_raw(cls, path: Path, target: str) -> AuthCredentials:
        """Fallback config parser when PyYAML is not installed.

        Supports a simplified key: value format for the most common cases.
        """
        creds = AuthCredentials()
        try:
            content = path.read_text()
            # Simple line-by-line parsing for flat config
            section = "global"
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # Detect section headers (no leading spaces, ends with colon)
                if not line.startswith(" ") and stripped.endswith(":"):
                    section = stripped[:-1].strip().strip('"').strip("'")
                    continue

                # Parse key: value pairs  
                if ":" in stripped:
                    key, _, val = stripped.partition(":")
                    key = key.strip().strip('"').strip("'")
                    val = val.strip().strip('"').strip("'")

                    if section == "headers" or section.endswith("/headers"):
                        creds.headers[key] = val
                    elif section == "cookies" or section.endswith("/cookies"):
                        creds.cookies[key] = val
        except Exception:
            pass
        return creds

    @classmethod
    def _parse_config_data(cls, data: Dict[str, Any], target: str) -> AuthCredentials:
        """Parse the structured config data dict."""
        creds = AuthCredentials()

        # Extract target domain for matching
        target_domain = cls._extract_domain(target)

        # Global config
        global_cfg = data.get("global") or {}
        if isinstance(global_cfg, dict):
            creds.headers.update(global_cfg.get("headers") or {})
            creds.cookies.update(global_cfg.get("cookies") or {})

        # Per-target config (overrides global)
        targets = data.get("targets") or {}
        if isinstance(targets, dict):
            for pattern, tcfg in targets.items():
                if cls._target_matches(target_domain, pattern):
                    if isinstance(tcfg, dict):
                        creds.headers.update(tcfg.get("headers") or {})
                        creds.cookies.update(tcfg.get("cookies") or {})

                        # Login credentials from per-target config
                        login_cfg = tcfg.get("login") or {}
                        if isinstance(login_cfg, dict) and login_cfg:
                            creds.login_username = login_cfg.get("username") or login_cfg.get("email")
                            creds.login_password = login_cfg.get("password")
                            creds.login_url = login_cfg.get("url")
                            creds.login_method = login_cfg.get("method", "auto")
                            creds.login_username_field = login_cfg.get("username_field")
                            creds.login_password_field = login_cfg.get("password_field")

        # Global login credentials (if no per-target login was found)
        if not creds.has_login_creds:
            login_cfg = data.get("login") or (global_cfg.get("login") if isinstance(global_cfg, dict) else None) or {}
            if isinstance(login_cfg, dict) and login_cfg:
                creds.login_username = login_cfg.get("username") or login_cfg.get("email")
                creds.login_password = login_cfg.get("password")
                creds.login_url = login_cfg.get("url")
                creds.login_method = login_cfg.get("method", "auto")
                creds.login_username_field = login_cfg.get("username_field")
                creds.login_password_field = login_cfg.get("password_field")

        # IDOR accounts
        idor_cfg = data.get("idor") or {}
        if isinstance(idor_cfg, dict):
            u1 = idor_cfg.get("user1") or {}
            u2 = idor_cfg.get("user2") or {}
            if u1:
                creds.idor_user1 = AuthCredentials(
                    headers=u1.get("headers") or {},
                    cookies=u1.get("cookies") or {},
                )
            if u2:
                creds.idor_user2 = AuthCredentials(
                    headers=u2.get("headers") or {},
                    cookies=u2.get("cookies") or {},
                )

        return creds

    @classmethod
    def _load_env_vars(cls) -> AuthCredentials:
        """Load credentials from environment variables."""
        creds = AuthCredentials()

        # BEATRIX_AUTH_TOKEN → Bearer token
        token = os.environ.get("BEATRIX_AUTH_TOKEN")
        if token:
            creds.bearer_token = token

        # BEATRIX_AUTH_COOKIE → raw cookie string  ("name1=val1; name2=val2")
        cookie_str = os.environ.get("BEATRIX_AUTH_COOKIE")
        if cookie_str:
            for part in cookie_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    creds.cookies[k.strip()] = v.strip()

        # BEATRIX_AUTH_HEADER → single header ("Authorization: Bearer xxx")
        header_str = os.environ.get("BEATRIX_AUTH_HEADER")
        if header_str and ":" in header_str:
            k, _, v = header_str.partition(":")
            creds.headers[k.strip()] = v.strip()

        # BEATRIX_AUTH_USER + BEATRIX_AUTH_PASS → basic auth
        user = os.environ.get("BEATRIX_AUTH_USER")
        passwd = os.environ.get("BEATRIX_AUTH_PASS")
        if user and passwd:
            creds.basic_auth = (user, passwd)

        # BEATRIX_LOGIN_USER + BEATRIX_LOGIN_PASS → auto-login credentials
        login_user = os.environ.get("BEATRIX_LOGIN_USER")
        login_pass = os.environ.get("BEATRIX_LOGIN_PASS")
        if login_user and login_pass:
            creds.login_username = login_user
            creds.login_password = login_pass
            creds.login_url = os.environ.get("BEATRIX_LOGIN_URL")

        return creds

    @classmethod
    def _parse_cli_args(
        cls,
        cookies: Optional[List[str]] = None,
        headers: Optional[List[str]] = None,
        token: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        login_user: Optional[str] = None,
        login_pass: Optional[str] = None,
        login_url: Optional[str] = None,
    ) -> AuthCredentials:
        """Parse CLI arguments into AuthCredentials."""
        creds = AuthCredentials()

        if token:
            creds.bearer_token = token

        if user and password:
            creds.basic_auth = (user, password)

        if login_user and login_pass:
            creds.login_username = login_user
            creds.login_password = login_pass
            creds.login_url = login_url

        if cookies:
            for cookie in cookies:
                if "=" in cookie:
                    k, _, v = cookie.partition("=")
                    creds.cookies[k.strip()] = v.strip()

        if headers:
            for header in headers:
                if ":" in header:
                    k, _, v = header.partition(":")
                    creds.headers[k.strip()] = v.strip()

        return creds

    @classmethod
    def _merge(cls, base: AuthCredentials, override: AuthCredentials) -> AuthCredentials:
        """Merge two AuthCredentials, with override taking precedence."""
        merged = AuthCredentials(
            headers={**base.headers, **override.headers},
            cookies={**base.cookies, **override.cookies},
            basic_auth=override.basic_auth or base.basic_auth,
            bearer_token=override.bearer_token or base.bearer_token,
            login_url=override.login_url or base.login_url,
            login_username=override.login_username or base.login_username,
            login_password=override.login_password or base.login_password,
            login_method=override.login_method or base.login_method,
            login_username_field=override.login_username_field or base.login_username_field,
            login_password_field=override.login_password_field or base.login_password_field,
            idor_user1=override.idor_user1 or base.idor_user1,
            idor_user2=override.idor_user2 or base.idor_user2,
        )
        return merged

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Extract domain from target string."""
        from urllib.parse import urlparse
        if "://" in target:
            return urlparse(target).netloc.split(":")[0]
        return target.split("/")[0].split(":")[0]

    @staticmethod
    def _target_matches(target_domain: str, pattern: str) -> bool:
        """Check if target domain matches a config pattern."""
        pattern = pattern.strip().lower()
        target = target_domain.strip().lower()
        # Exact match
        if target == pattern:
            return True
        # Subdomain match (e.g., api.example.com matches example.com)
        if target.endswith("." + pattern):
            return True
        # Wildcard (e.g., *.example.com)
        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return False

    @classmethod
    def generate_sample_config(cls) -> str:
        """Generate a sample auth.yaml config for the user."""
        return """# Beatrix Authentication Config
# Place at: ~/.beatrix/auth.yaml
# Or pass with: beatrix hunt target --auth-config /path/to/auth.yaml

# ─────────────────────────────────────────────
# Global auth — applied to ALL targets
# ─────────────────────────────────────────────
global:
  headers:
    # Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."
    # X-API-Key: "your-api-key"
  cookies:
    # session: "your-session-cookie"
    # csrf_token: "your-csrf-token"

# ─────────────────────────────────────────────
# Login credentials — Beatrix auto-logs in and captures the session
# Like Burp Suite: give username + password → Beatrix handles login
# ─────────────────────────────────────────────
login:
  # username: "your-email@example.com"   # or 'email:' — both work
  # password: "your-password"
  # url: "https://target.com/login"      # optional — auto-detected if omitted
  # method: "auto"                       # auto | form | json
  # username_field: "email"              # optional — auto-detected from form
  # password_field: "password"           # optional — auto-detected from form

# ─────────────────────────────────────────────
# Per-target auth — overrides global for specific targets
# ─────────────────────────────────────────────
targets:
  # "example.com":
  #   headers:
  #     Authorization: "Bearer target-specific-token"
  #   cookies:
  #     session: "target-session-id"
  #   login:
  #     username: "user@example.com"
  #     password: "password123"
  #     url: "https://example.com/api/auth/login"
  #     method: "json"
  #
  # "*.example.com":
  #   headers:
  #     X-API-Key: "wildcard-api-key"

# ─────────────────────────────────────────────
# IDOR testing — two different user sessions
# Required for proper access control testing
# ─────────────────────────────────────────────
idor:
  user1:
    cookies: {}
      # session: "user1-session-cookie"
    headers: {}
      # Authorization: "Bearer user1-token"
  user2:
    cookies: {}
      # session: "user2-session-cookie"
    headers: {}
      # Authorization: "Bearer user2-token"

# ─────────────────────────────────────────────
# Environment variables (alternative to this file)
# ─────────────────────────────────────────────
# BEATRIX_AUTH_TOKEN=your-bearer-token
# BEATRIX_AUTH_COOKIE="session=abc; csrf=xyz"
# BEATRIX_AUTH_HEADER="Authorization: Bearer xxx"
# BEATRIX_AUTH_USER=admin
# BEATRIX_AUTH_PASS=password123
# BEATRIX_LOGIN_USER=user@example.com
# BEATRIX_LOGIN_PASS=mypassword
# BEATRIX_LOGIN_URL=https://target.com/login
"""
