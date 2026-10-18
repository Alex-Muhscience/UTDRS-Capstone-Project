from typing import List, Literal, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # MongoDB
    MONGODB_URI: str
    DB_NAME: str = "utdrs"

    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # App
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "UTDRS API Gateway"
    VERSION: str = "1.0.0"
    ALLOWED_HOSTS: List[str] = ["*"]

    # Browser origins allowed to call the API with credentials. Set as a JSON list,
    # e.g. CORS_ORIGINS='["https://dashboard.example.com"]'. Never "*" with credentials.
    CORS_ORIGINS: List[str] = ["http://localhost:3001", "http://localhost:5173"]
    # Also allowed: origins matching this regular expression, for hosts whose preview
    # deployments get their own names (e.g. a Vercel project's previews).
    CORS_ORIGIN_REGEX: Optional[str] = None

    # Proxies in front of the gateway whose X-Forwarded-For header is believed, as a
    # JSON list of addresses or networks, e.g. '["10.0.0.0/8"]'. Without them, a client's
    # address is the connection's, and anyone could claim any address in the header.
    TRUSTED_PROXIES: List[str] = []

    # Sign-in throttling: failed attempts allowed in LOGIN_FAILURE_WINDOW_SECONDS, for one
    # account from one address, and from one address across all accounts.
    LOGIN_MAX_FAILURES_PER_ACCOUNT: int = 5
    LOGIN_MAX_FAILURES_PER_ADDRESS: int = 50
    LOGIN_FAILURE_WINDOW_SECONDS: int = 900

    # Tenancy: each organisation's data is kept apart (core/tenancy.py).
    # The tenant a single-organisation deployment uses, created at start-up.
    DEFAULT_TENANT_SLUG: str = "default"
    DEFAULT_TENANT_NAME: str = "Default organisation"
    # Self-registration (ALLOW_REGISTRATION): "join" adds an analyst to the default
    # tenant; "organisation" creates a new tenant with the person as its administrator.
    REGISTRATION_MODE: Literal["join", "organisation"] = "join"
    # The tenant device scans are recorded in, by slug (unset: the default tenant).
    SCANS_TENANT: Optional[str] = None

    # Accounts
    # When false, only administrators can create accounts (POST /users/).
    ALLOW_REGISTRATION: bool = True
    # The first administrator: on startup, this account is created as an admin if it
    # does not exist, or made an active admin if it does. Its password is only used
    # when creating it, so a password changed later is kept.
    ADMIN_USERNAME: Optional[str] = None
    ADMIN_EMAIL: Optional[str] = None
    ADMIN_PASSWORD: Optional[str] = None

    # Integration services
    # When CORE_ENGINE_URL is set, every ingested event is sent to the core engine for
    # detection, and any threat it finds becomes an alert here.
    CORE_ENGINE_URL: Optional[str] = None

    @field_validator("CORE_ENGINE_URL")
    @classmethod
    def _engine_scheme(cls, value: Optional[str]) -> Optional[str]:
        # Hosts that hand out "host:port" for a private network address (Render) need a scheme.
        if value and "://" not in value:
            return f"http://{value}"
        return value
    CORE_ENGINE_TIMEOUT_SECONDS: float = 10.0
    # Shared secret sent to the core engine as X-Internal-Token (must match its setting).
    INTERNAL_API_TOKEN: Optional[str] = None
    # How often the detection rules are re-sent to the core engine, besides after each change.
    RULE_SYNC_INTERVAL_SECONDS: int = 60

    # Email notifications (core/services/notifications.py). Without SMTP_HOST, nothing is
    # sent, and each notification is logged as skipped.
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    # "starttls" (port 587), "ssl" (port 465) or "none" (a local relay only).
    SMTP_SECURITY: Literal["starttls", "ssl", "none"] = "starttls"
    MAIL_FROM: str = "UTDRS <utdrs@localhost>"
    # Where the dashboard is, for links in emails.
    DASHBOARD_URL: str = "http://localhost:3001"
    # How often the outbox is checked for email to send, and the most emails one person
    # is sent in an hour (beyond it, notifications are logged as skipped).
    NOTIFY_INTERVAL_SECONDS: int = 10
    NOTIFY_MAX_PER_USER_PER_HOUR: int = 30
    # How often the gateway checks whether last month's reports are due (made on the 1st).
    REPORT_CHECK_INTERVAL_SECONDS: int = 3600

    # Data retention (core/services/retention.py): how many days each kind of data is
    # kept by default, the longest an organisation may choose, and how often to check.
    RETENTION_EVENTS_DAYS: int = 90
    RETENTION_ALERTS_DAYS: int = 365  # closed alerts and cases, and response actions
    RETENTION_NOTIFICATIONS_DAYS: int = 90
    RETENTION_LABELS_DAYS: int = 730
    RETENTION_MAX_DAYS: int = 730
    RETENTION_INTERVAL_SECONDS: int = 3600

    # Webhooks (core/services/webhooks.py): how often due deliveries are sent, and whether
    # receivers may be on private networks (only for a deployment's own receivers).
    WEBHOOK_INTERVAL_SECONDS: int = 5
    WEBHOOK_ALLOW_PRIVATE_ADDRESSES: bool = False

    # Encrypting secrets stored in the database (utils/crypto.py): 32 random bytes,
    # base64 (openssl rand -base64 32). When rotating, put the old key in _PREVIOUS.
    ENCRYPTION_KEY: Optional[str] = None
    ENCRYPTION_KEY_PREVIOUS: Optional[str] = None

    # Microsoft 365 (core/services/m365.py). An organisation connects either by admin
    # consent to UTDRS's own app registration (these two settings), or with an app
    # registration of its own.
    M365_CLIENT_ID: Optional[str] = None
    M365_CLIENT_SECRET: Optional[str] = None
    M365_LOGIN_URL: str = "https://login.microsoftonline.com"
    M365_GRAPH_URL: str = "https://graph.microsoft.com/v1.0"
    M365_MANAGEMENT_URL: str = "https://manage.office.com/api/v1.0"
    # How often sign-ins, audit logs and Defender alerts are fetched.
    M365_POLL_INTERVAL_SECONDS: int = 300


settings = Settings()
