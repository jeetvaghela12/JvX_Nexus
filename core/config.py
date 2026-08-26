"""
Core: config.py
Handles environment variables, secrets, and platform-wide business rules.

This is the single source of truth for every tunable constant in the
platform -- nothing here is duplicated or re-declared elsewhere. Any other
module that needs a URL, key, or business-rule constant imports `settings`
from this module rather than reading os.environ directly or hardcoding a
value.
"""
from decimal import Decimal
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        # Fail loudly on an unrecognized key in .env (e.g. a typo'd
        # variable name) instead of silently ignoring it -- a misspelled
        # var otherwise tends to surface as a confusing "field required"
        # error on a *different* setting rather than pointing at the typo.
        extra="forbid",
    )

    # ------------------------------------------------------------------
    # App Config
    # ------------------------------------------------------------------
    APP_NAME: str = "JvX Nexus"
    ENV: str = "development"

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    # SecretStr: this URL typically embeds a password
    # (postgresql://user:pass@host/db). SecretStr keeps that out of
    # repr()/str()/logs/tracebacks -- call .get_secret_value() at the one
    # place that actually opens the connection (core/database.py); never
    # log settings.DATABASE_URL directly.
    DATABASE_URL: SecretStr

    # ------------------------------------------------------------------
    # Security & Encryption
    # ------------------------------------------------------------------
    # AES-256-GCM key for core/encryption.py's EncryptedString
    # TypeDecorator (field-level encryption on regulated PII such as
    # tax_id_number). Must be a base64-encoded 32-byte (256-bit) key --
    # generate with e.g. base64.b64encode(os.urandom(32)). SecretStr for
    # the same reason as DATABASE_URL: this is the key protecting every
    # encrypted-at-rest PII column, so it must never end up in a log line
    # or an unhandled-exception traceback. Consumers call
    # .get_secret_value() before use -- core/encryption.py's
    # _decoded_key() will need that one-line update to match this type.
    #
    # Placeholder status: production should source this from a managed KMS
    # via envelope encryption rather than a static .env value -- see the
    # KEY MANAGEMENT note in core/encryption.py.
    FIELD_ENCRYPTION_KEY: SecretStr

    # SecretStr for the same reason: a signing key must never reach a log.
    JWT_SECRET: SecretStr

    # HMAC-SHA256 key shared with the partner bank for webhook signature
    # verification. api/b2b_routes.py currently mocks this check (no real
    # secret to verify against, until now) -- this field closes that gap
    # at the config layer; wiring _verify_hmac_signature_mock to actually
    # use it is a separate change to that file, not made here. SecretStr
    # for the same reason as the other two: never let it reach a log.
    BANK_WEBHOOK_HMAC_SECRET: SecretStr
    KYC_VERIFICATION_WEBHOOK_SECRET: SecretStr
    # Protects the mock POST /kyc/verify (api/kyc_routes.py) -- a shared
    # secret an admin/internal tool (eventually a real bank callback)
    # presents via the X-Verification-Secret header. Kept as its own
    # setting, not reusing BANK_WEBHOOK_HMAC_SECRET above: these protect
    # two conceptually different callers (a bank sending payment signals,
    # vs. whatever verifies KYC), and rotating one shouldn't force
    # rotating the other.

    ADMIN_API_KEY: SecretStr
    # Protects api/admin_routes.py's POST /admin/sweep-pending -- a
    # shared secret an external cron/scheduler (AWS EventBridge, or
    # anything else that can make an HTTPS call on a timer) presents via
    # the X-Admin-Api-Key header. Kept as its own setting rather than
    # reusing KYC_VERIFICATION_WEBHOOK_SECRET above, same reasoning as
    # that setting's own comment: different caller, different rotation
    # lifecycle, and this one specifically triggers money movement
    # (dispatching settlement for every stuck PENDING row), which is a
    # meaningfully higher-stakes action than approving one user's KYC --
    # worth being able to rotate independently of anything else.

    # ------------------------------------------------------------------
    # Business Rules (Dynamic -- injected via .env after bank negotiations)
    # ------------------------------------------------------------------
    # No defaults, intentionally: these are commercial terms negotiated
    # per bank partnership, not engineering constants. Omitting a default
    # makes BaseSettings treat each one as required -- startup fails fast
    # with a clear "field required" error if .env is missing one, instead
    # of the app silently running with an undefined fee/tax/split.
    #
    # Decimal, not float: these values get multiplied directly against the
    # ledger's Numeric(18, 4)/Decimal columns in services/margin_engine.py.
    # Decimal * float raises TypeError in Python outright -- and even if it
    # didn't, float would reintroduce the exact precision risk
    # Numeric(18, 4) was adopted to eliminate. Pydantic parses the env var
    # string straight into Decimal, so .env still just holds a plain
    # string like "0.18"; nothing changes about how the value is set.
    #
    # gt=0, lt=1 assumes these are expressed as fractions (0.18, not 18) --
    # adjust the bounds if your convention is 0-100 instead.
    PLATFORM_FEE_PERCENTAGE: Decimal = Field(gt=0, lt=1)
    TAX_PERCENTAGE: Decimal = Field(gt=0, lt=1)
    NET_SPLIT_PLATFORM: Decimal = Field(gt=0, lt=1)
    NET_SPLIT_PARTNER: Decimal = Field(gt=0, lt=1)

    # ------------------------------------------------------------------
    # Cloud Provider Adapter (the "dibba" pattern)
    # ------------------------------------------------------------------
    # This string is the entire surface area for swapping cloud providers.
    # When the services layer is built, anything that talks to blob
    # storage, secrets, queues, etc. must go through a small adapter
    # factory keyed on this value (e.g. get_storage_adapter(settings.
    # CLOUD_PROVIDER)) rather than importing boto3 / azure-sdk directly in
    # business logic -- swapping AWS for Azure should mean changing this
    # one .env value and adding/selecting the matching adapter, with zero
    # changes to margin_engine.py, bank_webhook.py, or any other business
    # logic. The platform is the box ("dibba"); the cloud SDK is whatever
    # gets slotted into it.
    #
    # Literal, not str: a typo ("Azure" vs "AZURE") fails loudly at
    # startup instead of silently reaching an adapter factory that doesn't
    # recognize the value. Extend this set as new provider adapters are
    # actually built.
    # ------------------------------------------------------------------
    # Google Sign-In
    # ------------------------------------------------------------------
    GOOGLE_OAUTH_CLIENT_ID: str
    OAUTH_STATE_SECRET: SecretStr
    GOOGLE_ADSENSE_CLIENT_ID: str
    GOOGLE_ADSENSE_CLIENT_SECRET: SecretStr
    GOOGLE_ADSENSE_REDIRECT_URI: str
    COMPANIES_HOUSE_API_KEY: SecretStr
    GOOGLE_WEB_RISK_API_KEY: SecretStr
    # Deliberately plain str, NOT SecretStr -- unlike every other
    # credential in this file, an OAuth *client ID* (as opposed to a
    # client *secret*) is designed to be public. It's embedded directly
    # in frontend JavaScript/mobile app code for the "Sign in with
    # Google" button to work at all, so wrapping it as a secret here
    # would be misleading about what it actually protects. This is the
    # value api/auth_routes.py checks every incoming Google ID token's
    # "aud" (audience) claim against, confirming the token was actually
    # issued for THIS application and not silently accepting a token
    # meant for some other app.

    CLOUD_PROVIDER: Literal["AWS", "AZURE"] = "AWS"

    COMPLIANCE_MODE: Literal["mock", "real"]
    # No default -- same reasoning as COMPLYADVANTAGE_BASE_URL below:
    # defaulting to either value silently would be worse than forcing an
    # explicit choice every time this app starts. "mock" is for LOCAL
    # TESTING AND DEMO RECORDING ONLY, when real Cashfree/ComplyAdvantage/
    # AWS credentials aren't available yet -- it makes verify_pan_linkage,
    # screen_aml_watchlists, and extract_invoice_metadata in
    # services/compliance_engine.py return deterministic local results
    # instead of making real network calls. The actual safety mechanism
    # against this reaching production isn't this field alone -- it's
    # compliance_engine.py's _compliance_mode_is_mock(), which refuses to
    # honor "mock" at all when ENV=production, hard-stopping instead.

    # ------------------------------------------------------------------
    # Compliance Engine Providers (Cashfree, ComplyAdvantage, AWS Textract)
    # ------------------------------------------------------------------
    # None of these have real values behind them yet -- PLACEHOLDERS,
    # per services/compliance_engine.py's own module docstring. Required
    # (no default) rather than optional: unlike VAM_PROVIDER's mock/real
    # switch in bank_onboarding_client.py, these four functions have no
    # local-only fallback anymore, so a missing value here means every
    # KYC submission, bank-account addition, and invoice upload fails
    # loudly at first use rather than silently degrading.
    CASHFREE_CLIENT_ID: SecretStr
    CASHFREE_CLIENT_SECRET: SecretStr
    CASHFREE_BASE_URL: str = "https://api.cashfree.com"
    # Production host by default -- override to Cashfree's sandbox
    # subdomain for testing against non-live data.

    COMPLYADVANTAGE_API_KEY: SecretStr
    COMPLYADVANTAGE_BASE_URL: str
    # No default: ComplyAdvantage is region-specific (EU/US/APAC hosts),
    # and defaulting to the wrong region silently would be worse than
    # forcing an explicit choice.

    AWS_TEXTRACT_REGION: str = "ap-south-1"
    # Mumbai -- the natural default for an India-based platform's data
    # residency, but per AWS's own documented service quotas, this region
    # is throttled to 1 synchronous AnalyzeExpense transaction/second,
    # versus 5 TPS in us-east-1/us-west-2. Worth a deliberate choice, not
    # an assumption, once real invoice volume matters.
    # AWS credentials themselves are NOT a settings field here -- boto3
    # resolves them via its own standard chain (environment variables,
    # ~/.aws/credentials, or an IAM role). Adding an AWS_ACCESS_KEY_ID
    # field here would just be a second, redundant, easier-to-leak place
    # for the same credential to live.

    # ------------------------------------------------------------------
    # Virtual Account Provider Adapter (same "dibba" pattern as CLOUD_PROVIDER)
    # ------------------------------------------------------------------
    # services/bank_onboarding_client.py reads this to decide which
    # VirtualAccountProvider implementation to construct. "mock" preserves
    # existing behavior with zero new required config -- every field below
    # is optional at the Settings level and only enforced (by the
    # validator further down) when VAM_PROVIDER is actually set to a real
    # provider. api/kyc_routes.py and api/b2b_routes.py never reference
    # "decentro" by name -- they only ever talk to the VirtualAccountProvider
    # interface, so adding a second real provider later means adding
    # another Literal value and another settings block here, not touching
    # either route file.
    VAM_PROVIDER: Literal["mock", "decentro_sandbox"] = "mock"

    # Decentro v3 stack specifically -- confirmed directly against
    # Decentro's own current API reference (not the older v1/v2 stack,
    # which uses a different base URL and a different, four-header
    # auth scheme entirely). Sandbox base URL is Decentro's documented
    # constant; production would be https://api.decentro.tech.
    DECENTRO_BASE_URL: str = "https://staging.api.decentro.tech"
    DECENTRO_CLIENT_ID: SecretStr | None = None
    DECENTRO_CLIENT_SECRET: SecretStr | None = None
    # consumer_urn: assigned BY Decentro during onboarding -- not
    # something generated locally. Check the Decentro dashboard, or the
    # onboarding email/thread, for this value; virtual account creation
    # fails immediately without it (error_invalid_consumer_urn /
    # error_missing_key_consumer_urn per Decentro's own documented error
    # list).
    DECENTRO_CONSUMER_URN: str | None = None
    # ADDED after a live 401 (error_authentication_failed): Decentro's v3
    # Create Virtual Account reference page only documents client_id/
    # client_secret as headers, but what Decentro's own onboarding team
    # actually issues includes two more secrets their v3 docs don't
    # mention needing -- confirmed against a real, live curl example on
    # Decentro's own India docs site (a v2 balance-check endpoint) using
    # the exact header name module_secret with placeholder text
    # "YOUR_CORE_BANKING_MODULE_SECRET", matching what was issued here.
    # "YBL" = Yes Bank Limited, which matches Decentro's own statement
    # elsewhere in their docs that Yes Bank is currently the sole provider
    # for v3 virtual accounts -- provider_secret is very likely the
    # per-provider counterpart to module_secret. This is a well-evidenced
    # hypothesis based on real, live error output and Decentro's own
    # documentation, not a confirmed fact -- flagging that distinction
    # explicitly rather than overstating certainty this code can't
    # actually verify without your next live test.
    # Two module secrets kept, not one -- your onboarding email issued
    # BOTH "Core Banking Module Secret" and "Payments Module Secret".
    # CORE_BANKING was tried first (URL path says /v3/banking/...) and
    # still 401'd. PAYMENTS is the current hypothesis instead, since
    # Decentro's own docs sidebar files this exact endpoint under
    # Payments -> Virtual Account Collections v3, not under a Core
    # Banking heading -- the URL name and Decentro's own categorization
    # disagree, and only one of these two guesses has actually failed so
    # far. bank_onboarding_client.py currently sends
    # DECENTRO_PAYMENTS_MODULE_SECRET as the module_secret header; the
    # Core Banking one stays here, populated, so switching back is a
    # one-line change in that file rather than another round of hunting
    # down the value again.
    DECENTRO_CORE_BANKING_MODULE_SECRET: SecretStr | None = None
    DECENTRO_PAYMENTS_MODULE_SECRET: SecretStr | None = None
    DECENTRO_PROVIDER_SECRET: SecretStr | None = None  # "Ybl Provider Secret"
    # Decentro's webhook auth is NOT HMAC -- unlike BANK_WEBHOOK_HMAC_SECRET
    # above, which signs the request body, Decentro's callback docs
    # describe a shared custom header name/value pair that the platform
    # itself defines and shares with Decentro's team (currently by email,
    # not a self-serve API/dashboard step, per their documented onboarding
    # flow). The name is intentionally an env-configurable field, not a
    # fixed constant, since the platform picks that name when registering
    # the callback with Decentro.
    DECENTRO_WEBHOOK_HEADER_NAME: str | None = None
    DECENTRO_WEBHOOK_HEADER_VALUE: SecretStr | None = None

    @model_validator(mode="after")
    def _decentro_settings_required_when_selected(self) -> "Settings":
        """
        Fail loudly at startup if VAM_PROVIDER=decentro_sandbox is chosen
        without the credentials it needs, rather than failing later, more
        confusingly, on the first real API call.
        """
        if self.VAM_PROVIDER == "decentro_sandbox":
            missing = [
                name
                for name, value in (
                    ("DECENTRO_CLIENT_ID", self.DECENTRO_CLIENT_ID),
                    ("DECENTRO_CLIENT_SECRET", self.DECENTRO_CLIENT_SECRET),
                    ("DECENTRO_CONSUMER_URN", self.DECENTRO_CONSUMER_URN),
                    ("DECENTRO_CORE_BANKING_MODULE_SECRET", self.DECENTRO_CORE_BANKING_MODULE_SECRET),
                    ("DECENTRO_PAYMENTS_MODULE_SECRET", self.DECENTRO_PAYMENTS_MODULE_SECRET),
                    ("DECENTRO_PROVIDER_SECRET", self.DECENTRO_PROVIDER_SECRET),
                )
                if value is None
            ]
            if missing:
                raise ValueError(
                    f"VAM_PROVIDER is set to 'decentro_sandbox' but missing: {', '.join(missing)}. "
                    "DECENTRO_WEBHOOK_HEADER_NAME/VALUE are also needed once the webhook side is "
                    "registered with Decentro, though account creation alone doesn't need them yet."
                )
        return self

    @model_validator(mode="after")
    def _revenue_split_must_sum_to_one(self) -> "Settings":
        """
        Locks the platform / partner-bank split: the two shares of the net
        fee must always account for exactly the whole net fee, with
        nothing lost or double-counted. Runs after field parsing, so both
        values are already Decimal here -- an exact equality check, not a
        float tolerance/epsilon comparison, because Decimal arithmetic is
        exact.
        """
        total = self.NET_SPLIT_PLATFORM + self.NET_SPLIT_PARTNER
        if total != Decimal("1.0"):
            raise ValueError(
                "NET_SPLIT_PLATFORM + NET_SPLIT_PARTNER must equal 1.0 exactly "
                f"(got {self.NET_SPLIT_PLATFORM} + {self.NET_SPLIT_PARTNER} = {total}). "
                "Check the values injected via .env."
            )
        return self


settings = Settings()