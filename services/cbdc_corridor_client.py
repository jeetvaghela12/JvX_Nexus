"""
Services: cbdc_corridor_client.py
The CorridorProvider Protocol -- scaffolding for a future bank/bridge DLT
node, mirroring services/bank_onboarding_client.py's VirtualAccountProvider
pattern for the cross-border CBDC corridor concept instead.

PERMANENTLY MOCK, NOT "PENDING CREDENTIALS" -- read this before assuming
this file will eventually get a "real" sibling implementation the way
bank_onboarding_client.py's Decentro class sits next to its Mock. There is
no corridor to sign up for, no sandbox, no vendor -- confirmed by
dedicated research: India isn't a confirmed mBridge participant, RBI's own
2025-26 Annual Report describes bilateral CBDC discussions (not
operational pilots) with Singapore's MAS and the UAE's central bank, and
any eventual corridor access will belong to a participating BANK, not to
a technology vendor. This file exists so the REST of a future integration
-- routes, AtomicFxSwap's lifecycle, ledger-linking -- can be built and
tested against a stable, predictable interface now, well before any real
provider is likely to exist for a TSP to plug into. When a bank partner
eventually gets real corridor access, the actual integration work is
writing one new class that implements CorridorProvider -- not redesigning
this interface.

No is_mock field on the results below, unlike compliance_engine.py before
its production rewrite -- this file was never asked to stop being a mock,
and mirrors bank_onboarding_client.py's own pattern instead: the provider
CLASS (Mock vs. a real implementation, once one can exist) conveys
mock-vs-real status, not a field on every result.
"""
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Protocol

from models.cbdc_model import CbdcWallet
from models.user_model import User

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class WalletProvisionResult:
    success: bool
    wallet_address: str | None
    provider_reference: str | None
    error_message: str | None


@dataclass(frozen=True, slots=True)
class AtomicSwapResult:
    success: bool
    destination_amount: Decimal | None
    fx_rate_applied: Decimal | None
    # Both returned by the provider, not supplied by the caller: a real
    # corridor provider is the party actually executing the swap and
    # quoting the live rate -- the caller specifies source_amount and
    # asks "how much lands on the other side," it doesn't get to declare
    # the rate itself.
    settled_at: datetime | None
    provider_reference: str | None
    error_message: str | None


class CorridorProvider(Protocol):
    def provision_wallet(self, user: User, cbdc_type: str) -> WalletProvisionResult: ...

    def execute_atomic_swap(
        self,
        source_wallet: CbdcWallet,
        source_amount: Decimal,
        destination_wallet: CbdcWallet,
    ) -> AtomicSwapResult: ...


class MockCorridorProvider:
    """See this module's docstring -- this is the only implementation that will exist for the foreseeable future, not a stand-in for a real one already chosen."""

    def provision_wallet(self, user: User, cbdc_type: str) -> WalletProvisionResult:
        fake_address = f"MOCK-CBDC-{cbdc_type}-{user.id:06d}"
        return WalletProvisionResult(
            success=True,
            wallet_address=fake_address,
            provider_reference=f"mock-provision-{uuid.uuid4().hex[:8]}",
            error_message=None,
        )

    def execute_atomic_swap(
        self,
        source_wallet: CbdcWallet,
        source_amount: Decimal,
        destination_wallet: CbdcWallet,
    ) -> AtomicSwapResult:
        # Deterministic 1:1 mock rate -- no real FX quoting exists to
        # simulate meaningfully; this exists to exercise the calling
        # code's shape (how a route would consume this result), not to
        # produce a realistic exchange rate.
        mock_rate = Decimal("1.0")
        return AtomicSwapResult(
            success=True,
            destination_amount=source_amount * mock_rate,
            fx_rate_applied=mock_rate,
            settled_at=datetime.now(timezone.utc),
            provider_reference=f"mock-swap-{uuid.uuid4().hex[:8]}",
            error_message=None,
        )


def get_corridor_provider() -> CorridorProvider:
    """
    Always returns MockCorridorProvider today -- no settings.
    CBDC_CORRIDOR_PROVIDER switch exists the way VAM_PROVIDER does for
    bank_onboarding_client.py, since there is only one implementation to
    choose between right now. Still a factory function, matching that
    file's pattern anyway, so a real provider -- once one can plausibly
    exist -- slots in as a second branch here without any caller needing
    to change.
    """
    return MockCorridorProvider()