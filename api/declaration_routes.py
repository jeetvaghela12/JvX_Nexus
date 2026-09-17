"""
API: declaration_routes.py

Pre-declarations and self-declarations.

A pre-declaration is filed before the money arrives, so the bank has
context when it lands rather than after. A self-declaration covers money
with no formal invoice behind it, which FEMA still requires a stated
purpose for.

DUPLICATE HANDLING mirrors the invoice upload deliberately: a fingerprint
check for the fast, readable rejection, and a unique constraint plus
IntegrityError catch as the actual guarantee. Two concurrent requests will
both pass the check; only one survives the insert. The database is the
authority, the pre-check is the courtesy.
"""
import hashlib
import logging
import secrets
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.compliance_model import CommercialInvoice
from models.declaration_model import Declaration
from models.user_model import User
from schemas.declaration_schemas import (
    DeclarationResponse,
    PreDeclarationCreate,
    SelfDeclarationCreate,
    SelfDeclarationReceipt,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/declarations", tags=["Declarations"])


def _fingerprint(
    user_id: int,
    kind: str,
    amount: Decimal,
    currency: str,
    payer_name: str,
    purpose_code: str,
) -> str:
    """
    A content hash over the fields that define what is being claimed.

    Same principle as the invoice content fingerprint, adapted to a record
    with no file behind it. Normalisation matters more than the hash: a
    payer written "Acme Corp" and "  ACME CORP  " is the same payer, and a
    fingerprint that treats them as different catches nothing.

    Amount is normalised to a fixed 4 decimal places, because Decimal
    preserves trailing zeros and "2000" and "2000.0000" would otherwise
    produce different hashes for identical money.
    """
    normalized = "|".join(
        [
            str(user_id),
            kind,
            f"{amount:.4f}",
            currency.upper(),
            " ".join(payer_name.split()).upper(),
            purpose_code.upper(),
        ]
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _make_reference(kind: str) -> str:
    """
    A short, human-quotable identifier. JVX-PD-... or JVX-SD-...

    Random rather than sequential on purpose: a sequential reference tells
    anyone holding one roughly how many declarations exist and lets them
    guess their neighbours', which is free intelligence handed to someone
    who should not have it.
    """
    prefix = "PD" if kind == "PRE_PAYMENT" else "SD"
    return f"JVX-{prefix}-{secrets.token_hex(4).upper()}"


def _persist(db: Session, declaration: Declaration) -> Declaration:
    try:
        db.add(declaration)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An identical declaration already exists.",
        )
    except Exception:
        db.rollback()
        logger.exception("Failed to persist declaration for user_id=%s", declaration.user_id)
        raise
    db.refresh(declaration)
    return declaration


@router.post("/pre-payment", response_model=DeclarationResponse, status_code=201)
def create_pre_declaration(
    payload: PreDeclarationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Declaration:
    """
    Tell the bank about money before it arrives.

    HYPOTHESIS, stated plainly because it has not been tested against a
    real bank: giving the bank purpose and payer context in advance should
    reduce how often an inbound payment is held or queried on arrival.
    That is the claim this endpoint exists to let a pilot measure. It is
    not a proven result and must not be presented as one.
    """
    if payload.invoice_id is not None:
        # Confirm the invoice exists AND belongs to this user. Checking
        # only existence would let any authenticated caller attach their
        # declaration to a stranger's invoice by guessing an id.
        invoice = db.execute(
            select(CommercialInvoice).where(
                CommercialInvoice.id == payload.invoice_id,
                CommercialInvoice.user_id == current_user.id,
            )
        ).scalar_one_or_none()
        if invoice is None:
            raise HTTPException(status_code=404, detail="Invoice not found.")

    fingerprint = _fingerprint(
        current_user.id,
        "PRE_PAYMENT",
        payload.expected_amount,
        payload.currency,
        payload.payer_name,
        payload.purpose_code,
    )

    existing = db.execute(
        select(Declaration).where(Declaration.content_fingerprint == fingerprint)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"You have already filed this declaration ({existing.reference}).",
        )

    return _persist(
        db,
        Declaration(
            reference=_make_reference("PRE_PAYMENT"),
            user_id=current_user.id,
            kind="PRE_PAYMENT",
            status="FILED",
            expected_amount=payload.expected_amount,
            currency=payload.currency,
            payer_name=payload.payer_name,
            payer_country=payload.payer_country,
            purpose_code=payload.purpose_code,
            description=payload.description,
            expected_by=payload.expected_by,
            invoice_id=payload.invoice_id,
            content_fingerprint=fingerprint,
        ),
    )


@router.post("/self", response_model=SelfDeclarationReceipt, status_code=201)
def create_self_declaration(
    payload: SelfDeclarationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SelfDeclarationReceipt:
    """
    Declare money that has no invoice behind it.

    The response carries the disclaimer. Any surface rendering this as a
    document must render that line with it — see the note on the model.
    """
    fingerprint = _fingerprint(
        current_user.id,
        "SELF_DECLARATION",
        payload.expected_amount,
        payload.currency,
        payload.payer_name,
        payload.purpose_code,
    )

    existing = db.execute(
        select(Declaration).where(Declaration.content_fingerprint == fingerprint)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"You have already filed this declaration ({existing.reference}).",
        )

    declaration = _persist(
        db,
        Declaration(
            reference=_make_reference("SELF_DECLARATION"),
            user_id=current_user.id,
            kind="SELF_DECLARATION",
            status="FILED",
            expected_amount=payload.expected_amount,
            currency=payload.currency,
            payer_name=payload.payer_name,
            payer_country=payload.payer_country,
            purpose_code=payload.purpose_code,
            description=payload.description,
            content_fingerprint=fingerprint,
        ),
    )

    return SelfDeclarationReceipt(
        reference=declaration.reference,
        kind=declaration.kind,
        status=declaration.status,
        expected_amount=declaration.expected_amount,
        currency=declaration.currency,
        payer_name=declaration.payer_name,
        purpose_code=declaration.purpose_code,
        description=declaration.description,
        expected_by=declaration.expected_by,
        matched_payment_id=declaration.matched_payment_id,
        created_at=declaration.created_at,
        disclaimer=declaration.disclaimer,
    )


@router.get("", response_model=list[DeclarationResponse])
def list_declarations(
    kind: str | None = Query(None, pattern="^(PRE_PAYMENT|SELF_DECLARATION)$"),
    status: str | None = Query(None, pattern="^(FILED|MATCHED|EXPIRED|WITHDRAWN)$"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Declaration]:
    """
    This user's declarations, newest first.

    The user_id filter is not optional and is not a parameter. It comes
    from the verified token, never from the request, so there is no shape
    of query string that can reach another user's records.
    """
    query = select(Declaration).where(Declaration.user_id == current_user.id)
    if kind is not None:
        query = query.where(Declaration.kind == kind)
    if status is not None:
        query = query.where(Declaration.status == status)

    query = query.order_by(Declaration.created_at.desc()).limit(limit)
    return list(db.execute(query).scalars().all())


@router.get("/{reference}", response_model=DeclarationResponse)
def get_declaration(
    reference: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Declaration:
    declaration = db.execute(
        select(Declaration).where(
            Declaration.reference == reference,
            Declaration.user_id == current_user.id,
        )
    ).scalar_one_or_none()

    if declaration is None:
        # 404 whether it does not exist or belongs to someone else.
        # Distinguishing the two would confirm to a caller that a
        # reference they guessed is real, which is exactly the signal an
        # enumeration attempt is looking for.
        raise HTTPException(status_code=404, detail="Declaration not found.")

    return declaration


@router.post("/{reference}/withdraw", response_model=DeclarationResponse)
def withdraw_declaration(
    reference: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Declaration:
    """
    Withdraw a declaration filed in error.

    Withdrawn, never deleted. A declaration is a statement made to a bank;
    the record that it was made and then retracted is itself part of the
    compliance trail, and destroying it would remove evidence the customer
    may later need.
    """
    declaration = db.execute(
        select(Declaration).where(
            Declaration.reference == reference,
            Declaration.user_id == current_user.id,
        )
    ).scalar_one_or_none()

    if declaration is None:
        raise HTTPException(status_code=404, detail="Declaration not found.")

    if declaration.status == "MATCHED":
        raise HTTPException(
            status_code=409,
            detail="This declaration has already been matched to a payment and cannot be withdrawn.",
        )
    if declaration.status == "WITHDRAWN":
        return declaration

    declaration.status = "WITHDRAWN"
    db.commit()
    db.refresh(declaration)
    return declaration