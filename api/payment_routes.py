"""
API: payment_routes.py

What the customer sees about money arriving — read-only, every one of
them.

This is the surface the bank renders inside its own app. Nothing here
creates, modifies, or advances a payment: those events originate at the
bank and reach us through the webhook. A write endpoint in this file would
mean this service had started to believe it controls money it does not
touch.
"""
import logging
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.declaration_model import Declaration
from models.payment_model import InboundPayment
from models.user_model import User
from schemas.payment_schemas import PaymentResponse, PaymentSummary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/payments", tags=["Payments"])


def _to_response(payment: InboundPayment, declaration_reference: str | None) -> PaymentResponse:
    return PaymentResponse(
        bank_reference=payment.bank_reference,
        status=payment.status,
        amount=payment.amount,
        currency=payment.currency,
        payer_name=payment.payer_name,
        payer_country=payment.payer_country,
        credited_amount_inr=payment.credited_amount_inr,
        exchange_rate=payment.exchange_rate,
        purpose_code=payment.purpose_code,
        fira_reference=payment.fira_reference,
        fira_issued_at=payment.fira_issued_at,
        declaration_reference=declaration_reference,
        bank_remark=payment.bank_remark,
        received_at=payment.received_at,
    )


@router.get("", response_model=list[PaymentResponse])
def list_payments(
    status: str | None = Query(None, pattern="^(RECEIVED|CREDITED|RETURNED|ON_HOLD)$"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[PaymentResponse]:
    """
    This user's payments, newest first.

    One LEFT JOIN rather than a query per row for the declaration
    reference. Fifty payments would otherwise mean fifty-one round trips,
    and that pattern is invisible in development against ten rows and
    obvious in production against ten thousand.
    """
    query = (
        select(InboundPayment, Declaration.reference)
        .outerjoin(Declaration, InboundPayment.declaration_id == Declaration.id)
        .where(InboundPayment.user_id == current_user.id)
    )
    if status is not None:
        query = query.where(InboundPayment.status == status)

    query = query.order_by(InboundPayment.received_at.desc()).limit(limit)

    return [_to_response(payment, reference) for payment, reference in db.execute(query).all()]


@router.get("/summary", response_model=PaymentSummary)
def payment_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaymentSummary:
    """
    Header figures for the dashboard.

    Aggregated in the database rather than by loading rows and counting in
    Python. The difference does not show at ten payments and is the whole
    difference at ten thousand.
    """
    counts = db.execute(
        select(InboundPayment.status, func.count(InboundPayment.id))
        .where(InboundPayment.user_id == current_user.id)
        .group_by(InboundPayment.status)
    ).all()

    by_status = {status: count for status, count in counts}

    credited_total = db.execute(
        select(func.coalesce(func.sum(InboundPayment.credited_amount_inr), 0)).where(
            InboundPayment.user_id == current_user.id,
            InboundPayment.status == "CREDITED",
        )
    ).scalar_one()

    return PaymentSummary(
        total_received_count=sum(by_status.values()),
        total_credited_count=by_status.get("CREDITED", 0),
        on_hold_count=by_status.get("ON_HOLD", 0),
        credited_total_inr=Decimal(credited_total),
    )


@router.get("/{bank_reference}", response_model=PaymentResponse)
def get_payment(
    bank_reference: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaymentResponse:
    row = db.execute(
        select(InboundPayment, Declaration.reference)
        .outerjoin(Declaration, InboundPayment.declaration_id == Declaration.id)
        .where(
            InboundPayment.bank_reference == bank_reference,
            InboundPayment.user_id == current_user.id,
        )
    ).one_or_none()

    if row is None:
        # Same 404 whether it does not exist or belongs to another user.
        raise HTTPException(status_code=404, detail="Payment not found.")

    payment, declaration_reference = row
    return _to_response(payment, declaration_reference)