"""
demo_app.py — RemitCore

The surface a partner bank renders inside its own application. Calls the
live API over HTTP; nothing on this screen is mocked.

Design note: display is rendered as custom HTML rather than Streamlit
widgets wherever possible. Streamlit's defaults are recognisable, and a
product whose entire argument is "the bank's interface is from 2011"
cannot afford to look like a prototype.
"""
import datetime
from decimal import Decimal

import requests
import streamlit as st

API = "http://127.0.0.1:8000"

st.set_page_config(page_title="Export Collections", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --navy:#0A1F44; --navy-soft:#1B3565; --ink:#101828; --muted:#667085;
    --line:#E4E7EC; --line-soft:#F2F4F7; --paper:#FBFBFC;
    --green:#05603A; --green-bg:#ECFDF3;
    --amber:#B54708; --amber-bg:#FFFAEB;
    --red:#B42318; --red-bg:#FEF3F2;
    --serif:'Newsreader',Georgia,serif;
    --sans:'Inter',-apple-system,sans-serif;
    --mono:'JetBrains Mono',Consolas,monospace;
  }
[data-testid="stHeader"]{background:transparent; height:0;}
  [data-testid="stToolbar"]{display:none;}
  #MainMenu{visibility:hidden;}
  .stApp {background:var(--paper);}
  .block-container {padding:2rem 2rem 3rem; max-width:1180px;}
  .stApp, .stApp p, .stApp span, .stApp label {font-family:var(--sans);}

  .bar{background:var(--navy); border-radius:12px; padding:18px 26px;
    display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;}
  .bar-l{display:flex; align-items:baseline; gap:14px;}
  .bar-title{font-family:var(--serif); font-size:21px; color:#fff; letter-spacing:-.01em;}
  .bar-div{width:1px; height:16px; background:rgba(255,255,255,.22);}
  .bar-sub{font-size:12.5px; color:#93A6CC;}
  .bar-r{font-size:12.5px; color:#93A6CC; display:flex; align-items:center; gap:7px;}
  .dot{width:6px; height:6px; border-radius:50%; background:#35C08A;}

  .acct{background:linear-gradient(135deg,#0A1F44 0%,#1B3565 100%);
    border-radius:14px; padding:26px 30px; color:#fff; min-height:186px;
    display:flex; flex-direction:column; justify-content:space-between;}
  .acct-label{font-size:11px; letter-spacing:.09em; text-transform:uppercase; color:#93A6CC; margin-bottom:14px;}
  .acct-num{font-family:var(--mono); font-size:26px; font-weight:500; letter-spacing:.02em; line-height:1.25;}
  .acct-meta{margin-top:20px; padding-top:16px; border-top:1px solid rgba(255,255,255,.14);
    display:flex; justify-content:space-between; font-size:12.5px; color:#93A6CC;}
  .acct-empty{font-family:var(--serif); font-size:20px; color:#93A6CC;}

  .tiles{display:grid; grid-template-columns:repeat(3,1fr); gap:13px;}
  .tile{background:#fff; border:1px solid var(--line); border-radius:12px; padding:17px 19px;}
  .tile-label{font-size:11px; letter-spacing:.07em; text-transform:uppercase; color:var(--muted);}
  .tile-value{font-family:var(--serif); font-size:30px; color:var(--navy); margin-top:6px; line-height:1;}
  .tile-note{font-size:12px; color:var(--muted); margin-top:7px;}
  .total{background:#fff; border:1px solid var(--line); border-radius:12px; padding:17px 21px;
    margin-top:13px; display:flex; justify-content:space-between; align-items:baseline;}
  .total-label{font-size:13px; color:var(--muted);}
  .total-value{font-family:var(--serif); font-size:28px; color:var(--navy);}

  .sec{font-family:var(--serif); font-size:19px; color:var(--ink); margin:32px 0 4px; letter-spacing:-.01em;}
  .sec-sub{font-size:13.5px; color:var(--muted); margin-bottom:15px; line-height:1.55;}

  .rows{background:#fff; border:1px solid var(--line); border-radius:12px; overflow:hidden;}
  .row{display:grid; grid-template-columns:2.1fr 1.4fr 1fr 1.5fr; gap:18px;
    padding:17px 22px; align-items:center; border-bottom:1px solid var(--line-soft);}
  .row:last-child{border-bottom:none;}
  .r-payer{font-size:14.5px; font-weight:500; color:var(--ink);}
  .r-date{font-size:12px; color:var(--muted); margin-top:2px;}
  .r-amt{font-family:var(--serif); font-size:18px; color:var(--ink);}
  .r-inr{font-size:12px; color:var(--muted); margin-top:2px;}
  .r-meta{font-size:12.5px; color:var(--muted); text-align:right;}
  .r-meta b{color:var(--ink); font-weight:500;}

  .pill{display:inline-block; padding:3px 11px; border-radius:16px; font-size:11.5px; font-weight:500;}
  .p-credited{background:var(--green-bg); color:var(--green);}
  .p-received{background:var(--line-soft); color:var(--muted);}
  .p-hold{background:var(--amber-bg); color:var(--amber);}
  .p-returned{background:var(--red-bg); color:var(--red);}
  .p-filed{background:var(--line-soft); color:var(--muted);}
  .p-matched{background:var(--green-bg); color:var(--green);}

  .empty{background:#fff; border:1px dashed var(--line); border-radius:12px; padding:44px 30px; text-align:center;}
  .empty-t{font-family:var(--serif); font-size:17px; color:var(--ink);}
  .empty-s{font-size:13.5px; color:var(--muted); margin-top:7px; max-width:46ch;
    margin-left:auto; margin-right:auto; line-height:1.55;}

  .res{border-radius:12px; padding:20px 24px; margin-top:10px;}
  .res-ok{background:var(--green-bg); border:1px solid #A6F4C5;}
  .res-no{background:var(--red-bg); border:1px solid #FECDCA;}
  .res-t{font-family:var(--serif); font-size:19px; margin-bottom:5px;}
  .res-ok .res-t{color:var(--green);} .res-no .res-t{color:var(--red);}
  .res-b{font-size:13.5px; line-height:1.55;}
  .res-ok .res-b{color:#067647;} .res-no .res-b{color:#912018;}
  .res-code{font-family:var(--mono); font-size:11.5px; margin-top:11px;
    padding-top:11px; border-top:1px solid rgba(0,0,0,.07); opacity:.7;}

  .note{background:var(--amber-bg); border:1px solid #FEDF89; border-radius:10px;
    padding:15px 18px; font-size:13px; color:var(--amber); line-height:1.55; margin-top:12px;}

  .dcard{background:#fff; border:1px solid var(--line); border-radius:11px; padding:16px 20px;
    margin-bottom:9px; display:grid; grid-template-columns:1.5fr 1.2fr 1fr .9fr; gap:16px; align-items:center;}
  .d-ref{font-family:var(--mono); font-size:13px; color:var(--navy); font-weight:500;}
  .d-payer{font-size:12.5px; color:var(--muted); margin-top:3px;}
  .d-amt{font-family:var(--serif); font-size:17px; color:var(--ink);}
  .d-code{font-family:var(--mono); font-size:12px; color:var(--muted);}

  .stTabs [data-baseweb="tab-list"]{gap:4px; border-bottom:1px solid var(--line);}
  .stTabs [data-baseweb="tab"]{font-size:14px; font-weight:500; color:var(--muted); padding:11px 18px;}
  .stTabs [aria-selected="true"]{color:var(--navy) !important;}
  .stButton button{border-radius:8px; font-weight:500; font-size:14px; padding:9px 20px;
    border:1px solid var(--navy); background:var(--navy); color:#fff;}
  .stButton button:hover{background:var(--navy-soft); border-color:var(--navy-soft); color:#fff;}
  .stTextInput input, .stTextArea textarea, .stDateInput input{border-radius:8px; border-color:var(--line); font-size:14px;}
  label{font-size:13px !important; color:var(--muted) !important; font-weight:500 !important;}
</style>
""", unsafe_allow_html=True)


def api(method, path, **kwargs):
    """One call, token attached, status code returned so the caller can
    show a 409 as the feature it is rather than a failure."""
    headers = kwargs.pop("headers", {})
    if st.session_state.get("token"):
        headers["Authorization"] = f"Bearer {st.session_state['token']}"
    try:
        r = requests.request(method, f"{API}{path}", headers=headers, timeout=15, **kwargs)
    except requests.exceptions.ConnectionError:
        return False, {"detail": "Cannot reach the API. Is uvicorn running on port 8000?"}, 0
    try:
        return r.ok, r.json(), r.status_code
    except ValueError:
        return r.ok, {"detail": r.text or f"HTTP {r.status_code}"}, r.status_code


def money(v):
    return f"{Decimal(str(v or 0)):,.2f}"


def pill(status):
    cls = {"CREDITED": "p-credited", "RECEIVED": "p-received", "ON_HOLD": "p-hold",
           "RETURNED": "p-returned", "FILED": "p-filed", "MATCHED": "p-matched"}.get(status, "p-received")
    return f'<span class="pill {cls}">{status.replace("_", " ").title()}</span>'


if "token" not in st.session_state:
    st.session_state["token"] = None

if not st.session_state["token"]:
    st.markdown('<div class="bar"><div class="bar-l"><span class="bar-title">Export Collections</span>'
                '<span class="bar-div"></span><span class="bar-sub">Powered by RemitCore</span></div></div>',
                unsafe_allow_html=True)
    c, _ = st.columns([1, 1.6])
    with c:
        st.markdown('<div class="sec">Sign in</div>', unsafe_allow_html=True)
        st.markdown('<div class="sec-sub">Use the account you registered through the API.</div>',
                    unsafe_allow_html=True)
        email = st.text_input("Email", label_visibility="collapsed", placeholder="Email")
        pw = st.text_input("Password", type="password", label_visibility="collapsed", placeholder="Password")
        if st.button("Sign in", use_container_width=True):
            ok, data, _ = api("POST", "/auth/login", json={"email": email, "password": pw})
            if ok and "access_token" in data:
                st.session_state["token"] = data["access_token"]
                st.rerun()
            elif ok and "mfa_challenge_token" in data:
                st.markdown('<div class="note">This account has MFA enabled. '
                            'Use an account without MFA for the demo.</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="res res-no"><div class="res-t">Sign in failed</div>'
                            f'<div class="res-b">{data.get("detail", "")}</div></div>', unsafe_allow_html=True)
    st.stop()

st.markdown('<div class="bar"><div class="bar-l"><span class="bar-title">Export Collections</span>'
            '<span class="bar-div"></span><span class="bar-sub">Receive international payments '
            '&middot; Powered by RemitCore</span></div>'
            '<div class="bar-r"><span class="dot"></span>Connected</div></div>', unsafe_allow_html=True)

t1, t2, t3 = st.tabs(["Payments", "Invoices", "Declarations"])

with t1:
    _, vans, _ = api("GET", "/van")
    _, summ, _ = api("GET", "/payments/summary")
    left, right = st.columns([1, 1.45], gap="medium")

    with left:
        if isinstance(vans, list) and vans:
            v = vans[0]
            st.markdown(f'<div class="acct"><div><div class="acct-label">Your receiving account</div>'
                        f'<div class="acct-num">{v.get("masked_account_number", "-")}</div></div>'
                        f'<div class="acct-meta"><span>{v.get("country_code", "-")} &middot; '
                        f'{v.get("currency_code", "-")}</span>'
                        f'<span>{str(v.get("status", "-")).title()}</span></div></div>',
                        unsafe_allow_html=True)
        else:
            st.markdown('<div class="acct"><div><div class="acct-label">Your receiving account</div>'
                        '<div class="acct-empty">Not issued yet</div></div>'
                        '<div class="acct-meta"><span>Complete KYC to receive one</span></div></div>',
                        unsafe_allow_html=True)

    with right:
        s = summ if isinstance(summ, dict) else {}
        st.markdown(f'<div class="tiles">'
                    f'<div class="tile"><div class="tile-label">Received</div>'
                    f'<div class="tile-value">{s.get("total_received_count", 0)}</div>'
                    f'<div class="tile-note">payments in total</div></div>'
                    f'<div class="tile"><div class="tile-label">Credited</div>'
                    f'<div class="tile-value">{s.get("total_credited_count", 0)}</div>'
                    f'<div class="tile-note">settled by the bank</div></div>'
                    f'<div class="tile"><div class="tile-label">On hold</div>'
                    f'<div class="tile-value">{s.get("on_hold_count", 0)}</div>'
                    f'<div class="tile-note">awaiting a query</div></div></div>'
                    f'<div class="total"><span class="total-label">Total credited to your account</span>'
                    f'<span class="total-value">&#8377;{money(s.get("credited_total_inr", 0))}</span></div>',
                    unsafe_allow_html=True)

    st.markdown('<div class="sec">Recent payments</div>', unsafe_allow_html=True)
    st.markdown('<div class="sec-sub">Reported by the bank. RemitCore records what it is told - '
                'it never creates or moves a payment.</div>', unsafe_allow_html=True)

    _, pays, _ = api("GET", "/payments")
    if isinstance(pays, list) and pays:
        html = '<div class="rows">'
        for p in pays:
            inr = (f'<div class="r-inr">&#8377;{money(p["credited_amount_inr"])} credited</div>'
                   if p.get("credited_amount_inr") else "")
            if p.get("fira_reference"):
                meta = f'<b>FIRA</b> {p["fira_reference"]}'
            elif p.get("declaration_reference"):
                meta = f'Declared &middot; {p["declaration_reference"]}'
            else:
                meta = "No declaration"
            html += (f'<div class="row"><div><div class="r-payer">'
                     f'{p.get("payer_name") or "Unknown payer"}</div>'
                     f'<div class="r-date">{(p.get("received_at") or "")[:10]}</div></div>'
                     f'<div><div class="r-amt">{p.get("currency", "")} {money(p.get("amount"))}</div>{inr}</div>'
                     f'<div>{pill(p.get("status", ""))}</div>'
                     f'<div class="r-meta">{meta}</div></div>')
        st.markdown(html + "</div>", unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty"><div class="empty-t">No payments yet</div>'
                    '<div class="empty-s">Payments appear here the moment the bank reports them. '
                    'Nothing on this screen is created by RemitCore.</div></div>', unsafe_allow_html=True)

with t2:
    st.markdown('<div class="sec">Upload an invoice</div>', unsafe_allow_html=True)
    st.markdown('<div class="sec-sub">Every file is fingerprinted twice - once over the bytes, '
                'once over the contents. The same invoice cannot be submitted again, even re-saved '
                'under a different name.</div>', unsafe_allow_html=True)

    a, b = st.columns(2)
    inv = a.text_input("Invoice number", value="INV-2026-001")
    amt = b.text_input("Amount", value="2000.00")
    c, d = st.columns(2)
    cur = c.text_input("Currency", value="USD")
    buy = d.text_input("Buyer", value="Acme Corp")
    up = st.file_uploader("Invoice file", type=["pdf", "png", "jpg", "jpeg"])

    if st.button("Upload invoice"):
        if up is None:
            st.markdown('<div class="note">Choose a file first.</div>', unsafe_allow_html=True)
        else:
            ok, data, code = api("POST", "/invoices/upload",
                                 files={"file": (up.name, up.getvalue(), up.type)},
                                 data={"invoice_number": inv, "amount": amt,
                                       "currency": cur, "buyer_name": buy})
            if ok:
                st.markdown(f'<div class="res res-ok"><div class="res-t">Accepted</div>'
                            f'<div class="res-b">{data.get("invoice_number", "")} &middot; '
                            f'{data.get("message", "")}</div>'
                            f'<div class="res-code">HTTP {code} &middot; fingerprint recorded</div></div>',
                            unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="res res-no"><div class="res-t">Rejected</div>'
                            f'<div class="res-b">{data.get("detail", "")}</div>'
                            f'<div class="res-code">HTTP {code} &middot; dual-hash check</div></div>',
                            unsafe_allow_html=True)

with t3:
    st.markdown('<div class="sec">Tell the bank in advance</div>', unsafe_allow_html=True)
    st.markdown('<div class="sec-sub">Today the money lands and the bank starts asking questions. '
                'File the purpose and payer first, and the context is already there when it '
                'arrives.</div>', unsafe_allow_html=True)

    kind = st.radio("Type", ["Before the payment arrives", "No invoice exists"],
                    horizontal=True, label_visibility="collapsed")

    e, f = st.columns(2)
    d_amt = e.text_input("Expected amount", value="2000.00", key="k1")
    d_cur = f.text_input("Currency", value="USD", key="k2")
    g, h = st.columns(2)
    d_pay = g.text_input("Payer", value="Acme Corp", key="k3")
    d_ctry = h.text_input("Payer country", value="US", key="k4")
    i, j = st.columns(2)
    d_pur = i.text_input("RBI purpose code", value="P0802", key="k5")
    d_by = j.date_input("Expected by", value=datetime.date.today() + datetime.timedelta(days=30),
                        disabled=(kind == "No invoice exists"))
    d_desc = st.text_area("Description", value="Software development services", key="k6")

    if st.button("File declaration"):
        body = {"expected_amount": d_amt, "currency": d_cur, "payer_name": d_pay,
                "payer_country": d_ctry, "purpose_code": d_pur, "description": d_desc}
        if kind == "Before the payment arrives":
            body["expected_by"] = d_by.isoformat()
            ok, data, code = api("POST", "/declarations/pre-payment", json=body)
        else:
            ok, data, code = api("POST", "/declarations/self", json=body)

        if ok:
            st.markdown(f'<div class="res res-ok"><div class="res-t">Filed</div>'
                        f'<div class="res-b">Reference <b>{data.get("reference", "")}</b> - the bank '
                        f'now has the purpose and payer on record.</div>'
                        f'<div class="res-code">HTTP {code}</div></div>', unsafe_allow_html=True)
            if data.get("disclaimer"):
                st.markdown(f'<div class="note">{data["disclaimer"]}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="res res-no"><div class="res-t">Not filed</div>'
                        f'<div class="res-b">{data.get("detail", "")}</div>'
                        f'<div class="res-code">HTTP {code}</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="sec">Filed declarations</div>', unsafe_allow_html=True)
    _, decls, _ = api("GET", "/declarations")
    if isinstance(decls, list) and decls:
        out = ""
        for x in decls:
            out += (f'<div class="dcard"><div><div class="d-ref">{x.get("reference", "")}</div>'
                    f'<div class="d-payer">{x.get("payer_name", "")}</div></div>'
                    f'<div class="d-amt">{x.get("currency", "")} '
                    f'{money(x.get("expected_amount"))}</div>'
                    f'<div class="d-code">{x.get("purpose_code", "")}</div>'
                    f'<div>{pill(x.get("status", ""))}</div></div>')
        st.markdown(out, unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty"><div class="empty-t">Nothing filed yet</div>'
                    '<div class="empty-s">File a declaration above and it appears here, '
                    'ready for the bank to read.</div></div>', unsafe_allow_html=True)