"""
BAGUS_OS // TERMINAL v2.6 — Cyberpunk 2077 / Netrunner CLI UI Layer
===================================================================

Provides:
  1. Global Cyberpunk CSS injection (`#060609` void background, `#0d0f17` panels,
     Google Font `'Share Tech Mono'`, polygon-clipped neon buttons `#FCEE0A` / `#00F0FF`,
     and a fixed `pointer-events: none` CRT scanline + vignette overlay).
  2. ASCII Art HUD header & Netrunner 3-stage security gatekeeper stepper.
  3. Red `[CRITICAL_SYSTEM_HALT: HARDWARE_DONGLE_NOT_FOUND]` breach lockscreen banner.
  4. Persistent interactive CLI Log Console (`st.session_state.cli_logs`) rendered
     under prompt `[ROOT@BAGUS-VAULT ~]#` with timestamps, severity badges, and
     SHA-256 / HMAC hex digests.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Optional

import streamlit as st
from Crypto.Hash import SHA256

MAX_CLI_LOGS: int = 120

BAGUS_ASCII_BANNER: str = r"""
 ██████╗  █████╗  ██████╗ ██╗   ██╗███████╗      ██████╗ ███████╗    ██╗   ██╗██████╗    ██████╗ 
 ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝     ██╔═══██╗██╔════╝    ██║   ██║╚════██╗  ██╔════╝ 
 ██████╔╝███████║██║  ███╗██║   ██║███████╗     ██║   ██║███████╗    ██║   ██║ █████╔╝  ███████╗ 
 ██╔══██╗██╔══██║██║   ██║██║   ██║╚════██║     ██║   ██║╚════██║    ╚██╗ ██╔╝██╔═══╝   ██╔═══██╗
 ██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████║███████╗██████╔╝███████║     ╚████╔╝ ███████╗██╗╚██████╔╝
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═════╝ ╚══════╝      ╚═══╝  ╚══════╝╚═╝ ╚═════╝ 
""".strip("\n")

HALT_ASCII_SKULL: str = r"""
   ▄████▄   ██▀███   ██▓▄▄▄█████▓ ██▓ ▄████▄   ▄▄▄       ██▓         ██░ ██  ▄▄▄       ██▓  ▄▄▄█████▓
  ▒██▀ ▀█  ▓██ ▒ ██▒▓██▒▓  ██▒ ▓▒▓██▒▒██▀ ▀█  ▒████▄    ▓██▒        ▓██░ ██▒▒████▄    ▓██▒  ▓  ██▒ ▓▒
  ▒▓█    ▄ ▓██ ░▄█ ▒▒██▒▒ ▓██░ ▒░▒██▒▒▓█    ▄ ▒██  ▀█▄  ▒██░        ▒██▀▀██░▒██  ▀█▄  ▒██░  ▒ ▓██░ ▒░
  ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██░░ ▓██▓ ░ ░██░▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██░        ░▓█ ░██ ░██▄▄▄▄██ ▒██░  ░ ▓██▓ ░ 
  ▒ ▓███▀ ░░██▓ ▒██▒░██░  ▒██▒ ░ ░██░▒ ▓███▀ ░ ▓█   ▓██▒░██████▒    ░▓█▒░██▓ ▓█   ▓██▒░██████▒▒██▒ ░ 
""".strip("\n")


# --------------------------------------------------------------------------- #
# 1. Custom CSS + CRT Scanline Overlay Injection
# --------------------------------------------------------------------------- #
def inject_cyberpunk_css() -> None:
    """Inject global Cyberpunk 2077 / Netrunner theme styles & fixed CRT scanline overlay."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

        :root {
            --cp-bg: #060609;
            --cp-panel: #0d0f17;
            --cp-panel-alt: #121521;
            --cp-yellow: #FCEE0A;
            --cp-cyan: #00F0FF;
            --cp-red: #FF003C;
            --cp-green: #00FF66;
            --cp-text: #E2F1FF;
            --cp-muted: #7C8DA6;
        }

        /* Force dark mode background (#060609) & panel backgrounds (#0d0f17) */
        html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
            background-color: var(--cp-bg) !important;
            color: var(--cp-text) !important;
            font-family: 'Share Tech Mono', monospace !important;
        }

        [data-testid="stSidebar"], [data-testid="stSidebar"] > div:first-child {
            background-color: var(--cp-panel) !important;
            border-right: 1px solid rgba(0, 240, 255, 0.35) !important;
            box-shadow: 4px 0 24px rgba(0, 240, 255, 0.08);
        }

        /* Apply Share Tech Mono globally while preserving Streamlit Material icon ligatures */
        h1, h2, h3, h4, h5, h6, p, label, input, textarea, button, table, th, td,
        code, pre, .stMarkdown, [data-testid="stMetricLabel"], [data-testid="stMetricValue"],
        [data-baseweb="tab"], [data-baseweb="select"], [data-testid="stExpander"] summary p {
            font-family: 'Share Tech Mono', monospace !important;
            letter-spacing: 0.04em;
        }

        h1, h2, h3 {
            color: var(--cp-yellow) !important;
            text-transform: uppercase;
            text-shadow: 0 0 10px rgba(252, 238, 10, 0.35);
        }

        h4, h5, h6 {
            color: var(--cp-cyan) !important;
            text-transform: uppercase;
            text-shadow: 0 0 8px rgba(0, 240, 255, 0.3);
        }

        /* Fixed, pointer-events-none CRT Scanline + subtle phosphor flicker overlay */
        .crt-scanline-overlay {
            position: fixed;
            inset: 0;
            width: 100vw;
            height: 100vh;
            pointer-events: none !important;
            z-index: 999999;
            background:
                linear-gradient(
                    rgba(18, 16, 16, 0) 50%,
                    rgba(0, 0, 0, 0.34) 50%
                ),
                radial-gradient(
                    circle at center,
                    transparent 65%,
                    rgba(0, 0, 0, 0.55) 100%
                );
            background-size: 100% 4px, 100% 100%;
            opacity: 0.75;
        }

        /* Panels, Expanders, Forms, Metrics, Tables */
        [data-testid="stExpander"], [data-testid="stForm"], div[data-testid="stMetric"],
        [data-testid="stFileUploader"], [data-testid="stCameraInput"], table {
            background-color: var(--cp-panel) !important;
            border: 1px solid rgba(0, 240, 255, 0.32) !important;
            border-left: 3px solid var(--cp-cyan) !important;
            border-radius: 0px !important;
            box-shadow: 0 0 14px rgba(0, 240, 255, 0.07);
        }

        div[data-testid="stMetric"] {
            padding: 12px 16px !important;
            clip-path: polygon(0 0, 95% 0, 100% 22%, 100% 100%, 5% 100%, 0 78%);
        }

        [data-testid="stMetricValue"] {
            color: var(--cp-yellow) !important;
            text-shadow: 0 0 10px rgba(252, 238, 10, 0.45);
        }

        /* Inputs & Textareas */
        input, textarea, [data-baseweb="input"] > div, [data-baseweb="textarea"] > div,
        [data-baseweb="select"] > div {
            background-color: var(--cp-panel) !important;
            color: var(--cp-cyan) !important;
            border: 1px solid rgba(0, 240, 255, 0.45) !important;
            border-radius: 0px !important;
        }

        input:focus, textarea:focus {
            border-color: var(--cp-yellow) !important;
            box-shadow: 0 0 12px rgba(252, 238, 10, 0.45) !important;
        }

        /* Cyberpunk Angled Buttons (Standard = Neon Cyan, Primary = Neon Yellow) */
        .stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
            background: linear-gradient(135deg, #0d0f17 0%, #141a29 100%) !important;
            color: var(--cp-cyan) !important;
            border: 1px solid var(--cp-cyan) !important;
            border-radius: 0px !important;
            clip-path: polygon(0 0, 95% 0, 100% 25%, 100% 100%, 5% 100%, 0 75%);
            text-transform: uppercase !important;
            font-weight: 700 !important;
            letter-spacing: 0.08em !important;
            padding: 0.55rem 1.2rem !important;
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.25), inset 0 0 8px rgba(0, 240, 255, 0.12) !important;
            transition: all 0.16s ease-in-out !important;
        }

        .stButton > button[kind="primary"], [data-testid="stFormSubmitButton"] > button[kind="primary"] {
            background: linear-gradient(135deg, rgba(252, 238, 10, 0.16) 0%, #0d0f17 100%) !important;
            color: var(--cp-yellow) !important;
            border: 1px solid var(--cp-yellow) !important;
            box-shadow: 0 0 14px rgba(252, 238, 10, 0.35), inset 0 0 10px rgba(252, 238, 10, 0.15) !important;
        }

        .stButton > button:hover, .stDownloadButton > button:hover,
        [data-testid="stFormSubmitButton"] > button:hover {
            background: var(--cp-yellow) !important;
            color: #060609 !important;
            border-color: var(--cp-yellow) !important;
            box-shadow: 0 0 22px rgba(252, 238, 10, 0.85), 0 0 6px var(--cp-cyan) !important;
            transform: translateY(-1px);
        }

        /* Tabs */
        button[data-baseweb="tab"] {
            background-color: var(--cp-panel) !important;
            color: var(--cp-muted) !important;
            border: 1px solid rgba(0, 240, 255, 0.22) !important;
            clip-path: polygon(0 0, 93% 0, 100% 28%, 100% 100%, 0 100%);
            margin-right: 6px !important;
            padding: 8px 16px !important;
            text-transform: uppercase;
        }

        button[data-baseweb="tab"][aria-selected="true"] {
            color: var(--cp-yellow) !important;
            border-color: var(--cp-yellow) !important;
            box-shadow: 0 0 12px rgba(252, 238, 10, 0.3);
        }

        /* HUD Banner & Stepper Cards */
        .cp-hud-box {
            background: linear-gradient(180deg, rgba(13, 15, 23, 0.96) 0%, rgba(6, 6, 9, 0.98) 100%);
            border: 1px solid var(--cp-cyan);
            border-left: 4px solid var(--cp-yellow);
            padding: 14px 18px;
            margin-bottom: 14px;
            clip-path: polygon(0 0, 98.5% 0, 100% 18%, 100% 100%, 1.5% 100%, 0 82%);
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.14);
        }

        .cp-ascii {
            color: var(--cp-yellow);
            font-size: 10.5px;
            line-height: 1.12;
            overflow-x: auto;
            margin: 0;
            text-shadow: 0 0 8px rgba(252, 238, 10, 0.55), 2px 0 1px rgba(255, 0, 60, 0.45);
        }

        .cp-halt-box {
            background: linear-gradient(135deg, rgba(35, 4, 14, 0.94) 0%, rgba(13, 15, 23, 0.98) 100%);
            border: 2px solid var(--cp-red);
            border-left: 6px solid var(--cp-red);
            padding: 20px 22px;
            margin: 12px 0 18px 0;
            clip-path: polygon(0 0, 97% 0, 100% 14%, 100% 100%, 3% 100%, 0 86%);
            box-shadow: 0 0 28px rgba(255, 0, 60, 0.38), inset 0 0 18px rgba(255, 0, 60, 0.18);
            animation: cpPulseRed 2.2s infinite ease-in-out;
        }

        @keyframes cpPulseRed {
            0%, 100% { box-shadow: 0 0 20px rgba(255, 0, 60, 0.35), inset 0 0 14px rgba(255, 0, 60, 0.15); }
            50%      { box-shadow: 0 0 36px rgba(255, 0, 60, 0.72), inset 0 0 24px rgba(255, 0, 60, 0.30); }
        }

        /* Interactive CLI Log Console ([ROOT@BAGUS-VAULT ~]#) */
        .cp-cli-window {
            background-color: #030504;
            border: 1px solid #00FF66;
            border-top: 3px solid var(--cp-yellow);
            padding: 12px 16px;
            margin: 10px 0 16px 0;
            box-shadow: 0 0 20px rgba(0, 255, 102, 0.16), inset 0 0 24px rgba(0, 255, 102, 0.06);
            clip-path: polygon(0 0, 99% 0, 100% 12%, 100% 100%, 1% 100%, 0 88%);
        }

        .cp-cli-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px dashed rgba(0, 255, 102, 0.35);
            padding-bottom: 6px;
            margin-bottom: 8px;
            font-size: 12px;
            color: var(--cp-yellow);
        }

        .cp-cli-body {
            max-height: 230px;
            overflow-y: auto;
            font-size: 12.5px;
            line-height: 1.48;
            color: #00FF66;
            font-family: 'Share Tech Mono', monospace !important;
        }

        .cp-cli-line {
            margin: 2px 0;
            word-break: break-all;
        }
        </style>
        <div class="crt-scanline-overlay"></div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# 2. Persistent CLI Log Console State & Helpers
# --------------------------------------------------------------------------- #
def init_cli_logs() -> None:
    """Ensure `st.session_state.cli_logs` exists and is seeded with boot telemetry."""
    if "cli_logs" not in st.session_state:
        st.session_state.cli_logs = []
        boot_digest = SHA256.new(b"BAGUS_OS//TERMINAL_v2.6//KERNEL_BOOT").hexdigest()[:24]
        log_cli(
            "KERNEL",
            "BAGUS_OS // TERMINAL v2.6 netrunner kernel online — HKDF-SHA256 key hierarchy mounted",
            digest=boot_digest,
            level="OK",
        )


def sha256_hex(data: bytes | str) -> str:
    """Compute a full SHA-256 hex digest for CLI telemetry logging."""
    raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else bytes(data)
    return SHA256.new(raw).hexdigest()


def log_cli(
    module: str,
    action: str,
    digest: Optional[str] = None,
    level: str = "OK",
) -> None:
    """
    Append a real-time execution entry to `st.session_state.cli_logs`.

    :param module: Subsystem tag (e.g. `DONGLE_GUARD`, `BIO_AUTH`, `POW_CHAIN`, `SUPER_ENC`).
    :param action: Human-readable description of the cryptographic step.
    :param digest: Optional hex digest (SHA-256 / HMAC-SHA256 / nonce) to display.
    :param level:  `OK` | `INFO` | `WARN` | `CRIT`
    """
    if "cli_logs" not in st.session_state:
        st.session_state.cli_logs = []

    ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    entry = {
        "ts": ts,
        "module": module.upper(),
        "action": action,
        "digest": digest,
        "level": level.upper(),
    }
    st.session_state.cli_logs.append(entry)
    if len(st.session_state.cli_logs) > MAX_CLI_LOGS:
        st.session_state.cli_logs = st.session_state.cli_logs[-MAX_CLI_LOGS:]


def render_cli_console(position_label: str = "LIVE NETRUNNER TELEMETRY STREAM") -> None:
    """Render the `[ROOT@BAGUS-VAULT ~]#` black-and-green terminal console."""
    init_cli_logs()
    level_colors = {
        "OK": "#00FF66",
        "INFO": "#00F0FF",
        "WARN": "#FCEE0A",
        "CRIT": "#FF003C",
    }

    lines_html: list[str] = []
    for item in st.session_state.cli_logs[-25:]:
        color = level_colors.get(item["level"], "#00FF66")
        ts = html.escape(item["ts"])
        mod = html.escape(item["module"])
        act = html.escape(item["action"])
        digest_html = ""
        if item.get("digest"):
            d_str = html.escape(str(item["digest"]))
            digest_html = (
                f' <span style="color:#00F0FF;">[DIGEST::0x{d_str[:32]}'
                f'{"…" if len(d_str) > 32 else ""}]</span>'
            )
        lines_html.append(
            f'<div class="cp-cli-line">'
            f'<span style="color:#7C8DA6;">[{ts} UTC]</span> '
            f'<span style="color:#FCEE0A;">[ROOT@BAGUS-VAULT ~]#</span> '
            f'<span style="color:{color};font-weight:bold;">[{item["level"]}::{mod}]</span> '
            f'<span style="color:#00FF66;">{act}</span>'
            f'{digest_html}'
            f'</div>'
        )

    lines_Joined = "\n".join(lines_html)
    st.markdown(
        f"""
        <div class="cp-cli-window">
            <div class="cp-cli-bar">
                <span>⚡ [ROOT@BAGUS-VAULT ~]# // {html.escape(position_label)}</span>
                <span style="color:#00FF66;">TTY0 :: AES/CHACHA20/SHA256 ENGINE ACTIVE ({len(st.session_state.cli_logs)} EVENTS)</span>
            </div>
            <div class="cp-cli-body">
                {lines_Joined}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# 3. ASCII Art HUD Banner, Gatekeeper Stepper & Breach Lockscreen
# --------------------------------------------------------------------------- #
def render_ascii_hud(
    current_step: int,
    operator: Optional[str] = None,
    dongle_label: Optional[str] = None,
) -> None:
    """Render the top Cyberpunk ASCII Art header and 3-stage security gatekeeper HUD."""
    op_badge = html.escape((operator or "UNAUTHENTICATED").upper())
    dg_badge = html.escape((dongle_label or "NO_TOKEN").upper())
    gate_color = "#FF003C" if current_step == 1 else ("#FCEE0A" if current_step == 2 else "#00FF66")

    st.markdown(
        f"""
        <div class="cp-hud-box">
            <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#00F0FF;margin-bottom:6px;">
                <span>// NIGHT_CITY_NETRUNNER_SUBSYSTEM :: GEOVAULT SPATIAL &amp; SECRET VAULT</span>
                <span style="color:{gate_color};">SECURITY_GATE [{current_step}/3] | DONGLE: {dg_badge} | OP: {op_badge}</span>
            </div>
            <pre class="cp-ascii">{html.escape(BAGUS_ASCII_BANNER)}</pre>
            <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;margin-top:8px;border-top:1px solid rgba(0,240,255,0.25);padding-top:6px;">
                <span style="color:#FCEE0A;font-weight:bold;">BAGUS_OS // TERMINAL v2.6 — CRYPTOGRAPHIC COMMAND INTERFACE</span>
                <span style="color:#7C8DA6;">CIPHERS: HMAC-SHA256 · PBKDF2 · AES-128-EAX · SHA256-PoW · VIGENERE+AES256 · CHACHA20 · LSB</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    steps = [
        (1, "GATE_01 // DONGLE_HMAC_CHECK"),
        (2, "GATE_02 // BIOMETRIC_AES128_AUTH"),
        (3, "GATE_03 // NETRUNNER_VAULT_CORE"),
    ]
    cols = st.columns(3)
    for col, (num, title) in zip(cols, steps):
        if num < current_step:
            border, fg, status_txt = "#00FF66", "#00FF66", "ONLINE // CLEARED"
        elif num == current_step:
            border, fg, status_txt = "#FCEE0A", "#FCEE0A", "ACTIVE // ENGAGED"
        else:
            border, fg, status_txt = "#FF003C", "#7C8DA6", "LOCKED // STANDBY"
        with col:
            st.markdown(
                f"""
                <div style="background:#0d0f17;border:1px solid {border};border-left:4px solid {border};
                            padding:8px 12px;margin-bottom:8px;
                            clip-path:polygon(0 0,95% 0,100% 25%,100% 100%,5% 100%,0 75%);">
                    <div style="font-size:11px;color:#7C8DA6;">{status_txt}</div>
                    <div style="font-size:13px;color:{fg};font-weight:bold;">{title}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_dongle_breach_banner(reason: str, has_tamper_failure: bool = False) -> None:
    """Render the crimson `[CRITICAL_SYSTEM_HALT: HARDWARE_DONGLE_NOT_FOUND]` breach alert."""
    sub_code = (
        "ERR_0xDEAD_HMAC // FORGED_OR_CLONED_TOKEN_DETECTED"
        if has_tamper_failure
        else "ERR_0x00404_USB // .GEOVAULT_DONGLE_SIGNATURE_MISSING"
    )
    st.markdown(
        f"""
        <div class="cp-halt-box">
            <div style="display:flex;justify-content:space-between;align-items:center;color:#FF003C;font-size:13px;font-weight:bold;">
                <span>🚨 [CRITICAL_SYSTEM_HALT: HARDWARE_DONGLE_NOT_FOUND]</span>
                <span style="color:#FCEE0A;">{sub_code}</span>
            </div>
            <pre style="color:#FF003C;font-size:9.5px;line-height:1.1;margin:10px 0;overflow-x:auto;
                        text-shadow:0 0 10px rgba(255,0,60,0.7);">{html.escape(HALT_ASCII_SKULL)}</pre>
            <div style="color:#E2F1FF;font-size:13.5px;border-top:1px dashed rgba(255,0,60,0.5);padding-top:8px;">
                <strong style="color:#FCEE0A;">[BREACH_CONTAINMENT_PROTOCOL]</strong>
                ACCESS TO BAGUS_OS // TERMINAL v2.6 IS HARD-LOCKED. INSERT A REMOVABLE USB DRIVE
                CONTAINING A VALID <code style="color:#00F0FF;">.geovault_dongle</code> HMAC-SHA256
                HARDWARE TOKEN TO DISENGAGE ICE LOCKDOWN.<br/>
                <span style="color:#FF003C;">DIAGNOSTIC: {html.escape(reason)}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
