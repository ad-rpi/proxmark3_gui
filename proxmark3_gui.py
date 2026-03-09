from nicegui import ui, app
import subprocess
import threading
import signal
import shutil
import glob
import os
import re
import sys
import time
import json
from pathlib import Path
from collections import deque

# ── Dump / upload directory ──────────────────────────────────
# All pm3 dump files land here; files are downloadable from the browser.
# Override by setting the PM3_DUMP_DIR environment variable.
DUMP_DIR = Path(os.environ.get('PM3_DUMP_DIR', str(Path(__file__).parent / 'logs')))
DUMP_DIR.mkdir(parents=True, exist_ok=True)


def list_dump_files(exts=('.json', '.bin', '.eml', '.trace', '.txt')) -> list[Path]:
    """Return dump files in DUMP_DIR sorted newest-first."""
    files = [p for p in DUMP_DIR.iterdir() if p.is_file() and p.suffix in exts]
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)


def dump_path(name: str) -> str:
    """Return absolute path string for a dump filename inside DUMP_DIR."""
    p = Path(name)
    if p.is_absolute():
        return str(p)
    # strip any extension pm3 might add later — pass the stem
    return str(DUMP_DIR / p.stem)

# ────────────────────────────────────────────────
# GLOBAL STATE
# ────────────────────────────────────────────────
MAX_LINES = 1000

pm3_proc: subprocess.Popen | None = None
proc_lock = threading.Lock()
output: deque = deque(maxlen=MAX_LINES)

state = {
    'connected': False,
    'port': '',
    'status': 'IDLE',
}

_ui_terminals: list = []
_ui_conn_labels: list = []
_ui_status_labels: list = []


# ────────────────────────────────────────────────
# PROCESS / PORT HELPERS
# ────────────────────────────────────────────────

def log(msg: str):
    ts = time.strftime('%H:%M:%S')
    print(f'[{ts}] {msg}', flush=True)


def find_pm3_binary() -> str | None:
    found = shutil.which('pm3')
    if found:
        return found
    candidates = [
        '/usr/local/bin/pm3',
        '/usr/bin/pm3',
        os.path.expanduser('~/proxmark3/pm3'),
        os.path.expanduser('~/proxmark3/client/proxmark3'),
        '/opt/proxmark3/pm3',
        '/opt/proxmark3/client/proxmark3',
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for root, _, files in os.walk(os.path.dirname(script_dir)):
        for f in files:
            if f in ('pm3', 'proxmark3'):
                fp = os.path.join(root, f)
                if os.access(fp, os.X_OK):
                    return fp
    return None


def get_available_ports() -> list[str]:
    ports = []
    for pattern in ('/dev/ttyACM*', '/dev/ttyUSB*', '/dev/cu.usbmodem*', '/dev/ttyAMA*'):
        ports.extend(sorted(glob.glob(pattern)))
    log(f'Port scan: {ports if ports else "none found"}')
    return ports


# ────────────────────────────────────────────────
# UI REFRESH
# ────────────────────────────────────────────────

def _refresh_all_ui():
    text = '\n'.join(output)
    is_conn = state['connected']
    st = state['status']

    if st == 'CONNECTING':
        conn_text = '● CONNECTING…'
        conn_cls  = 'text-yellow-400 font-mono text-sm'
    elif is_conn:
        conn_text = '● CONNECTED'
        conn_cls  = 'text-green-400 font-mono text-sm'
    else:
        conn_text = '● DISCONNECTED'
        conn_cls  = 'text-red-400 font-mono text-sm'

    status_text = f'STATUS: {st}'

    html_content = '<pre style="margin:0">' + _escape_html(text) + '</pre>'
    for t in list(_ui_terminals):
        try:
            t.set_content(html_content)
        except Exception:
            try: _ui_terminals.remove(t)
            except ValueError: pass

    if _ui_terminals:
        try:
            ui.run_javascript(
                "document.querySelectorAll('.pm3-terminal')"
                ".forEach(el => { el.scrollTop = el.scrollHeight; })"
            )
        except Exception:
            pass

    for lbl in list(_ui_conn_labels):
        try:
            lbl.set_text(conn_text)
            lbl.classes(replace=conn_cls)
        except Exception:
            try: _ui_conn_labels.remove(lbl)
            except ValueError: pass

    for lbl in list(_ui_status_labels):
        try:
            lbl.set_text(status_text)
        except Exception:
            try: _ui_status_labels.remove(lbl)
            except ValueError: pass


# ────────────────────────────────────────────────
# SUBPROCESS I/O
# ────────────────────────────────────────────────

def _strip_ansi(s: str) -> str:
    s = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', s)
    s = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', s)
    s = re.sub(r'\x1b[()][AB012]', '', s)
    s = re.sub(r'\x1b.', '', s)
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    return s


def _update_status(line: str):
    if re.search(r'\[usb\]|\[bt\]', line):
        state['status'] = 'IDLE'
    elif re.search(r'#db#|Reading|Writing|Sniffing|Simulating|Brute', line, re.IGNORECASE):
        state['status'] = 'BUSY'


def _proc_reader():
    global pm3_proc
    log('pm3 stdout reader thread started')
    try:
        for raw_line in pm3_proc.stdout:
            line = _strip_ansi(raw_line).strip()
            if not line:
                continue
            log(f'RX: {repr(line)}')
            output.append(line)
            _update_status(line)
            if state['status'] == 'CONNECTING' and re.search(
                r'\[usb\]|\[bt\]|Proxmark3|proxmark3 v', line, re.IGNORECASE
            ):
                state['status'] = 'IDLE'
    except Exception as e:
        log(f'Reader thread error: {e}')
    finally:
        log('pm3 stdout reader thread exited')
        if state['connected']:
            state['connected'] = False
            state['status'] = 'IDLE'
            output.append('[GUI] pm3 process ended.')


def connect(port: str):
    global pm3_proc
    if not port or port == 'No ports found':
        ui.notify('Select a valid port first', type='warning')
        return
    if pm3_proc and pm3_proc.poll() is None:
        ui.notify('Already connected', type='info')
        return
    pm3_bin = find_pm3_binary()
    if not pm3_bin:
        ui.notify('pm3 binary not found — install Proxmark3 client or add to $PATH', type='negative')
        return
    try:
        cmd = [pm3_bin, '-p', port]
        log(f'Spawning: {" ".join(cmd)}')
        pm3_proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1, text=True,
            env={**os.environ, 'TERM': 'dumb'},
        )
        state['connected'] = True
        state['port'] = port
        state['status'] = 'CONNECTING'
        output.clear()
        output.append(f'[GUI] Spawned: {" ".join(cmd)}')
        log(f'pm3 process started (pid={pm3_proc.pid})')
        ui.notify(f'Connecting via pm3 on {port}…', type='positive')
        threading.Thread(target=_proc_reader, daemon=True).start()
    except Exception as e:
        log(f'Connection FAILED: {e}')
        ui.notify(f'Connection failed: {e}', type='negative')


def disconnect():
    global pm3_proc
    if pm3_proc:
        try:
            pm3_proc.stdin.write('quit\n')
            pm3_proc.stdin.flush()
        except Exception:
            pass
        time.sleep(0.4)
        try:
            pm3_proc.terminate()
        except Exception:
            pass
        pm3_proc = None
    state['connected'] = False
    state['status'] = 'IDLE'
    output.append('[GUI] Disconnected.')
    ui.notify('Disconnected', type='warning')


def _send_raw(cmd: str):
    if pm3_proc and pm3_proc.poll() is None:
        with proc_lock:
            try:
                pm3_proc.stdin.write(cmd + '\n')
                pm3_proc.stdin.flush()
                log(f'TX: {repr(cmd)}')
            except Exception as e:
                log(f'TX error: {e}')
    else:
        log(f'TX skipped (not running): {repr(cmd)}')


def send(cmd: str):
    if pm3_proc and pm3_proc.poll() is None:
        _send_raw(cmd)
        ui.notify(f'→ {cmd.strip()}', timeout=1000)
    else:
        ui.notify('Not connected', type='warning')


# ────────────────────────────────────────────────
# LAYOUT HELPERS
# ────────────────────────────────────────────────

def _nav_item(path: str, icon_name: str, label: str):
    with ui.link(target=path).classes('no-underline w-full'):
        with ui.row().classes(
            'items-center gap-2 px-3 py-1 rounded cursor-pointer w-full '
            'hover:bg-grey-8 text-grey-4 hover:text-red-400'
        ):
            ui.icon(icon_name).classes('text-base')
            ui.label(label).classes('font-mono text-xs')


def _nav_section(title: str, icon_name: str, items: list):
    """Collapsible nav section. items = list of (path, icon, label)."""
    with ui.expansion(title, icon=icon_name).classes(
        'w-full font-mono text-xs text-grey-4 bg-transparent'
    ).props('dense dark header-class="px-3 py-1 text-grey-5 hover:text-red-400"'):
        with ui.column().classes('gap-0 pl-3'):
            for path, ic, lbl in items:
                _nav_item(path, ic, lbl)


def add_shared_layout():
    ui.dark_mode().enable()
    ui.timer(0.2, _refresh_all_ui)

    # ── Header ──────────────────────────────────
    with ui.header(elevated=True).classes(
        'bg-grey-10 text-white items-center justify-between px-4 py-1'
    ).style('min-height:48px'):
        with ui.row().classes('items-center gap-2'):
            ui.icon('nfc').classes('text-red-400 text-xl')
            ui.label('Proxmark3').classes('text-base text-red-400 font-mono font-bold')
        with ui.row().classes('items-center gap-3'):
            conn_lbl = ui.label(
                '● CONNECTED' if state['connected'] else '● DISCONNECTED'
            ).classes('text-green-400 font-mono text-xs' if state['connected'] else 'text-red-400 font-mono text-xs')
            _ui_conn_labels.append(conn_lbl)
            ui.label('|').classes('text-grey-7')
            status_lbl = ui.label(f"STATUS: {state['status']}").classes('text-amber-400 font-mono text-xs')
            _ui_status_labels.append(status_lbl)

    # ── Left Drawer ──────────────────────────────
    with ui.left_drawer(value=True, fixed=False).classes(
        'bg-grey-10 border-r border-grey-800'
    ).style('width:210px'):

        # Dashboard link
        with ui.column().classes('pt-2 pb-1 gap-0'):
            _nav_item('/', 'home', 'Dashboard')

        ui.separator().classes('bg-grey-800 my-1')

        # ── Technology groups ────────────────────
        _nav_section('HF · High Frequency', 'wifi', [
            ('/hf',        'search',          'hf search / tune'),
            ('/hf14a',     'contactless_off', '14A · ISO14443A'),
            ('/hf14b',     'contactless_off', '14B · ISO14443B'),
            ('/hf15',      'contactless_off', '15 · ISO15693'),
            ('/hfmf',      'credit_card',     'MIFARE Classic'),
            ('/hfmful',    'credit_card',     'MIFARE Ultralight'),
            ('/hfemlid',   'badge',           'EM4x / iClass'),
            ('/hffelica',  'contactless_off', 'FeliCa'),
            ('/hflegic',   'lock',            'LEGIC'),
            ('/hficlass',  'badge',           'iClass / HID'),
        ])

        _nav_section('LF · Low Frequency', 'radio', [
            ('/lf',        'search',   'lf search / tune'),
            ('/lft55',     'memory',   'T5577'),
            ('/lfem',      'badge',    'EM4x'),
            ('/lfhid',     'badge',    'HID Prox'),
            ('/lfindala',  'badge',    'Indala'),
            ('/lfio',      'badge',    'ioProx / Paradox'),
            ('/lfother',   'more_horiz','Other LF'),
        ])

        _nav_section('NFC', 'tap_and_play', [
            ('/nfc',       'tap_and_play', 'NFC overview'),
        ])

        _nav_section('EMV / Smart Card', 'payment', [
            ('/emv',       'payment',  'EMV ISO14443'),
            ('/smart',     'sim_card', 'ISO-7816 Smart'),
            ('/piv',       'badge',    'PIV / CAC'),
        ])

        _nav_section('Hardware', 'developer_board', [
            ('/hw',        'developer_board', 'hw status / version'),
            ('/hwtune',    'graphic_eq',      'hw tune'),
        ])

        _nav_section('Utils', 'build', [
            ('/analyse',   'science',      'Analyse'),
            ('/data',      'show_chart',   'Data / Plot'),
            ('/trace',     'hearing',      'Trace / Sniff'),
            ('/wiegand',   'view_week',    'Wiegand'),
            ('/reveng',    'calculate',    'CRC / RevEng'),
            ('/script',    'terminal',     'Scripts'),
            ('/mqtt',      'cloud',        'MQTT'),
            ('/firmware',  'system_update','Firmware Update'),
        ])

        ui.separator().classes('bg-grey-800 my-1')
        ui.label('CONNECTION').classes('text-caption text-grey-6 font-mono px-3 pt-1')

        with ui.column().classes('px-3 pb-3 gap-1'):
            ports = get_available_ports()
            options = ports if ports else ['No ports found']
            port_sel = ui.select(
                options=options,
                value=state['port'] if state['port'] in options else options[0],
                label='Port'
            ).props('dense outlined dark').classes('w-full font-mono text-xs')

            def _do_connect():  connect(port_sel.value)
            def _refresh_ports():
                p = get_available_ports()
                port_sel.options = p if p else ['No ports found']
                port_sel.value   = p[0] if p else 'No ports found'
                port_sel.update()

            ui.button('↺ Ports',     on_click=_refresh_ports, color='grey' ).props('outline dense').classes('w-full font-mono text-xs')
            ui.button('Connect',     on_click=_do_connect,    color='green').props('outline dense').classes('w-full font-mono text-xs')
            ui.button('Disconnect',  on_click=disconnect,     color='red'  ).props('outline dense').classes('w-full font-mono text-xs')

            dc_lbl = ui.label(
                '● CONNECTED' if state['connected'] else '● DISCONNECTED'
            ).classes('text-green-400 font-mono text-xs text-center' if state['connected']
                      else 'text-red-400 font-mono text-xs text-center')
            _ui_conn_labels.append(dc_lbl)


# ────────────────────────────────────────────────
# WIDGET HELPERS
# ────────────────────────────────────────────────

def _escape_html(s: str) -> str:
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def make_terminal(height: str = '280px'):
    with ui.card().classes('w-full bg-grey-10 border border-grey-800'):
        with ui.row().classes('items-center justify-between px-3 pt-2'):
            ui.label('TERMINAL OUTPUT').classes('text-caption text-grey-5 font-mono')
            with ui.row().classes('gap-1'):
                def _clear():
                    output.clear()
                    for t in list(_ui_terminals):
                        try: t.set_content('<pre style="margin:0"></pre>')
                        except Exception: pass
                ui.button('Clear', on_click=_clear, color='grey').props('flat dense size=xs').classes('font-mono')
                ui.button('help',  on_click=lambda: send('help'), color='blue').props('flat dense size=xs').classes('font-mono')
                ui.button('auto',  on_click=lambda: send('auto'), color='orange').props('flat dense size=xs').classes('font-mono')

        initial_html = '<pre style="margin:0">' + _escape_html('\n'.join(output)) + '</pre>'
        term = ui.html(initial_html).classes('pm3-terminal w-full').style(
            f'height:{height}; overflow-y:auto; overflow-x:auto;'
            'background:#0a0a0a; color:#f87171;'
            'font-family:"Courier New",monospace;'
            'display:block; padding:8px; box-sizing:border-box;'
            'font-size:0.75rem; line-height:1.4;'
        )
        _ui_terminals.append(term)

        with ui.row().classes('px-2 pb-2 gap-2 items-center border-t border-grey-800'):
            cmd_in = ui.input(placeholder='Enter pm3 command…').props('dense outlined dark clearable').classes('flex-grow font-mono text-xs')
            def _send():
                c = cmd_in.value.strip()
                if c:
                    send(c)
                    cmd_in.set_value('')
            cmd_in.on('keydown.enter', _send)
            ui.button('Send', on_click=_send, color='red').props('dense outline').classes('font-mono text-xs')


def page_header(title: str, subtitle: str = '', help_cmd: str = ''):
    with ui.row().classes('items-end gap-3 mt-3 mb-1'):
        ui.label(title).classes('text-lg font-mono text-red-400 font-bold')
        if subtitle:
            ui.label(subtitle).classes('text-caption text-grey-5')
        if help_cmd:
            ui.button(f'{help_cmd} help', on_click=lambda h=help_cmd: send(f'{h} help'),
                      color='grey').props('flat dense size=xs').classes('font-mono text-xs')
    ui.separator().classes('bg-grey-800 mb-3')


def cmd_card(title: str, commands: list, color: str = 'red'):
    with ui.card().classes('bg-grey-10 border border-grey-800'):
        ui.label(title).classes('text-caption text-amber-400 font-mono mb-1')
        with ui.column().classes('gap-1'):
            for lbl, cmd in commands:
                if callable(cmd):
                    ui.button(lbl, on_click=cmd).props(f'outline dense color={color}').classes('font-mono text-xs w-full text-left')
                else:
                    ui.button(lbl, on_click=lambda c=cmd: send(c)).props(f'outline dense color={color}').classes('font-mono text-xs w-full text-left')


def make_download_bar(label: str = 'SAVED FILES'):
    """Card that lists files in DUMP_DIR and offers per-file download + delete."""
    with ui.card().classes('w-full bg-grey-10 border border-grey-800 p-3'):
        with ui.row().classes('items-center justify-between mb-1'):
            ui.label(label).classes('text-caption text-amber-400 font-mono')
            ui.label('(auto-refreshes)').classes('text-xs text-grey-6 font-mono')
        file_list = ui.column().classes('gap-1 w-full')

        def _refresh_files():
            file_list.clear()
            files = list_dump_files()
            if not files:
                with file_list:
                    ui.label('No files yet').classes('text-xs text-grey-6 font-mono')
            else:
                for fp in files:
                    sz = fp.stat().st_size
                    sz_str = f'{sz/1024:.1f} KB' if sz > 1024 else f'{sz} B'
                    mtime = time.strftime('%H:%M:%S', time.localtime(fp.stat().st_mtime))
                    with file_list:
                        with ui.row().classes('items-center gap-2 w-full'):
                            ui.label(f'{mtime}  {fp.name}  ({sz_str})').classes(
                                'text-xs text-grey-3 font-mono flex-grow truncate')
                            ui.button('↓', on_click=lambda p=fp: ui.download(str(p)),
                                      color='teal').props('flat dense size=xs').classes('font-mono')
                            def _del(p=fp):
                                try: p.unlink()
                                except Exception: pass
                                _refresh_files()
                            ui.button('✕', on_click=_del,
                                      color='red').props('flat dense size=xs').classes('font-mono')

        _refresh_files()
        ui.button('↺ Refresh', on_click=_refresh_files, color='grey').props('flat dense size=xs').classes('font-mono text-xs mt-1')


def make_upload_card(label: str, on_loaded, accept: str = '.json,.bin,.eml,.trace'):
    """Card with drag-and-drop upload; calls on_loaded(path: Path) when done."""
    with ui.card().classes('w-full bg-grey-10 border border-blue-900 p-3'):
        ui.label(label).classes('text-caption text-blue-400 font-mono mb-2')

        def _handle(e):
            import io
            dest = DUMP_DIR / e.name
            with open(dest, 'wb') as f:
                f.write(e.content.read())
            ui.notify(f'Uploaded: {e.name}', type='positive')
            on_loaded(dest)

        ui.upload(
            label='Drop file here or click to browse',
            on_upload=_handle,
            auto_upload=True,
        ).props(f'accept="{accept}" flat outlined dark').classes('w-full font-mono text-xs')


def input_row(label_text: str, placeholder: str, width: str = 'w-full') -> 'ui.input':
    return ui.input(label=label_text, placeholder=placeholder).props('dense outlined dark').classes(f'{width} font-mono text-xs')


def num_input(label_text: str, value=0, mn=0, mx=255, width: str = 'w-28') -> 'ui.number':
    return ui.number(label=label_text, value=value, min=mn, max=mx).props('dense outlined dark').classes(f'{width} font-mono text-xs')


# ────────────────────────────────────────────────
# PAGES
# ────────────────────────────────────────────────


@ui.page('/')
def page_home():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Dashboard', 'Proxmark3 Control Center')

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('CONNECTION').classes('text-caption text-grey-5 font-mono')
            lbl = ui.label('● CONNECTED' if state['connected'] else '● DISCONNECTED').classes(
                'text-lg font-mono ' + ('text-green-400' if state['connected'] else 'text-red-400'))
            _ui_conn_labels.append(lbl)

        with ui.card().classes('bg-grey-10 border border-amber-900 p-3 w-full'):
            ui.label('STATUS').classes('text-caption text-grey-5 font-mono')
            slbl = ui.label(f"STATUS: {state['status']}").classes('text-lg text-amber-400 font-mono')
            _ui_status_labels.append(slbl)

        with ui.card().classes('bg-grey-10 border border-blue-900 p-3 w-full'):
            ui.label('PM3 BINARY').classes('text-caption text-grey-5 font-mono')
            _b = find_pm3_binary()
            ui.label(_b or 'NOT FOUND').classes('text-sm font-mono ' + ('text-blue-400' if _b else 'text-red-500'))

        with ui.card().classes('w-full bg-grey-10 border border-grey-800 p-3'):
            ui.label('QUICK ACTIONS').classes('text-caption text-grey-5 font-mono mb-2')
            with ui.row().classes('gap-2 flex-wrap'):
                for lbl, cmd, col in [
                    ('auto',       'auto',       'orange'),
                    ('hf search',  'hf search',  'red'),
                    ('lf search',  'lf search',  'deep-orange'),
                    ('hw version', 'hw version', 'blue'),
                    ('hw status',  'hw status',  'blue'),
                    ('hw tune',    'hw tune',    'teal'),
                    ('lf tune',    'lf tune',    'teal'),
                    ('prefs show', 'prefs show', 'grey'),
                    ('hints',      'hints',      'grey'),
                    ('help',       'help',       'grey'),
                ]:
                    ui.button(lbl, on_click=lambda c=cmd: send(c), color=col).props('outline dense').classes('font-mono text-xs')

        make_terminal(height='350px')


# ── HF Overview ──────────────────────────────────

@ui.page('/hf')
def page_hf():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('HF · High Frequency', '13.56 MHz commands', 'hf')
        cmd_card('Search & Tune', [
            ('hf search — auto-detect tag',   'hf search'),
            ('hf tune   — measure antenna',   'hf tune'),
            ('hf list   — list supported tags','hf list'),
        ])
        cmd_card('Sniff', [
            ('hf sniff',      'hf sniff'),
            ('hf list 14a',   'hf list 14a'),
            ('hf list 14b',   'hf list 14b'),
            ('hf list mf',    'hf list mf'),
        ])
        cmd_card('Sub-protocols (use left nav)', [
            ('→ ISO14443A / NFC-A  (14a)',    '/hf14a'),
            ('→ ISO14443B          (14b)',    '/hf14b'),
            ('→ ISO15693 / NFC-V   (15)',     '/hf15'),
            ('→ MIFARE Classic      (mf)',    '/hfmf'),
            ('→ MIFARE Ultralight  (mfu)',    '/hfmful'),
            ('→ FeliCa',                      '/hffelica'),
            ('→ LEGIC',                       '/hflegic'),
            ('→ iClass / HID',               '/hficlass'),
        ], color='blue-grey')
        make_terminal()


# ── HF 14A ──────────────────────────────────────

@ui.page('/hf14a')
def page_hf14a():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('HF 14A · ISO14443A', 'NFC-A · MIFARE · NTAG · DESFire', 'hf 14a')

        cmd_card('1. Reconnaissance', [
            ('hf 14a info   — detect & identify tag',  'hf 14a info'),
            ('hf 14a reader — continuous scan',        'hf 14a reader'),
            ('hf 14a sniff  — sniff reader↔card traffic','hf 14a sniff'),
            ('hf list 14a   — decode trace buffer',    'hf list 14a'),
        ])
        cmd_card('2. DESFire Enumeration', [
            ('hf mfdes info     — read DESFire card info',   'hf mfdes info'),
            ('hf mfdes enum     — list all apps + files',    'hf mfdes enum'),
            ('hf mfdes getuid   — get real UID',             'hf mfdes getuid'),
        ])
        cmd_card('3. Simulate', [
            ('hf 14a sim -t 1  — simulate MIFARE 1K',  'hf 14a sim -t 1'),
            ('hf 14a sim -t 2  — simulate MIFARE 4K',  'hf 14a sim -t 2'),
            ('hf 14a sim -t 9  — simulate NTAG213',    'hf 14a sim -t 9'),
            ('hf 14a sim -t 3  — simulate DESFire',    'hf 14a sim -t 3'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('4. RAW APDU').classes('text-caption text-amber-400 font-mono mb-2')
            apdu_d   = input_row('APDU bytes (hex)', '6000')
            with ui.row().classes('gap-2 mt-1'):
                apdu_sel = ui.checkbox('Select (-s)', value=True).props('dark dense')
                apdu_crc = ui.checkbox('CRC (-c)',    value=True).props('dark dense')
            def _apdu():
                d = apdu_d.value.strip()
                if not d: return
                flags = []
                if apdu_sel.value: flags.append('-s')
                if apdu_crc.value: flags.append('-c')
                send(f'hf 14a raw {" ".join(flags)} -d {d}')
            ui.button('Send APDU', on_click=_apdu, color='red').props('outline dense').classes('font-mono text-xs w-full mt-2')

        make_terminal()


# ── HF 14B ──────────────────────────────────────

@ui.page('/hf14b')
def page_hf14b():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('HF 14B · ISO14443B', 'ISO14443B contactless cards', 'hf 14b')

        cmd_card('1. Reconnaissance', [
            ('hf 14b info   — detect & identify',  'hf 14b info'),
            ('hf 14b reader — continuous scan',    'hf 14b reader'),
            ('hf 14b sniff  — sniff traffic',      'hf 14b sniff'),
            ('hf list 14b   — decode trace',       'hf list 14b'),
        ])
        cmd_card('2. Dump', [
            ('hf 14b dump   — dump tag data',      'hf 14b dump'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('3. RAW COMMAND').classes('text-caption text-amber-400 font-mono mb-2')
            raw14b = input_row('Hex bytes', '0500')
            def _send14b():
                d = raw14b.value.strip()
                if d: send(f'hf 14b raw -cks -d {d}')
            ui.button('Send Raw', on_click=_send14b, color='red').props('outline dense').classes('font-mono text-xs w-full mt-2')

        make_terminal()


# ── HF 15 ───────────────────────────────────────

@ui.page('/hf15')
def page_hf15():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('HF 15 · ISO15693', 'Vicinity / NFC-V tags', 'hf 15')

        cmd_card('1. Reconnaissance', [
            ('hf 15 info   — identify tag',              'hf 15 info'),
            ('hf 15 reader — continuous scan',           'hf 15 reader'),
            ('hf 15 dump   — dump all blocks',           'hf 15 dump'),
            ('hf 15 rdbl -* -b 0    — read block 0',    'hf 15 rdbl -* -b 0'),
            ('hf 15 rdmbl -* -b 0 -c 4 — read multiple','hf 15 rdmbl -* -b 0 -c 4'),
        ])
        cmd_card('2. Emulate', [
            ('hf 15 sim',     'hf 15 sim'),
            ('hf 15 restore', 'hf 15 restore'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('3. WRITE BLOCK').classes('text-caption text-amber-400 font-mono mb-2')
            b15 = num_input('Block #', 0, 0, 255)
            d15 = input_row('Data (8 hex bytes)', 'DEADBEEF')
            def _wr15():
                d = d15.value.strip()
                if d: send(f'hf 15 wrbl -* -b {int(b15.value)} -d {d}')
            ui.button('Write Block', on_click=_wr15, color='red').props('outline dense').classes('font-mono text-xs w-full mt-2')

        make_terminal()


# ── MIFARE Classic ───────────────────────────────

@ui.page('/hfmf')
def page_hfmf():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('MIFARE Classic', '1K · 4K · Mini — ISO14443A', 'hf mf')

        cmd_card('1. Reconnaissance', [
            ('hf mf info   — identify card type',       'hf mf info'),
            ('hf mf nack   — test for NACK bug',        'hf mf nack'),
            ('hf mf sniff  — sniff reader↔card traffic','hf mf sniff'),
        ])
        cmd_card('2. Key Recovery (Attacks)', [
            ('hf mf autopwn      — full auto: detect + crack + dump', 'hf mf autopwn'),
            ('hf mf darkside     — darkside attack (NACK required)',   'hf mf darkside'),
            ('hf mf hardnested   — hardnested attack',                 'hf mf hardnested'),
            ('hf mf chk --1k    — check default keys (1K)',           'hf mf chk --1k'),
            ('hf mf fchk --1k   — fast key check (1K)',               'hf mf fchk --1k'),
            ('hf mf chk --4k    — check default keys (4K)',           'hf mf chk --4k'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('3. READ BLOCK').classes('text-caption text-amber-400 font-mono mb-2')
            rb  = num_input('Block', 0, 0, 255)
            rk  = input_row('Key (12 hex)', 'FFFFFFFFFFFF')
            rkt = ui.select(['A','B'], value='A', label='Key type').props('dense outlined dark').classes('w-20 font-mono text-xs')
            def _rdbl():
                k = rk.value.strip() or 'FFFFFFFFFFFF'
                send(f'hf mf rdbl --blk {int(rb.value)} --key {k}' + (' -b' if rkt.value == 'B' else ''))
            ui.button('Read Block', on_click=_rdbl, color='teal').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('4. WRITE BLOCK').classes('text-caption text-amber-400 font-mono mb-2')
            wb  = num_input('Block', 1, 0, 255)
            wk  = input_row('Key (12 hex)', 'FFFFFFFFFFFF')
            wkt = ui.select(['A','B'], value='A', label='Key type').props('dense outlined dark').classes('w-20 font-mono text-xs')
            wd  = input_row('Data (32 hex)', '00000000000000000000000000000000')
            def _wrbl():
                k = wk.value.strip() or 'FFFFFFFFFFFF'
                d = wd.value.strip()
                if d: send(f'hf mf wrbl --blk {int(wb.value)} --key {k}' + (' -b' if wkt.value == 'B' else '') + f' -d {d}')
            ui.button('Write Block', on_click=_wrbl, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('5. DUMP TO FILE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label('Saved to: ' + str(DUMP_DIR)).classes('text-xs text-grey-6 font-mono mb-2')
            mf_dump_fn   = ui.input(label='Filename (no ext)', placeholder='hf-mf-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            mf_dump_size = ui.select(['--1k','--2k','--4k','--mini'], value='--1k', label='Card size').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _mf_dump():
                fn = dump_path(mf_dump_fn.value.strip() or 'hf-mf-dump')
                send(f'hf mf dump {mf_dump_size.value} -f {fn}')
                ui.notify(f'Dumping to {fn} …', type='positive')
            ui.button('Dump Card', on_click=_mf_dump, color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-orange-900 p-3 w-full'):
            ui.label('6. RESTORE FROM FILE').classes('text-caption text-orange-400 font-mono mb-2')
            mf_rest_fn   = ui.input(label='Filename (no ext)', placeholder='hf-mf-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            mf_rest_size = ui.select(['--1k','--2k','--4k','--mini'], value='--1k', label='Card size').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _mf_restore():
                fn = dump_path(mf_rest_fn.value.strip() or 'hf-mf-dump')
                send(f'hf mf restore {mf_rest_size.value} -f {fn}')
            ui.button('Restore to Card', on_click=_mf_restore, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-blue-900 p-3 w-full'):
            ui.label('7. EMULATOR LOAD / SAVE').classes('text-caption text-blue-400 font-mono mb-2')
            mf_emu_fn   = ui.input(label='Filename (no ext)', placeholder='hf-mf-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            mf_emu_size = ui.select(['--1k','--2k','--4k','--mini'], value='--1k', label='Card size').props('dense outlined dark').classes('w-full font-mono text-xs')
            with ui.row().classes('gap-2 mt-1'):
                def _mf_eload():
                    fn = dump_path(mf_emu_fn.value.strip() or 'hf-mf-dump')
                    send(f'hf mf eload {mf_emu_size.value} -f {fn}')
                def _mf_esave():
                    fn = dump_path(mf_emu_fn.value.strip() or 'hf-mf-save')
                    send(f'hf mf esave {mf_emu_size.value} -f {fn}')
                ui.button('Load to Emulator',   on_click=_mf_eload, color='blue').props('outline dense').classes('font-mono text-xs flex-1')
                ui.button('Save from Emulator', on_click=_mf_esave, color='teal').props('outline dense').classes('font-mono text-xs flex-1')

        mf_dl_holder = ui.column().classes('w-full')
        def _mf_refresh_dl():
            mf_dl_holder.clear()
            with mf_dl_holder:
                make_download_bar('SAVED FILES')
        _mf_refresh_dl()
        def _on_mf_upload(path: Path):
            mf_rest_fn.set_value(path.stem)
            mf_emu_fn.set_value(path.stem)
            _mf_refresh_dl()
        make_upload_card('UPLOAD DUMP FILE', _on_mf_upload, accept='.bin,.json,.eml')

        cmd_card('8. Magic Card / UID Clone', [
            ('hf mf cview        — view magic card contents',   'hf mf cview'),
            ('hf mf cwipe        — wipe magic card to default', 'hf mf cwipe'),
            ('hf mf gen3uid      — Gen3 UID info',              'hf mf gen3uid'),
            ('hf mf ginfo        — Gen4 info',                  'hf mf ginfo'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('SET MAGIC CARD UID (Gen1A)').classes('text-caption text-amber-400 font-mono mb-2')
            magic_uid = input_row('UID (8 hex bytes)', 'DEADBEEF')
            def _csetuid():
                u = magic_uid.value.strip()
                if u: send(f'hf mf csetuid -u {u}')
            ui.button('Set UID', on_click=_csetuid, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')

        cmd_card('9. Simulate', [
            ('hf mf sim --1k', 'hf mf sim --1k'),
            ('hf mf sim --4k', 'hf mf sim --4k'),
        ])

        make_terminal()


# ── MIFARE Ultralight ────────────────────────────

@ui.page('/hfmful')
def page_hfmful():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('MIFARE Ultralight / NTAG', 'MFU · UL-C · NTAG21x · EV1', 'hf mfu')

        cmd_card('1. Reconnaissance', [
            ('hf mfu info   — identify tag, check counters', 'hf mfu info'),
            ('hf mfu ndefs  — read NDEF records',            'hf mfu ndefs'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('2. READ / WRITE PAGE').classes('text-caption text-amber-400 font-mono mb-2')
            pg  = num_input('Page', 0, 0, 255)
            dat = input_row('Data (8 hex, for write)', '01020304')
            with ui.row().classes('gap-2 mt-1'):
                ui.button('Read Page',  on_click=lambda: send(f'hf mfu rdbl -b {int(pg.value)}'),
                          color='teal').props('outline dense').classes('font-mono text-xs flex-1')
                def _wrmfu():
                    d = dat.value.strip()
                    if d: send(f'hf mfu wrbl -b {int(pg.value)} -d {d}')
                ui.button('Write Page', on_click=_wrmfu, color='red').props('outline dense').classes('font-mono text-xs flex-1')

        cmd_card('3. Auth', [
            ('hf mfu auth -k 00..00', 'hf mfu auth -k 00000000000000000000000000000000'),
            ('hf mfu setpwd', 'hf mfu setpwd'),
            ('hf mfu pwdgen', 'hf mfu pwdgen'),
        ])

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('4. DUMP TO FILE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label('Saved to: ' + str(DUMP_DIR)).classes('text-xs text-grey-6 font-mono mb-2')
            mfu_fn = ui.input(label='Filename (no ext)', placeholder='hf-mfu-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _mfu_dump():
                fn = dump_path(mfu_fn.value.strip() or 'hf-mfu-dump')
                send(f'hf mfu dump -f {fn}')
                ui.notify(f'Dumping to {fn} …', type='positive')
            ui.button('Dump Tag', on_click=_mfu_dump, color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-orange-900 p-3 w-full'):
            ui.label('5. RESTORE FROM FILE').classes('text-caption text-orange-400 font-mono mb-2')
            mfu_rest_fn = ui.input(label='Filename (no ext)', placeholder='hf-mfu-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            mfu_magic   = ui.checkbox('Magic tag write (-s)', value=False).props('dark dense')
            def _mfu_restore():
                fn = dump_path(mfu_rest_fn.value.strip() or 'hf-mfu-dump')
                s_flag = ' -s' if mfu_magic.value else ''
                send(f'hf mfu restore -f {fn}{s_flag}')
            ui.button('Restore to Tag', on_click=_mfu_restore, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')

        mfu_dl_holder = ui.column().classes('w-full')
        def _mfu_refresh():
            mfu_dl_holder.clear()
            with mfu_dl_holder:
                make_download_bar('SAVED FILES')
        _mfu_refresh()
        def _on_mfu_upload(path: Path):
            mfu_rest_fn.set_value(path.stem)
            _mfu_refresh()
        make_upload_card('UPLOAD DUMP FILE', _on_mfu_upload, accept='.bin,.json,.eml')

        cmd_card('6. Clone / Simulate', [
            ('hf mfu setuid', 'hf mfu setuid'),
            ('hf mfu clone',  'hf mfu clone'),
            ('hf mfu sim',    'hf mfu sim'),
        ])

        make_terminal()


# ── FeliCa ───────────────────────────────────────

@ui.page('/hffelica')
def page_hffelica():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('FeliCa', 'Sony FeliCa / NFC-F', 'hf felica')
        cmd_card('1. Reconnaissance', [
            ('hf felica info',    'hf felica info'),
            ('hf felica reader',  'hf felica reader'),
            ('hf felica sniff',   'hf felica sniff'),
            ('hf list felica',    'hf list felica'),
        ])
        cmd_card('2. Dump & Simulate', [
            ('hf felica dump',    'hf felica dump'),
            ('hf felica sim',     'hf felica sim'),
            ('hf felica litesim', 'hf felica litesim'),
        ])
        make_terminal()


# ── LEGIC ────────────────────────────────────────

@ui.page('/hflegic')
def page_hflegic():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('LEGIC', 'LEGIC Prime / Advant', 'hf legic')
        cmd_card('1. Reconnaissance', [
            ('hf legic info',   'hf legic info'),
            ('hf legic reader', 'hf legic reader'),
            ('hf legic dump',   'hf legic dump'),
        ])
        cmd_card('2. Write & Simulate', [
            ('hf legic restore', 'hf legic restore'),
            ('hf legic eload',   'hf legic eload'),
            ('hf legic sim',     'hf legic sim'),
        ])
        make_terminal()


# ── iClass / HID ─────────────────────────────────

@ui.page('/hficlass')
def page_hficlass():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('iClass / HID', 'HID iClass · iClass SE · Picopass', 'hf iclass')

        cmd_card('1. Reconnaissance', [
            ('hf iclass info',   'hf iclass info'),
            ('hf iclass reader', 'hf iclass reader'),
            ('hf iclass sniff',  'hf iclass sniff'),
            ('hf list iclass',   'hf list iclass'),
        ])
        cmd_card('2. Key Recovery', [
            ('hf iclass loclass',   'hf iclass loclass'),
            ('hf iclass lookup',    'hf iclass lookup'),
            ('hf iclass managekeys','hf iclass managekeys'),
        ])
        cmd_card('3. Simulate', [
            ('hf iclass sim -t 0 — simulate tag',       'hf iclass sim -t 0'),
            ('hf iclass sim -t 2 — simulate with data', 'hf iclass sim -t 2'),
            ('hf iclass sim -t 3 — simulate from file', 'hf iclass sim -t 3'),
        ])

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('4. DUMP TO FILE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label('Saved to: ' + str(DUMP_DIR)).classes('text-xs text-grey-6 font-mono mb-2')
            ic_fn  = ui.input(label='Filename', placeholder='hf-iclass-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            ic_key = ui.input(label='Debit key (8 hex bytes)', placeholder='AFA785A7DAB33378').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _ic_dump():
                fn = dump_path(ic_fn.value.strip() or 'hf-iclass-dump')
                k  = ic_key.value.strip()
                kf = f' -k {k}' if k else ' --ki 0'
                send(f'hf iclass dump -f {fn}{kf}')
                ui.notify(f'Dumping to {fn} …', type='positive')
            ui.button('Dump Tag', on_click=_ic_dump, color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-orange-900 p-3 w-full'):
            ui.label('5. RESTORE FROM FILE').classes('text-caption text-orange-400 font-mono mb-2')
            ic_rest_fn  = ui.input(label='Filename', placeholder='hf-iclass-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            ic_rest_key = ui.input(label='Key (8 hex bytes)', placeholder='AFA785A7DAB33378').props('dense outlined dark').classes('w-full font-mono text-xs')
            ic_first    = ui.number(label='First block', value=6,  min=0, max=255).props('dense outlined dark').classes('w-28 font-mono text-xs')
            ic_last     = ui.number(label='Last block',  value=18, min=0, max=255).props('dense outlined dark').classes('w-28 font-mono text-xs')
            def _ic_restore():
                fn = dump_path(ic_rest_fn.value.strip() or 'hf-iclass-dump')
                k  = ic_rest_key.value.strip()
                kf = f' -k {k}' if k else ' --ki 0'
                send(f'hf iclass restore -f {fn}{kf} --first {int(ic_first.value)} --last {int(ic_last.value)}')
            ui.button('Restore to Tag', on_click=_ic_restore, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')

        ic_dl_holder = ui.column().classes('w-full')
        def _ic_refresh():
            ic_dl_holder.clear()
            with ic_dl_holder:
                make_download_bar('SAVED FILES')
        _ic_refresh()
        def _on_ic_upload(path: Path):
            ic_rest_fn.set_value(path.name)
            _ic_refresh()
        make_upload_card('UPLOAD DUMP FILE', _on_ic_upload, accept='.bin,.json,.eml')

        make_terminal()


# ── HF EM4x / Hitag ──────────────────────────────

@ui.page('/hfemlid')
def page_hfemlid():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('HF EM · Hitag', '13.56 MHz EM / Hitag', 'hf hitag')
        cmd_card('Hitag 1 / 2', [
            ('hf hitag info',   'hf hitag info'),
            ('hf hitag reader', 'hf hitag reader'),
            ('hf hitag dump',   'hf hitag dump'),
            ('hf hitag sim',    'hf hitag sim'),
        ])
        cmd_card('HitagS', [
            ('hf hitag hts reader', 'hf hitag hts reader'),
            ('hf hitag hts dump',   'hf hitag hts dump'),
            ('hf hitag hts sim',    'hf hitag hts sim'),
        ])
        make_terminal()


# ── LF Overview ──────────────────────────────────

@ui.page('/lf')
def page_lf():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('LF · Low Frequency', '125 / 134 kHz', 'lf')
        cmd_card('Search & Tune', [
            ('lf search — auto-detect tag', 'lf search'),
            ('lf tune   — measure antenna', 'lf tune'),
            ('lf read   — read raw signal', 'lf read'),
            ('lf sniff  — sniff LF traffic','lf sniff'),
            ('lf config — show config',     'lf config'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('SET FREQUENCY').classes('text-caption text-amber-400 font-mono mb-2')
            freq_s = ui.select(['125','134'], value='125', label='kHz').props('dense outlined dark').classes('w-24 font-mono text-xs')
            ui.button('Set', on_click=lambda: send(f'lf config -f {freq_s.value}'),
                      color='orange').props('outline dense').classes('font-mono text-xs mt-1')
        cmd_card('Sub-protocols (use left nav)', [
            ('→ T5577',          '/lft55'),
            ('→ EM4x',           '/lfem'),
            ('→ HID Prox',       '/lfhid'),
            ('→ Indala',         '/lfindala'),
            ('→ ioProx / Other', '/lfio'),
            ('→ Other LF',       '/lfother'),
        ], color='blue-grey')
        make_terminal()


# ── T5577 ────────────────────────────────────────

@ui.page('/lft55')
def page_lft55():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('T5577', 'LF R/W clone tag', 'lf t55')

        cmd_card('1. Reconnaissance', [
            ('lf t55xx detect  — detect T5577 + config', 'lf t55xx detect'),
            ('lf t55xx info    — detailed config decode', 'lf t55xx info'),
            ('lf t55xx dump    — dump all blocks',        'lf t55xx dump'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('2. READ BLOCK').classes('text-caption text-amber-400 font-mono mb-2')
            tb_r = num_input('Block', 0, 0, 7)
            tp_r = input_row('Password (opt, 8 hex)', '')
            def _t55r():
                c = f'lf t55xx read -b {int(tb_r.value)}'
                p = tp_r.value.strip()
                if p: c += f' --pwd {p}'
                send(c)
            ui.button('Read', on_click=_t55r, color='teal').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('3. WRITE BLOCK').classes('text-caption text-amber-400 font-mono mb-2')
            tb_w = num_input('Block', 1, 0, 7)
            td_w = input_row('Data (8 hex)', 'DEADBEEF')
            tp_w = input_row('Password (opt, 8 hex)', '')
            def _t55w():
                d = td_w.value.strip()
                if not d: return
                c = f'lf t55xx write -b {int(tb_w.value)} -d {d}'
                p = tp_w.value.strip()
                if p: c += f' --pwd {p}'
                send(c)
            ui.button('Write', on_click=_t55w, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')

        cmd_card('4. Password Recovery', [
            ('lf t55xx bruteforce -s 00000000 -e FFFFFFFF', 'lf t55xx bruteforce -s 00000000 -e FFFFFFFF'),
            ('lf t55xx chk', 'lf t55xx chk'),
        ])
        cmd_card('5. Config Block Presets', [
            ('Default / reset', 'lf t55xx config --ST -d 0'),
            ('EM4100 mode',     'lf t55xx config --EM4'),
            ('HID26 mode',      'lf t55xx config --HID26'),
            ('Indala mode',     'lf t55xx config --Indala'),
            ('AWID mode',       'lf t55xx config --AWID'),
        ])

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('6. DUMP TO FILE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label('Saved to: ' + str(DUMP_DIR)).classes('text-xs text-grey-6 font-mono mb-2')
            t55_dump_fn = ui.input(label='Filename (no ext)', placeholder='lf-t55-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _t55_dump():
                fn = dump_path(t55_dump_fn.value.strip() or 'lf-t55-dump')
                send(f'lf t55xx dump -f {fn}')
                ui.notify(f'Dumping to {fn} …', type='positive')
            ui.button('Dump Tag', on_click=_t55_dump, color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-orange-900 p-3 w-full'):
            ui.label('7. RESTORE FROM FILE').classes('text-caption text-orange-400 font-mono mb-2')
            t55_rest_fn  = ui.input(label='Filename (no ext)', placeholder='lf-t55-dump').props('dense outlined dark').classes('w-full font-mono text-xs')
            t55_rest_pwd = ui.input(label='Password (opt, 8 hex)', placeholder='').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _t55_restore():
                fn  = dump_path(t55_rest_fn.value.strip() or 'lf-t55-dump')
                pwd = t55_rest_pwd.value.strip()
                cmd = f'lf t55xx restore -f {fn}'
                if pwd: cmd += f' --pwd {pwd}'
                send(cmd)
            ui.button('Restore to Tag', on_click=_t55_restore, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')

        t55_dl_holder = ui.column().classes('w-full')
        def _t55_refresh():
            t55_dl_holder.clear()
            with t55_dl_holder:
                make_download_bar('SAVED FILES')
        _t55_refresh()
        def _on_t55_upload(path: Path):
            t55_rest_fn.set_value(path.stem)
            _t55_refresh()
        make_upload_card('UPLOAD DUMP FILE', _on_t55_upload, accept='.bin,.json,.eml')

        cmd_card('8. Wipe', [
            ('lf t55xx wipe', 'lf t55xx wipe'),
        ])
        make_terminal()


# ── EM4x LF ──────────────────────────────────────

@ui.page('/lfem')
def page_lfem():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('EM4x · LF', 'EM4100 · EM4200 · EM4305 · EM4450', 'lf em')

        cmd_card('1. EM410x (Read-Only tags)', [
            ('lf em 410x info',   'lf em 410x info'),
            ('lf em 410x reader', 'lf em 410x reader'),
            ('lf em 410x demod',  'lf em 410x demod'),
            ('lf em 410x sniff',  'lf em 410x sniff'),
            ('lf em 410x sim',    'lf em 410x sim'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('2. CLONE EM4100 → T5577').classes('text-caption text-amber-400 font-mono mb-2')
            em_id = input_row('EM ID (10 hex)', '1122334455')
            def _em_clone():
                uid = em_id.value.strip()
                if uid: send(f'lf em 410x clone --id {uid}')
            ui.button('Clone to T5577', on_click=_em_clone, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')

        cmd_card('3. EM4305 (R/W tags)', [
            ('lf em 4305 info',    'lf em 4305 info'),
            ('lf em 4305 reader',  'lf em 4305 reader'),
            ('lf em 4305 dump',    'lf em 4305 dump'),
            ('lf em 4305 write',   'lf em 4305 write'),
            ('lf em 4305 protect', 'lf em 4305 protect'),
        ])
        cmd_card('4. EM4450', [
            ('lf em 4450 reader', 'lf em 4450 reader'),
            ('lf em 4450 dump',   'lf em 4450 dump'),
        ])
        make_terminal()


# ── HID Prox ─────────────────────────────────────

@ui.page('/lfhid')
def page_lfhid():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('HID Prox · LF', '26-bit / 35-bit / Corporate 1000 / H10301', 'lf hid')

        cmd_card('1. Reconnaissance', [
            ('lf hid info',  'lf hid info'),
            ('lf hid reader','lf hid reader'),
            ('lf hid demod', 'lf hid demod'),
            ('lf hid sniff', 'lf hid sniff'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('2. CLONE / SIMULATE').classes('text-caption text-amber-400 font-mono mb-2')
            hid_fmt = ui.select(['H10301','Corporate1000','HID35'], value='H10301', label='Format').props('dense outlined dark').classes('w-full font-mono text-xs')
            hid_fc  = input_row('Facility code', '0')
            hid_cn  = input_row('Card number', '1')
            def _hid_sim():
                send(f'lf hid sim -w {hid_fmt.value} -F {hid_fc.value.strip()} -C {hid_cn.value.strip()}')
            def _hid_clone():
                send(f'lf hid clone -w {hid_fmt.value} -F {hid_fc.value.strip()} -C {hid_cn.value.strip()}')
            with ui.row().classes('gap-2 mt-1'):
                ui.button('Simulate', on_click=_hid_sim,  color='teal').props('outline dense').classes('font-mono text-xs flex-1')
                ui.button('Clone',    on_click=_hid_clone, color='red' ).props('outline dense').classes('font-mono text-xs flex-1')

        cmd_card('3. Brute Force', [
            ('lf hid brute -F 0 -C 1 --up', 'lf hid brute -F 0 -C 1 --up'),
        ])
        make_terminal()


# ── Indala ───────────────────────────────────────

@ui.page('/lfindala')
def page_lfindala():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Indala · LF', 'Motorola / Indala RFID', 'lf indala')
        cmd_card('1. Reconnaissance', [
            ('lf indala reader',   'lf indala reader'),
            ('lf indala demod',    'lf indala demod'),
            ('lf indala altdemod', 'lf indala altdemod'),
            ('lf indala sniff',    'lf indala sniff'),
        ])
        cmd_card('2. Clone / Simulate', [
            ('lf indala clone', 'lf indala clone'),
            ('lf indala sim',   'lf indala sim'),
        ])
        make_terminal()


# ── ioProx / Other LF ────────────────────────────

@ui.page('/lfio')
def page_lfio():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('ioProx · Paradox · Keri · AWID', 'Other common LF protocols')
        cmd_card('ioProx', [
            ('lf io reader', 'lf io reader'),
            ('lf io demod',  'lf io demod'),
            ('lf io clone',  'lf io clone'),
            ('lf io sim',    'lf io sim'),
        ])
        cmd_card('AWID', [
            ('lf awid reader', 'lf awid reader'),
            ('lf awid demod',  'lf awid demod'),
            ('lf awid clone',  'lf awid clone'),
            ('lf awid brute',  'lf awid brute'),
        ])
        cmd_card('Paradox', [
            ('lf paradox reader', 'lf paradox reader'),
            ('lf paradox demod',  'lf paradox demod'),
            ('lf paradox clone',  'lf paradox clone'),
            ('lf paradox sim',    'lf paradox sim'),
        ])
        cmd_card('Keri / Viking / Gallagher', [
            ('lf keri reader',      'lf keri reader'),
            ('lf keri clone',       'lf keri clone'),
            ('lf viking reader',    'lf viking reader'),
            ('lf viking clone',     'lf viking clone'),
            ('lf gallagher reader', 'lf gallagher reader'),
            ('lf gallagher clone',  'lf gallagher clone'),
        ])
        make_terminal()


# ── Other LF ─────────────────────────────────────

@ui.page('/lfother')
def page_lfother():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Other LF Protocols', 'Hitag · Noralsy · Securakey · FDX · etc.')
        cmd_card('Hitag (LF)', [
            ('lf hitag info',   'lf hitag info'),
            ('lf hitag reader', 'lf hitag reader'),
            ('lf hitag dump',   'lf hitag dump'),
            ('lf hitag sim',    'lf hitag sim'),
        ])
        cmd_card('FDX-B', [
            ('lf fdxb reader', 'lf fdxb reader'),
            ('lf fdxb demod',  'lf fdxb demod'),
            ('lf fdxb clone',  'lf fdxb clone'),
        ])
        cmd_card('Noralsy / Securakey / Pyramid / NexWatch', [
            ('lf noralsy reader',   'lf noralsy reader'),
            ('lf securakey reader', 'lf securakey reader'),
            ('lf pyramid reader',   'lf pyramid reader'),
            ('lf nexwatch reader',  'lf nexwatch reader'),
            ('lf pac reader',       'lf pac reader'),
        ])
        cmd_card('JABLOTRON / EM4x50', [
            ('lf jablotron reader', 'lf jablotron reader'),
            ('lf em 4x50 reader',   'lf em 4x50 reader'),
            ('lf em 4x50 dump',     'lf em 4x50 dump'),
        ])
        make_terminal()


# ── NFC ──────────────────────────────────────────

@ui.page('/nfc')
def page_nfc():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('NFC', 'NDEF · NFC Forum tags', 'nfc')
        cmd_card('Read NDEF', [
            ('hf mfu ndefs', 'hf mfu ndefs'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('DECODE NDEF HEX').classes('text-caption text-amber-400 font-mono mb-2')
            ndef_hex = input_row('NDEF hex bytes', 'D101...')
            def _ndef():
                d = ndef_hex.value.strip()
                if d: send(f'nfc decode -d {d}')
            ui.button('Decode', on_click=_ndef, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')
        make_terminal()


# ── EMV ──────────────────────────────────────────

@ui.page('/emv')
def page_emv():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('EMV · ISO14443 / ISO7816', 'Payment cards — contactless & contact', 'emv')

        with ui.card().classes('w-full bg-grey-10 border border-amber-900 p-2'):
            ui.label(
                '[-s] = activate field & select card (contactless)    [-w] = wired/contact\n'
                '[-k] = keep field ON    [-t] = TLV decode    [-a] = show APDUs'
            ).classes('text-xs text-amber-300 font-mono')

        cmd_card('1. Reconnaissance', [
            ('emv search -s        — find all applets (contactless)', 'emv search -s'),
            ('emv search -st       — find applets + TLV decode',      'emv search -st'),
            ('emv search -w        — find all applets (contact)',      'emv search -w'),
            ('emv pse -s           — read 2PAY directory',            'emv pse -s'),
            ('emv pse -s -1        — read 1PAY directory',            'emv pse -s -1'),
            ('emv reader           — act as EMV reader',              'emv reader'),
            ('emv reader -v        — verbose EMV reader',             'emv reader -v'),
        ])

        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('2. SELECT APPLET BY AID').classes('text-caption text-amber-400 font-mono mb-2')
            common_aids = {
                'VISA':'A0000000031010', 'Mastercard':'A0000000041010',
                'Amex':'A00000002501',   'Maestro':'A0000000043060',
                'VISA Debit':'A0000000980840', 'Discover':'A0000001523010',
                'JCB':'A0000000651010',  '2PAY (PPSE)':'325041592E5359532E4444463031',
            }
            emv_aid   = ui.input(label='AID (hex)', placeholder='A0000000031010').props('dense outlined dark').classes('w-full font-mono text-xs')
            emv_iface = ui.select(['-s (contactless)', '-w (contact)'], value='-s (contactless)', label='Interface').props('dense outlined dark').classes('w-full font-mono text-xs')
            emv_tlv   = ui.checkbox('TLV decode (-t)', value=True).props('dark dense')
            with ui.row().classes('gap-1 flex-wrap mt-1'):
                for _nm, _aid in common_aids.items():
                    ui.button(_nm, on_click=lambda a=_aid: emv_aid.set_value(a),
                              color='blue-grey').props('flat dense size=xs').classes('font-mono text-xs')
            def _emv_select():
                a  = emv_aid.value.strip()
                ch = emv_iface.value.split()[0]
                t  = 't' if emv_tlv.value else ''
                if a:
                    send(f'emv select -s{t} {a}' if ch == '-s' else f'emv select -w {("-t " if t else "")}{a}')
            ui.button('Select AID', on_click=_emv_select, color='red').props('outline dense').classes('font-mono text-xs w-full mt-2')

        cmd_card('3. Read Records', [
            ('emv readrec -k 0101  — SFI=01 rec=01 (keep field)', 'emv readrec -k 0101'),
            ('emv readrec -kt 0101 — SFI=01 rec=01 + TLV',        'emv readrec -kt 0101'),
            ('emv readrec -k 0201  — SFI=02 rec=01',              'emv readrec -k 0201'),
            ('emv readrec -k 0301  — SFI=03 rec=01',              'emv readrec -k 0301'),
            ('emv list             — list ISO7816 history',        'emv list'),
        ])

        cmd_card('4. Full Transaction', [
            ('emv exec -sat        — MSD, show APDUs + TLV',    'emv exec -sat'),
            ('emv exec -satc       — CDA transaction',           'emv exec -satc'),
            ('emv exec -sat --qvsdc — qVSDC / M/Chip',           'emv exec -sat --qvsdc'),
            ('emv exec -sat -w     — contact interface',         'emv exec -sat -w'),
        ])

        cmd_card('5. Manual Transaction Steps', [
            ('emv gpo -k           — GetProcessingOptions',      'emv gpo -k'),
            ('emv gpo -pmt 9F3704  — GPO with PDOL from file',   'emv gpo -pmt 9F3704'),
            ('emv genac -k -d tc   — GenerateAC (approved)',     'emv genac -k -d tc'),
            ('emv genac -k -d aac  — GenerateAC (declined)',     'emv genac -k -d aac'),
            ('emv genac -k -d arqc — GenerateAC (online auth)',  'emv genac -k -d arqc'),
            ('emv challenge -k     — Generate Challenge',        'emv challenge -k'),
            ('emv intauth -k 01020304 — Internal Auth',          'emv intauth -k 01020304'),
        ])

        cmd_card('6. Crypto & Security Tests', [
            ('emv test        — crypto self-tests',        'emv test'),
            ('emv roca        — contactless ROCA vuln test','emv roca'),
            ('emv roca -w     — contact ROCA test',        'emv roca -w'),
            ('emv roca --test — ROCA self-test only',      'emv roca --test'),
        ])

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('7. DUMP CARD → JSON FILE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label('Saves to: ' + str(DUMP_DIR)).classes('text-xs text-grey-6 font-mono mb-2')
            dump_fn    = ui.input(label='Filename (no ext)', placeholder='mycard').props('dense outlined dark').classes('w-full font-mono text-xs')
            dump_mode  = ui.select(['MSD (default)', 'qVSDC / M/Chip (--qvsdc)', 'qVSDC+CDA (-c)', 'VSDC (-x)'],
                                   value='MSD (default)', label='Transaction type').props('dense outlined dark').classes('w-full font-mono text-xs')
            dump_iface = ui.select(['Contactless (default)', 'Contact/wired (-w)'],
                                   value='Contactless (default)', label='Interface').props('dense outlined dark').classes('w-full font-mono text-xs')
            with ui.row().classes('gap-2 mt-1 flex-wrap'):
                dump_apdu = ui.checkbox('APDUs (-a)', value=True).props('dark dense')
                dump_tlv  = ui.checkbox('TLV (-t)',   value=True).props('dark dense')
                dump_ext  = ui.checkbox('Extract (-e)', value=True).props('dark dense')
            def _emv_dump():
                stem = dump_fn.value.strip() or 'emv_dump'
                abs_path = dump_path(stem)
                flags = ''
                if dump_apdu.value: flags += 'a'
                if dump_tlv.value:  flags += 't'
                if dump_ext.value:  flags += 'e'
                mode = dump_mode.value
                if '--qvsdc' in mode:   extra = ' --qvsdc'
                elif '-c' in mode:      extra = ' -c'
                elif '-x' in mode:      extra = ' -x'
                else:                   extra = ''
                wired = ' -w' if 'wired' in dump_iface.value or ('Contact' in dump_iface.value and 'default' not in dump_iface.value) else ''
                f = f'-{flags}' if flags else ''
                send(f'emv scan {f}{extra}{wired} {abs_path}')
                ui.notify(f'Dumping to {abs_path}.json …', type='positive')
                import threading as _t
                def _later():
                    import time as _tm; _tm.sleep(4)
                    _refresh_dl()
                _t.Thread(target=_later, daemon=True).start()
            ui.button('Dump Card to JSON', on_click=_emv_dump, color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-red-900 p-3 w-full'):
            ui.label('8. SEND RAW APDU').classes('text-caption text-red-400 font-mono mb-1')
            ui.label('EMV cards are read-only at the terminal level. Use raw APDUs for JavaCard / test cards.').classes('text-xs text-grey-5 font-mono mb-2')
            write_apdu  = ui.input(label='APDU hex', placeholder='00A4040007A0000000031010').props('dense outlined dark').classes('w-full font-mono text-xs')
            write_iface = ui.select(['Contact T=0 (smart raw)', 'Contactless (hf 14a apdu)'],
                                    value='Contact T=0 (smart raw)', label='Interface').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _emv_write():
                d = write_apdu.value.strip()
                if not d: return
                if 'Contact' in write_iface.value:
                    send(f'smart raw -s -0 -t -d {d}')
                else:
                    send(f'hf 14a apdu -st -d {d}')
            ui.button('Send APDU', on_click=_emv_write, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')

        dl_card_holder = ui.column().classes('w-full')
        def _refresh_dl():
            dl_card_holder.clear()
            with dl_card_holder:
                make_download_bar('SAVED DUMP FILES  (click ↓ to download)')
        _refresh_dl()

        def _on_upload(path: Path):
            ui.notify(f'Ready: {path.name}', type='positive')
            _refresh_dl()
        make_upload_card('UPLOAD DUMP FILE (for emulation / write)', _on_upload, accept='.json,.bin,.eml')

        make_terminal()


# ── Smart Card ISO-7816 ──────────────────────────

@ui.page('/smart')
def page_smart():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Smart Card · ISO-7816', 'Contact smart cards via SAM / SCM reader', 'smart')
        cmd_card('1. Reader & ATR', [
            ('smart info',   'smart info'),
            ('smart reader', 'smart reader'),
            ('smart atr',    'smart atr'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('2. SEND APDU').classes('text-caption text-amber-400 font-mono mb-2')
            sm_d = input_row('APDU (hex)', '00A4040000')
            def _sm():
                d = sm_d.value.strip()
                if d: send(f'smart raw -s -0 -t -d {d}')
            ui.button('Send', on_click=_sm, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')
        make_terminal()


# ── PIV ──────────────────────────────────────────

@ui.page('/piv')
def page_piv():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('PIV / CAC', 'Personal Identity Verification cards', 'piv')
        cmd_card('1. Read', [
            ('piv info',    'piv info'),
            ('piv reader',  'piv reader'),
            ('piv getdata', 'piv getdata'),
            ('piv scan',    'piv scan'),
        ])
        cmd_card('2. Certificates', [
            ('piv cert',  'piv cert'),
            ('piv nist',  'piv nist'),
            ('piv chuid', 'piv chuid'),
        ])
        make_terminal()


# ── Hardware ─────────────────────────────────────

@ui.page('/hw')
def page_hw():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Hardware', 'Device status and configuration', 'hw')
        cmd_card('Status & Info', [
            ('hw version', 'hw version'),
            ('hw status',  'hw status'),
            ('hw info',    'hw info'),
            ('hw pingng',  'hw pingng'),
            ('prefs show', 'prefs show'),
        ])
        cmd_card('Device Control', [
            ('hw dbg',      'hw dbg'),
            ('hw reset',    'hw reset'),
            ('hw tearoff',  'hw tearoff'),
            ('hw list',     'hw list'),
            ('hw standalone','hw standalone'),
        ])
        with ui.card().classes('bg-grey-10 border border-red-900 p-3 w-full'):
            ui.label('⚠  DANGER ZONE').classes('text-caption text-red-400 font-mono mb-2')
            cmd_card('Flash / Update', [
                ('hw flash   — flash firmware (caution!)', 'hw flash'),
                ('hw flushto — flush to device',           'hw flushto'),
            ], color='deep-orange')
        make_terminal()


@ui.page('/hwtune')
def page_hwtune():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Antenna Tuning', 'Measure HF/LF antenna performance', 'hw tune')
        cmd_card('Tune', [
            ('hw tune         — both antennas', 'hw tune'),
            ('hw tune --lf    — LF only',       'hw tune --lf'),
            ('hw tune --hf    — HF only',       'hw tune --hf'),
            ('lf tune         — LF measurement','lf tune'),
            ('hf tune         — HF measurement','hf tune'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('NOTES').classes('text-caption text-amber-400 font-mono mb-1')
            ui.label(
                'LF optimum: ~125 kHz or ~134 kHz\n'
                'HF optimum: ~13.56 MHz\n'
                'Output shows voltage & resonant frequency'
            ).classes('text-xs text-grey-4 font-mono')
        make_terminal()


# ── Analyse ──────────────────────────────────────

@ui.page('/analyse')
def page_analyse():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Analyse', 'Utility analysis tools', 'analyse')
        cmd_card('Bit / Byte Analysis', [
            ('analyse bits',    'analyse bits'),
            ('analyse chksum',  'analyse chksum'),
            ('analyse crc',     'analyse crc'),
            ('analyse demod',   'analyse demod'),
            ('analyse freq',    'analyse freq'),
            ('analyse lcr',     'analyse lcr'),
            ('analyse list',    'analyse list'),
            ('analyse nuid',    'analyse nuid'),
        ])
        cmd_card('Clocks & Encoding', [
            ('analyse a',       'analyse a'),
            ('analyse clocks',  'analyse clocks'),
            ('analyse lfsr',    'analyse lfsr'),
            ('analyse tea',     'analyse tea'),
            ('analyse units',   'analyse units'),
        ])
        make_terminal()


# ── Data / Plot ───────────────────────────────────

@ui.page('/data')
def page_data():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Data / Plot', 'Raw signal buffer manipulation', 'data')
        cmd_card('Buffer', [
            ('data info',         'data info'),
            ('data plot',         'data plot'),
            ('data print',        'data print'),
            ('data save -f dump', 'data save -f dump'),
            ('data load -f dump', 'data load -f dump'),
            ('data clear',        'data clear'),
        ])
        cmd_card('Decode / Manipulate', [
            ('data biphaserawdecode', 'data biphaserawdecode'),
            ('data detectclock',      'data detectclock'),
            ('data fskrawdemod',      'data fskrawdemod'),
            ('data manrawdecode',     'data manrawdecode'),
            ('data rawdemod',         'data rawdemod'),
            ('data askedge',          'data askedge'),
            ('data norm',             'data norm'),
            ('data trim',             'data trim'),
        ])
        make_terminal()


# ── Trace ─────────────────────────────────────────

@ui.page('/trace')
def page_trace():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Trace · Sniff', 'Capture and decode RF traffic', 'trace')

        cmd_card('1. Capture', [
            ('hf sniff',        'hf sniff'),
            ('hf 14a sniff',    'hf 14a sniff'),
            ('hf 14b sniff',    'hf 14b sniff'),
            ('hf 15 sniff',     'hf 15 sniff'),
            ('hf mf sniff',     'hf mf sniff'),
            ('hf iclass sniff', 'hf iclass sniff'),
            ('lf sniff',        'lf sniff'),
        ])
        cmd_card('2. Decode Buffer', [
            ('trace list -t 14a',    'trace list -t 14a'),
            ('trace list -t 14b',    'trace list -t 14b'),
            ('trace list -t 15',     'trace list -t 15'),
            ('trace list -t mf',     'trace list -t mf'),
            ('trace list -t iclass', 'trace list -t iclass'),
            ('trace list -t 7816',   'trace list -t 7816'),
            ('trace list -t felica', 'trace list -t felica'),
        ])

        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('3. SAVE TRACE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label('Saved to: ' + str(DUMP_DIR)).classes('text-xs text-grey-6 font-mono mb-2')
            trace_fn = ui.input(label='Filename (no ext)', placeholder='sniff').props('dense outlined dark').classes('w-full font-mono text-xs')
            def _trace_save():
                fn = dump_path(trace_fn.value.strip() or 'sniff')
                send(f'trace save -f {fn}')
                ui.notify(f'Saving trace to {fn}.trace …', type='positive')
            ui.button('Save Trace', on_click=_trace_save, color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')

        with ui.card().classes('bg-grey-10 border border-blue-900 p-3 w-full'):
            ui.label('4. LOAD & DECODE').classes('text-caption text-blue-400 font-mono mb-2')
            trace_load_fn = ui.input(label='Filename (no ext)', placeholder='sniff').props('dense outlined dark').classes('w-full font-mono text-xs')
            trace_proto   = ui.select(
                ['14a','14b','15','mf','iclass','7816','felica','raw','legic','lto','ht2','hts'],
                value='14a', label='Protocol'
            ).props('dense outlined dark').classes('w-full font-mono text-xs')
            def _trace_load():
                fn = dump_path(trace_load_fn.value.strip() or 'sniff')
                send(f'trace load -f {fn}')
                send(f'trace list -t {trace_proto.value}')
            ui.button('Load & Decode', on_click=_trace_load, color='blue').props('outline dense').classes('font-mono text-xs w-full mt-1')

        tr_dl_holder = ui.column().classes('w-full')
        def _tr_refresh():
            tr_dl_holder.clear()
            with tr_dl_holder:
                make_download_bar('SAVED TRACE FILES')
        _tr_refresh()
        def _on_tr_upload(path: Path):
            trace_load_fn.set_value(path.stem)
            _tr_refresh()
        make_upload_card('UPLOAD TRACE FILE', _on_tr_upload, accept='.trace,.bin')

        make_terminal()


# ── Wiegand ───────────────────────────────────────

@ui.page('/wiegand')
def page_wiegand():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Wiegand', 'Wiegand format encode / decode', 'wiegand')
        cmd_card('List Formats', [
            ('wiegand list', 'wiegand list'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('ENCODE').classes('text-caption text-amber-400 font-mono mb-2')
            wig_fmt = input_row('Format name', 'H10301')
            wig_fc  = input_row('Facility code', '0')
            wig_cn  = input_row('Card number', '1')
            def _wenc():
                send(f'wiegand encode -w {wig_fmt.value.strip()} -F {wig_fc.value.strip()} -C {wig_cn.value.strip()}')
            ui.button('Encode', on_click=_wenc, color='teal').props('outline dense').classes('font-mono text-xs w-full mt-1')
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('DECODE').classes('text-caption text-amber-400 font-mono mb-2')
            wig_raw = input_row('Raw Wiegand bits (hex)', '2006020')
            def _wdec():
                d = wig_raw.value.strip()
                if d: send(f'wiegand decode -r {d}')
            ui.button('Decode', on_click=_wdec, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')
        make_terminal()


# ── CRC / RevEng ──────────────────────────────────

@ui.page('/reveng')
def page_reveng():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('CRC · RevEng', 'CRC calculations from RevEng software', 'reveng')
        cmd_card('List CRC Models', [
            ('reveng -D', 'reveng -D'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('CALCULATE CRC').classes('text-caption text-amber-400 font-mono mb-2')
            crc_model = ui.select(
                ['CRC-8','CRC-16','CRC-32','CRC-CCITT','CRC-16/CCITT-FALSE','CRC-32/MPEG-2'],
                value='CRC-16', label='Model'
            ).props('dense outlined dark').classes('w-full font-mono text-xs')
            crc_data = input_row('Hex data', 'DEADBEEF')
            def _crc():
                d = crc_data.value.strip()
                if d: send(f'reveng -m {crc_model.value} -c {d}')
            ui.button('Calculate', on_click=_crc, color='teal').props('outline dense').classes('font-mono text-xs w-full mt-1')
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('BRUTEFORCE MODEL').classes('text-caption text-amber-400 font-mono mb-2')
            bf_data = input_row('Known data (hex)', 'DEADBEEF')
            bf_crc  = input_row('Known CRC result', '1234')
            def _bf():
                d = bf_data.value.strip()
                c = bf_crc.value.strip()
                if d and c: send(f'reveng -s {d} {c}')
            ui.button('Bruteforce', on_click=_bf, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')
        make_terminal()


# ── Scripts ───────────────────────────────────────

@ui.page('/script')
def page_script():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Scripts', 'Lua / CMD scripting', 'script')
        cmd_card('List & Help', [
            ('script list',   'script list'),
            ('script run -h', 'script run -h'),
        ])
        cmd_card('Common Scripts', [
            ('hf_mf_autopwn',       'script run hf_mf_autopwn.lua'),
            ('hf_mf_dumpdecrypted', 'script run hf_mf_dumpdecrypted.lua'),
            ('hf_mfu_magicwrite',   'script run hf_mfu_magicwrite.lua'),
            ('lf_em4x_clone',       'script run lf_em4x_clone.lua'),
            ('hf_14a_ndef',         'script run hf_14a_ndef.lua'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('RUN SCRIPT').classes('text-caption text-amber-400 font-mono mb-2')
            sc_name = input_row('Script name / path', 'myscript.lua')
            sc_args = input_row('Arguments (optional)', '-n 5')
            def _run_script():
                n = sc_name.value.strip()
                a = sc_args.value.strip()
                if n: send(f'script run {n}' + (f' {a}' if a else ''))
            ui.button('Run Script', on_click=_run_script, color='red').props('outline dense').classes('font-mono text-xs w-full mt-1')
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('RUN CMD FILE').classes('text-caption text-amber-400 font-mono mb-2')
            cmd_file = input_row('CMD file path', 'myscript.cmd')
            def _run_cmd():
                f = cmd_file.value.strip()
                if f: send(f'script run {f}')
            ui.button('Run CMD file', on_click=_run_cmd, color='orange').props('outline dense').classes('font-mono text-xs w-full mt-1')
        make_terminal()


# ── MQTT ─────────────────────────────────────────

@ui.page('/mqtt')
def page_mqtt():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('MQTT', 'Publish pm3 results to MQTT broker', 'mqtt')
        cmd_card('Commands', [
            ('mqtt connect',    'mqtt connect'),
            ('mqtt status',     'mqtt status'),
            ('mqtt disconnect', 'mqtt disconnect'),
            ('mqtt help',       'mqtt help'),
        ])
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('CONNECT TO BROKER').classes('text-caption text-amber-400 font-mono mb-2')
            mq_host  = input_row('Broker host', 'localhost')
            mq_port  = input_row('Port', '1883')
            mq_topic = input_row('Topic', 'pm3/results')
            def _mq_conn():
                h = mq_host.value.strip()
                p = mq_port.value.strip()
                t = mq_topic.value.strip()
                send(f'mqtt connect -h {h} -p {p} -t {t}')
            ui.button('Connect', on_click=_mq_conn, color='teal').props('outline dense').classes('font-mono text-xs w-full mt-1')
        make_terminal()




# ── Firmware Update ───────────────────────────────

FIRMWARE_DIR = DUMP_DIR.parent / 'firmware'
FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)

# GitHub API URL for latest release
GITHUB_RELEASES_URL = 'https://api.github.com/repos/RfidResearchGroup/proxmark3/releases/latest'


def _fetch_latest_release() -> dict:
    """Fetch latest release metadata from GitHub API. Returns dict or raises."""
    import urllib.request, json
    req = urllib.request.Request(
        GITHUB_RELEASES_URL,
        headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'pm3-gui/1.0'}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def _find_release_zip(assets: list) -> dict | None:
    """Pick the best firmware zip asset. Prefer rdv4, fall back to any zip with elf files."""
    # Priority: rdv4 zip > generic zip
    for keyword in ['rdv4', 'proxmark3', 'pm3']:
        for a in assets:
            name = a['name'].lower()
            if name.endswith('.zip') and keyword in name:
                return a
    # Any zip
    for a in assets:
        if a['name'].lower().endswith('.zip'):
            return a
    return None


@ui.page('/firmware')
def page_firmware():
    add_shared_layout()
    with ui.column().classes('p-4 w-full gap-4 max-w-3xl mx-auto'):
        page_header('Firmware Update', 'Download & flash latest RRG/Iceman firmware', 'hw')

        with ui.card().classes('w-full bg-grey-10 border border-amber-900 p-3'):
            ui.label(
                '⚠  Disconnect the pm3 client before flashing.\n'
                'The flasher uses the same serial port — both cannot run simultaneously.\n'
                'Source: github.com/RfidResearchGroup/proxmark3'
            ).classes('text-xs text-amber-300 font-mono')

        # ── Current installed version ─────────────────
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('INSTALLED VERSION').classes('text-caption text-amber-400 font-mono mb-2')
            installed_lbl = ui.label('Run hw version to check').classes('text-xs text-grey-3 font-mono')
            ui.button('hw version', on_click=lambda: send('hw version'),
                      color='blue').props('outline dense').classes('font-mono text-xs mt-1')

        # ── Latest release info ───────────────────────
        with ui.card().classes('bg-grey-10 border border-grey-800 p-3 w-full'):
            ui.label('LATEST RELEASE  (github.com/RfidResearchGroup/proxmark3)').classes('text-caption text-amber-400 font-mono mb-2')
            release_info  = ui.label('Click "Check" to query GitHub').classes('text-xs text-grey-3 font-mono')
            release_date  = ui.label('').classes('text-xs text-grey-6 font-mono')
            release_notes = ui.label('').classes('text-xs text-grey-5 font-mono mt-1').style('white-space:pre-wrap; max-height:120px; overflow-y:auto;')
            asset_lbl     = ui.label('').classes('text-xs text-teal-400 font-mono mt-1')

            _release_state = {'data': None}

            def _check_release():
                release_info.set_text('Fetching …')
                release_date.set_text('')
                release_notes.set_text('')
                asset_lbl.set_text('')
                try:
                    data = _fetch_latest_release()
                    _release_state['data'] = data
                    tag  = data.get('tag_name', '?')
                    name = data.get('name', tag)
                    date = data.get('published_at', '')[:10]
                    body = data.get('body', '')
                    # Truncate changelog to first 20 lines
                    lines = body.splitlines()[:20]
                    body_short = '\n'.join(lines) + ('\n…' if len(body.splitlines()) > 20 else '')
                    asset = _find_release_zip(data.get('assets', []))
                    asset_text = f'Asset: {asset["name"]}  ({asset["size"]//1024} KB)' if asset else 'No zip asset found'
                    release_info.set_text(f'{name}  ({tag})')
                    release_date.set_text(f'Published: {date}')
                    release_notes.set_text(body_short)
                    asset_lbl.set_text(asset_text)
                    dl_btn.enable()
                except Exception as e:
                    release_info.set_text(f'Error: {e}')
                    _release_state['data'] = None

            ui.button('↺ Check GitHub', on_click=_check_release,
                      color='grey').props('outline dense').classes('font-mono text-xs mt-2')

        # ── Download firmware ─────────────────────────
        with ui.card().classes('bg-grey-10 border border-green-900 p-3 w-full'):
            ui.label('DOWNLOAD FIRMWARE').classes('text-caption text-green-400 font-mono mb-1')
            ui.label(f'Downloads to: {FIRMWARE_DIR}').classes('text-xs text-grey-6 font-mono mb-2')

            dl_progress = ui.label('').classes('text-xs text-grey-3 font-mono')
            dl_log      = ui.label('').classes('text-xs text-grey-5 font-mono mt-1').style('white-space:pre-wrap; max-height:80px; overflow-y:auto;')

            def _do_download():
                data = _release_state.get('data')
                if not data:
                    dl_progress.set_text('No release loaded — click Check GitHub first')
                    return
                asset = _find_release_zip(data.get('assets', []))
                if not asset:
                    dl_progress.set_text('No downloadable zip asset in this release')
                    return

                dl_progress.set_text(f'Downloading {asset["name"]} …')
                dl_log.set_text('')
                dl_btn.disable()

                import threading, urllib.request, zipfile

                def _worker():
                    try:
                        url      = asset['browser_download_url']
                        dest_zip = FIRMWARE_DIR / asset['name']

                        # Stream download with progress
                        req = urllib.request.Request(url, headers={'User-Agent': 'pm3-gui/1.0'})
                        with urllib.request.urlopen(req, timeout=60) as resp:
                            total   = int(resp.headers.get('Content-Length', 0))
                            done    = 0
                            chunk   = 65536
                            with open(dest_zip, 'wb') as fout:
                                while True:
                                    buf = resp.read(chunk)
                                    if not buf:
                                        break
                                    fout.write(buf)
                                    done += len(buf)
                                    pct = int(done * 100 / total) if total else 0
                                    dl_progress.set_text(f'Downloading … {pct}%  ({done//1024} / {total//1024} KB)')

                        dl_progress.set_text(f'Downloaded: {dest_zip.name}  — extracting …')

                        # Extract .elf files
                        extracted = []
                        with zipfile.ZipFile(dest_zip) as z:
                            for member in z.namelist():
                                basename = Path(member).name
                                if basename in ('bootrom.elf', 'fullimage.elf'):
                                    dest_elf = FIRMWARE_DIR / basename
                                    with z.open(member) as src_f, open(dest_elf, 'wb') as dst_f:
                                        dst_f.write(src_f.read())
                                    extracted.append(basename)

                        if not extracted:
                            dl_progress.set_text('⚠  No .elf files found in zip!')
                            dl_log.set_text(f'Contents: {chr(10).join(z.namelist()[:20])}')
                        else:
                            dl_progress.set_text(f'✓ Ready: {", ".join(extracted)}')
                            dl_log.set_text(f'Saved to {FIRMWARE_DIR}')
                            # Populate the flash path inputs
                            for nm in extracted:
                                p = str(FIRMWARE_DIR / nm)
                                if 'bootrom' in nm:
                                    boot_path.set_value(p)
                                elif 'fullimage' in nm:
                                    full_path.set_value(p)
                            flash_section.visible = True

                        dl_btn.enable()

                    except Exception as ex:
                        dl_progress.set_text(f'Error: {ex}')
                        dl_btn.enable()

                threading.Thread(target=_worker, daemon=True).start()

            dl_btn = ui.button('Download Firmware', on_click=_do_download,
                               color='green').props('outline dense').classes('font-mono text-xs w-full mt-1')
            dl_btn.disable()   # enabled after Check

        # ── Upload own .elf files ─────────────────────
        with ui.card().classes('bg-grey-10 border border-blue-900 p-3 w-full'):
            ui.label('OR UPLOAD YOUR OWN .ELF FILES').classes('text-caption text-blue-400 font-mono mb-2')

            def _on_elf_upload(e):
                dest = FIRMWARE_DIR / e.name
                with open(dest, 'wb') as f:
                    f.write(e.content.read())
                ui.notify(f'Saved: {dest}', type='positive')
                p = str(dest)
                if 'bootrom' in e.name:
                    boot_path.set_value(p)
                elif 'fullimage' in e.name:
                    full_path.set_value(p)
                flash_section.visible = True

            ui.upload(
                label='Drop bootrom.elf / fullimage.elf here',
                on_upload=_on_elf_upload,
                auto_upload=True,
                multiple=True,
            ).props('accept=".elf" flat outlined dark').classes('w-full font-mono text-xs')

        # ── Flash section (shown after files are ready) ─
        flash_section = ui.card().classes('bg-grey-10 border border-red-900 p-3 w-full')
        flash_section.visible = False

        with flash_section:
            ui.label('⚡ FLASH FIRMWARE').classes('text-caption text-red-400 font-mono mb-2')
            ui.label(
                'Disconnect the pm3 client first!  The device must be on the same serial port.\n'
                'For old bootloaders: unplug, hold button, replug while holding button.'
            ).classes('text-xs text-amber-300 font-mono mb-2')

            boot_path = ui.input(
                label='bootrom.elf path', placeholder=str(FIRMWARE_DIR / 'bootrom.elf')
            ).props('dense outlined dark').classes('w-full font-mono text-xs')
            full_path = ui.input(
                label='fullimage.elf path', placeholder=str(FIRMWARE_DIR / 'fullimage.elf')
            ).props('dense outlined dark').classes('w-full font-mono text-xs')

            flash_port = ui.select(
                options=get_available_ports() or ['/dev/ttyACM0'],
                label='Port', value=(get_available_ports() or ['/dev/ttyACM0'])[0]
            ).props('dense outlined dark').classes('w-full font-mono text-xs mt-1')

            flash_opts = ui.row().classes('gap-2 mt-1 flex-wrap')
            with flash_opts:
                cb_unlock   = ui.checkbox('--unlock-bootloader', value=True).props('dark dense')
                cb_force    = ui.checkbox('--force (skip version check)', value=False).props('dark dense')
                cb_boot_only = ui.checkbox('Bootrom only', value=False).props('dark dense')

            flash_log   = ui.label('').classes('text-xs text-grey-3 font-mono mt-2').style(
                'white-space:pre-wrap; max-height:180px; overflow-y:auto; background:#0a0a0a; padding:6px; border-radius:4px; width:100%;'
            )

            def _do_flash():
                port = flash_port.value
                boot = boot_path.value.strip() or str(FIRMWARE_DIR / 'bootrom.elf')
                full = full_path.value.strip() or str(FIRMWARE_DIR / 'fullimage.elf')

                if not Path(boot).exists():
                    flash_log.set_text(f'bootrom.elf not found: {boot}')
                    return
                if not cb_boot_only.value and not Path(full).exists():
                    flash_log.set_text(f'fullimage.elf not found: {full}')
                    return

                pm3_bin = find_pm3_binary()
                if not pm3_bin:
                    flash_log.set_text('pm3 binary not found — cannot flash')
                    return

                # Disconnect GUI session first
                disconnect()

                # Build command
                cmd_parts = [pm3_bin, port, '--flash']
                if cb_unlock.value:
                    cmd_parts.append('--unlock-bootloader')
                if cb_force.value:
                    cmd_parts.append('--force')
                cmd_parts += ['--image', boot]
                if not cb_boot_only.value:
                    cmd_parts += ['--image', full]

                flash_log.set_text(f'Running:\n{" ".join(cmd_parts)}\n\n')
                flash_btn.disable()
                ui.notify('Flashing started — do not unplug!', type='warning')

                import threading, subprocess as _sp

                def _flash_worker():
                    try:
                        proc = _sp.Popen(
                            cmd_parts,
                            stdout=_sp.PIPE, stderr=_sp.STDOUT,
                            text=True, env={**os.environ, 'TERM': 'dumb'}
                        )
                        lines = []
                        for line in proc.stdout:
                            lines.append(line.rstrip())
                            flash_log.set_text('\n'.join(lines[-60:]))
                        proc.wait()
                        result = '\n✓ Flash complete! Reconnect the device.' if proc.returncode == 0 else f'\n✗ Flasher exited with code {proc.returncode}'
                        lines.append(result)
                        flash_log.set_text('\n'.join(lines[-60:]))
                        ui.notify('Flash complete — reconnect device', type='positive' if proc.returncode == 0 else 'negative')
                    except Exception as ex:
                        flash_log.set_text(f'Error: {ex}')
                    finally:
                        flash_btn.enable()

                threading.Thread(target=_flash_worker, daemon=True).start()

            flash_btn = ui.button('⚡ Flash Now', on_click=_do_flash,
                                  color='red').props('outline dense').classes('font-mono text-xs w-full mt-2')

            with ui.row().classes('gap-2 mt-1'):
                ui.button('↺ Refresh ports', on_click=lambda: flash_port.set_options(get_available_ports() or ['/dev/ttyACM0']),
                          color='grey').props('flat dense size=xs').classes('font-mono text-xs')
                ui.button('Show downloaded files', on_click=lambda: [
                    flash_log.set_text('\n'.join(str(p) for p in FIRMWARE_DIR.iterdir()))
                ], color='grey').props('flat dense size=xs').classes('font-mono text-xs')

        make_terminal()

# ────────────────────────────────────────────────
# SHUTDOWN
# ────────────────────────────────────────────────

def _shutdown(sig, frame):
    log('Shutdown — terminating pm3 process')
    if pm3_proc and pm3_proc.poll() is None:
        try:
            pm3_proc.stdin.write('quit\n')
            pm3_proc.stdin.flush()
            time.sleep(0.4)
        except Exception:
            pass
        pm3_proc.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

log('=== Proxmark3 GUI starting ===')
_b = find_pm3_binary()
log(f'pm3 binary : {_b or "NOT FOUND"}')
log(f'Ports found: {get_available_ports()}')

ui.run(
    title='Proxmark3',
    host='0.0.0.0',
    port=8080,
    dark=True,
    reload=False,
    show=False,
    show_welcome_message=False,
)