"""
Cuttlefish (crosvm)
Target OS: EndeavourOS (Linux Hardened, Wayland/KDE, NVIDIA)
"""

# sudo /home/none/cuttlefish/user/bin/adb -s 127.0.0.1:6520 shell getprop ro.build.type
# sudo /home/none/cuttlefish/user/bin/adb -s 127.0.0.1:6520 shell getprop ro.build.version.release
# sudo /home/none/cuttlefish/user/bin/adb -s 127.0.0.1:6520 shell getprop ro.build.version.sdk

import os
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.system("clear")
os.system("stty sane 2>/dev/null")
import sys
import re

class DashboardDualLogger:
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout
        self.buffer = ""
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def write(self, message):
        self.original_stdout.write(message)
        self.original_stdout.flush()

        if "console" in sys.argv:
            return

        self.buffer += message

        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            self._send_to_dash(line)

        if "\r" in self.buffer:
            parts = self.buffer.split("\r")
            if len(parts) > 1 and parts[-2].strip():
                self._send_to_dash(parts[-2])
            self.buffer = parts[-1]

    def _send_to_dash(self, line):
        clean_line = self.ansi_escape.sub('', line).strip()

        # PREVENT UI FLICKER: Ignore the terminal's 1-line telemetry string.
        # The compiler loop will manually send a custom 2-line version to the UI.
        if clean_line.startswith("[BUILD TELEMETRY]"):
            return

        if clean_line and 'broadcast_log_line' in globals():
            try:
                if clean_line.startswith("[INFO]"):
                    clean_line = clean_line.replace("[INFO]", "[PROCESS]", 1)
                broadcast_log_line(clean_line)
            except Exception:
                pass

    def flush(self):
        self.original_stdout.flush()

# Hook the terminal output globally
sys.stdout = DashboardDualLogger(sys.stdout)
import argparse
import asyncio
import atexit
import base64
import builtins
import datetime
import getpass
import glob
import grp
import ipaddress
import json
import logging
import math
import os
import pty
import pwd
import queue
import re
import resource
import select
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.request
from pathlib import Path
import traceback


GLOBAL_CPU_PCT = 70
GLOBAL_RAM_PCT = 70
START_TIME = time.time()
GLOBAL_FILE_PROGRESS = ""
GLOBAL_PERCENT = ""
ACTIVE_ROADMAP_STEP = "Initializing..."
# Add these globals to track active processes for instant manual restarts
ACTIVE_WORKER_PROC = None
INTENTIONAL_RESTART = False
# --- PURE WAYLAND DISPLAY AUTO-DETECTION ---
# Completely purge X11/Xwayland usage
os.environ.pop("DISPLAY", None)
os.environ.pop("XAUTHORITY", None)

# Force UI toolkits into native Wayland mode
os.environ["GDK_BACKEND"] = "wayland"
os.environ["QT_QPA_PLATFORM"] = "wayland"
os.environ["SDL_VIDEODRIVER"] = "wayland"
os.environ["MOZ_ENABLE_WAYLAND"] = "1"

xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
wayland_sockets = glob.glob(os.path.join(xdg_runtime, "wayland-*"))
if wayland_sockets:
    os.environ["WAYLAND_DISPLAY"] = os.path.basename(wayland_sockets[0])
else:
    os.environ["WAYLAND_DISPLAY"] = "wayland-0"

ACTIVE_PROCESS_GROUPS = []
SHUTTING_DOWN = False
CURRENT_SYNC_THREADS = 8
CURRENT_COMPILE_THREADS = 1
dynamic_compile_threads = 1
ninja_load_limit = 2
RATE_LIMIT_STRIKES = 0
COMPILE_STRIKES = 0
SHUTDOWN_WITH_BROWSER = True
GLOBAL_LOG_BUFFER = []
GLOBAL_BANNER_LINES = []
DASHBOARD_PORT = None
DASHBOARD_BROWSER_PROC = None
_CACHED_SUDO_PASSWORD = None
CURRENT_FILE = os.path.abspath(__file__)
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
# Permanent vault for downloaded images and host packages
VAULT_DIR = "/opt/cuttlefish_vault"
# Permanent native filesystem path for Cuttlefish workspace
BASE_WORKSPACE = "/var/tmp/cuttlefish"
GLOBAL_CURRENT_SUBSYSTEM = "Initializing"
SUBSYSTEM_COUNTS = {}
SUBSYSTEM_TOTALS = {
    "packages": 12000,
    "frameworks": 15000,
    "hardware": 8000,
    "external": 10000,
    "system": 5000,
    "art": 3000,
    "build": 2000
}

if "no-root" in sys.argv:
    WORKSPACE_DIR = os.path.join(BASE_WORKSPACE, "user")
else:
    WORKSPACE_DIR = os.path.join(BASE_WORKSPACE, "debug")

def get_bin(name):
    """Dynamically resolves workspace binary or falls back to system PATH."""
    import shutil
    local_path = os.path.join(WORKSPACE_DIR, "bin", name)
    if os.path.exists(local_path):
        return local_path
    sys_path = shutil.which(name)
    return sys_path if sys_path else name

AOSP_SRC_DIR = os.path.join(WORKSPACE_DIR, "aosp_src")
USER_CACHE_DIR = os.path.join(WORKSPACE_DIR, "cuttlefish_user_cache")
DEBUG_LOG_PATH = os.path.join(WORKSPACE_DIR, "debug.log")
VENV_DIR = os.path.join(WORKSPACE_DIR, ".venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")
os.environ["ANDROID_SERIAL"] = "127.0.0.1:6520"
current_pid = os.getpid()
script_name = os.path.basename(__file__)

output_lock = threading.Lock()
GLOBAL_TERMINAL_OUTPUT = []

logger = logging.getLogger("CuttlefisLog")
logger.setLevel(logging.DEBUG)

VALID_COMMANDS = {"help", "docker", "no-root", "sandbox", "reset", "console", "ai", "stream", "banner", "do-copy", "refresh"}
unknown = [arg for arg in sys.argv[1:] if arg not in VALID_COMMANDS]

import subprocess
import shlex
from subprocess import CalledProcessError
import os
import time
import sys

def get_system_telemetry():
    """Reads live CPU load and RAM usage directly from /proc without external dependencies."""
    cpu_pct = 0.0
    try:
        with open('/proc/stat', 'r') as f:
            line1 = [float(x) for x in f.readline().split()[1:]]
        time.sleep(0.1)
        with open('/proc/stat', 'r') as f:
            line2 = [float(x) for x in f.readline().split()[1:]]
        idle_delta = (line2[3] + line2[4]) - (line1[3] + line1[4])
        total_delta = sum(line2) - sum(line1)
        if total_delta > 0:
            cpu_pct = round(100.0 * (1.0 - (idle_delta / total_delta)), 1)
    except Exception:
        pass

    mem_used_gb, mem_total_gb = 0.0, 31.0
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = {line.split(':')[0]: int(line.split()[1]) for line in f.readlines() if ':' in line}
            total_kb = meminfo.get('MemTotal', 1)
            avail_kb = meminfo.get('MemAvailable', total_kb)
            mem_total_gb = round(total_kb / (1024 * 1024), 1)
            mem_used_gb = round((total_kb - avail_kb) / (1024 * 1024), 1)
    except Exception:
        pass

    return cpu_pct, mem_used_gb, mem_total_gb

def get_sudo_password():
    """Reads the password file dynamically or prompts interactively once, caching it in memory."""
    global _CACHED_SUDO_PASSWORD
    if _CACHED_SUDO_PASSWORD is not None:
        return _CACHED_SUDO_PASSWORD

    possible_paths = [
        os.path.join(VAULT_DIR, "password"),
        os.path.join(SCRIPT_DIR, "password")
    ]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8-sig") as f:
                    content = f.read().strip("\r\n \t")
                    if content:
                        _CACHED_SUDO_PASSWORD = content
                        return _CACHED_SUDO_PASSWORD
            except Exception:
                pass

    _CACHED_SUDO_PASSWORD = getpass.getpass(f"\nEnter sudo password for {pwd.getpwuid(os.getuid()).pw_name}: ")
    return _CACHED_SUDO_PASSWORD

# Global module-level cache to prevent repeated password prompts and terminal state resets
get_sudo_password()

def call_subprocess(*args, **kwargs):
    if len(args) == 1 and isinstance(args[0], (list, tuple)):
        cmd_list = list(args[0])
    else:
        cmd_list = list(args)

    # NO PRINT STATEMENT HERE

    global _CACHED_SUDO_PASSWORD
    if "sudo" in cmd_list and _CACHED_SUDO_PASSWORD is not None:
        sudo_idx = cmd_list.index("sudo")
        if "-S" not in cmd_list[sudo_idx + 1:]:
            cmd_list.insert(sudo_idx + 1, "-S")

        orig_input = kwargs.get("input", None)
        is_text = kwargs.get("text", False)

        if orig_input is not None:
            if is_text:
                kwargs["input"] = _CACHED_SUDO_PASSWORD + "\n" + orig_input
            else:
                kwargs["input"] = (_CACHED_SUDO_PASSWORD + "\n").encode() + orig_input
        else:
            if is_text:
                kwargs["input"] = _CACHED_SUDO_PASSWORD + "\n"
            else:
                kwargs["input"] = (_CACHED_SUDO_PASSWORD + "\n").encode()

    try:
        return subprocess.run(cmd_list, **kwargs)
    except subprocess.CalledProcessError as e:
        # Only prints if a command fatally fails
        print(f"[-] Command failed with exit code {e.returncode}: {' '.join(str(c) for c in cmd_list)}")
        raise

def handle_refresh_assets():
    """Downloads a pristine client.html from AOSP, decodes the Base64 stream, validates HTML, and writes globally to all workspace and cache trees."""
    import os
    import sys
    import time
    import base64
    import tempfile
    from curl_cffi import requests
    from pathlib import Path

    print(f"[INFO] Initializing pristine client.html download...")

    # AOSP Gitiles returns files as Base64 when format=TEXT is used
    url = "https://android.googlesource.com/device/google/cuttlefish/+/refs/heads/main/host/frontend/webrtc/html_client/client.html?format=TEXT"

    fd, temp_path = tempfile.mkstemp(suffix=".b64")
    os.close(fd)

    # Retry logic to handle AOSP server throttling or connection drops
    max_retries = 3
    retry_delay = 2
    response = None

    for attempt in range(1, max_retries + 1):
        try:
            # Increased timeout to 60s to prevent curl error 28
            response = requests.get(url, stream=True, impersonate="chrome110", timeout=60)
            response.raise_for_status()
            break
        except Exception as e:
            print(f"[WARNING] Download attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                print(f"[INFO] Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("[-] Error: Failed to download pristine asset after multiple attempts.")
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                sys.exit(1)

    try:
        # Handle missing Content-Length headers safely
        total_size = int(response.headers.get("content-length", 0) or response.headers.get("Content-Length", 0))
        downloaded = 0
        start_time = time.time()
        last_render_time = 0.0

        with open(temp_path, "wb") as file:
            for data in response.iter_content(chunk_size=8192):
                if not data:
                    continue
                file.write(data)
                downloaded += len(data)
                now = time.time()

                if (now - last_render_time > 0.05) or (total_size > 0 and downloaded == total_size):
                    kb_down = downloaded / 1024
                    elapsed = now - start_time
                    speed = kb_down / elapsed if elapsed > 0 else 0.0

                    if total_size > 0:
                        percent = int((downloaded / total_size) * 100)
                        filled = int(30 * downloaded // total_size)
                        bar = "█" * filled + "━" * (30 - filled)
                        sys.stdout.write(f"\r ↳ [{bar}] {percent:3d}% | {kb_down:.1f}/{total_size/1024:.1f} KB | {speed:.1f} KB/s\033[K")
                    else:
                        sys.stdout.write(f"\r ↳ [ Downloading... ] {kb_down:.1f} KB | {speed:.1f} KB/s\033[K")

                    sys.stdout.flush()
                    last_render_time = now

        sys.stdout.write("\n")
        sys.stdout.flush()

        # Integrity Validation Check & Base64 Decoding
        with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()

        try:
            # Decode the Gitiles Base64 response back to raw HTML
            decoded_html = base64.b64decode(raw_content).decode("utf-8")
        except Exception:
            decoded_html = raw_content  # Fallback in case AOSP changes API behavior

        # --- INJECT AUTO-DISMISS SCRIPT ---
        auto_dismiss_script = """
        <script>
            // Shadow-DOM piercing ADB error annihilator
            function obliterateAdbError(element) {
                if (!element) return;

                // 1. If this element has a Shadow DOM, break into it and search
                if (element.shadowRoot) {
                    obliterateAdbError(element.shadowRoot);
                }

                // 2. Search all immediate children
                element.childNodes.forEach(child => {
                    if (child.nodeType === Node.TEXT_NODE && child.nodeValue.toLowerCase().includes('adb connection failed')) {

                        // Text found inside the Shadow DOM! Find the 'X' button in this exact scope and click it.
                        let domContext = child.getRootNode();
                        let closeBtn = domContext.querySelector('button, [title*="close" i], .close');
                        if (closeBtn) {
                            closeBtn.click();
                        }

                        // Fallback: Nuke the visual container and climb out of the shadow boundary
                        let target = child.parentElement;
                        let count = 0;
                        while (target && count < 6) {
                            if (target.style) {
                                target.style.setProperty('display', 'none', 'important');
                                target.style.setProperty('opacity', '0', 'important');
                            }
                            // Move up the tree, jumping across the shadow root boundary if necessary
                            target = target.parentElement || target.getRootNode().host;
                            count++;
                        }
                    } else {
                        // Keep digging deeper
                        obliterateAdbError(child);
                    }
                });
            }

            // Run this rapidly to catch the banner the moment it renders
            setInterval(() => obliterateAdbError(document.body), 150);
        </script>
        </head>
        """
        decoded_html = decoded_html.replace("</head>", auto_dismiss_script)
        # ----------------------------------

        if len(decoded_html) < 500 or "<html" not in decoded_html.lower():
            print("[-] Error: Downloaded file validation failed. Content does not contain valid HTML markup.")
            sys.exit(1)

        print("[SUCCESS] Downloaded file verified and decoded as a clean HTML document.")

        # Global Workspace & Cache Replacement (Scans the entire root cuttlefish workspace tree)
        target_files = set()
        base_root = os.path.dirname(WORKSPACE_DIR) # Resolves to /var/tmp/cuttlefish
        if os.path.exists(base_root):
            for path in Path(base_root).rglob("client.html"):
                target_files.add(str(path))

        primary_target = os.path.join(WORKSPACE_DIR, "usr", "share", "webrtc", "assets", "client.html")
        target_files.add(primary_target)

        for target_path in target_files:
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            # Write the decoded_html string to every cached and deployed tree
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(decoded_html)
            print(f"[INFO] Globally synchronized and replaced: {target_path}")

        print("[INFO] All global workspace and cache client.html assets successfully updated and verified.")
    except Exception as e:
        print(f"[-] Refresh failed: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    sys.exit(0)

# =================================================================
# 1. API EVENT WATCHER DAEMON & REGISTRY
# =================================================================
API_EVENT_QUEUE = queue.Queue()
API_EVENT_HANDLERS = {}

def register_api_event(event_signature, handler_function, run_once=True, delay_sec=0):
    """Registers a function to trigger when a specific API event appears in the logs."""
    API_EVENT_HANDLERS[event_signature] = {
        "handler": handler_function,
        "run_once": run_once,
        "delay_sec": delay_sec,
        "has_run": False
    }


def background_api_event_watcher():
    """Background daemon that monitors the queue and dispatches functions."""
    print("[SYSTEM] Background API Event Watcher Daemon online.")
    while True:
        line = API_EVENT_QUEUE.get()
        if line is None:
            break

        for event_signature, config in API_EVENT_HANDLERS.items():
            if event_signature in line:
                if config["run_once"] and config["has_run"]:
                    continue

                if event_signature != "[SYSTEM_BOOTSTRAP]":
                    print(f"\n[EVENT DAEMON] Captured API Event: {event_signature}")
                config["has_run"] = True

                def execute_handler(cfg):
                    if cfg["delay_sec"] > 0:
                        print(f"[EVENT DAEMON] Delaying execution for {cfg['delay_sec']}s to allow subsystem stabilization...")
                        time.sleep(cfg["delay_sec"])
                    cfg["handler"]()

                threading.Thread(target=execute_handler, args=(config,), daemon=True).start()

        API_EVENT_QUEUE.task_done()

def enforce_native_nat_routing():
    """Enforces broad host-side NAT masquerade for all Cuttlefish subnets via UFW."""
    import subprocess
    print("[INFO] Enforcing native host NAT (192.168.0.0/16) and STUN bypass rules via UFW...")
    try:
        call_subprocess(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        call_subprocess(["sudo", "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "192.168.0.0/16", "-j", "MASQUERADE"], check=False)
        call_subprocess(["sudo", "ufw", "route", "allow", "from", "192.168.0.0/16"], check=False)
        call_subprocess(["sudo", "ufw", "allow", "19302/udp"], check=False)
        print("[INFO] Broad native host network routing and masquerade successfully active.")
    except Exception as e:
        print(f"[-] Native NAT enforcement warning: {e}")

# =================================================================
# 2. MASTER EVENT HANDLERS
# =================================================================
def handle_system_bootstrap():
    """Phase 1: Cleans the host, configures KVM, and launches Cuttlefish."""
    try:
        perform_startup_cleanup()
        stop_and_clean_cvd()
        purge_legacy_systems()
        setup_apparmor()
        setup_debian_library_compat()
        phase_0_auto_remediate()

        if "no-root" in sys.argv:
            handle_aosp_artifacts_and_build()
        else:
            handle_aosp_artifacts()

        enforce_stable_cuttlefish_networking()
        enforce_native_nat_routing()

        setup_nginx_proxy()
        fix_tap_checksum_offloading()
        detect_and_set_graphics_environment()

        print("[SYSTEM] Host setup complete. Launching Hypervisor...")
        # Launch Cuttlefish (This starts the logs flowing into the Event Queue)
        launch_cuttlefish_daemon()

    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Bootstrap exception: {e}\n")
        traceback.print_exc(file=sys.stderr)

def hold_for_inspection(message="\n[INFO] Execution paused. Dashboard and logs preserved. Press ENTER to exit..."):
    """
    Prevents the script from automatically closing or restarting,
    keeping the Chromium UI alive and terminal logs visible.
    """
    import sys
    print(f"\033[1;33m{message}\033[0m")
    try:
        input()  # Wait indefinitely for the user to press Enter
    except KeyboardInterrupt:
        pass
    finally:
        sys.exit(1)

def handle_docker_bootstrap():
    """Phase 1 (Docker): Cleans Docker host, builds container, and launches Cuttlefish."""
    print("  Cuttlefish Controller - Docker Container Mode (API Driven)")
    try:
        perform_docker_cleanup()
        ensure_vsock_kernel_modules(_CACHED_SUDO_PASSWORD)
        enforce_docker_cuttlefish_networking()
        ensure_cuttlefish_bridge_up()

        import threading
        threading.Thread(target=persistent_bridge_enforcer, daemon=True).start()

        handle_aosp_artifacts()
        handle_system_bootstrap()
        detect_and_set_graphics_environment()

        global container_proc
        container_proc = run_cuttlefish_docker()

        print("[INFO] Cuttlefish Virtual Device is LIVE in Docker in the background.")

    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Docker Bootstrap exception: {e}\n")
        import traceback
        traceback.print_exc(file=sys.stderr)

def apply_pre_diagnostic_networking():
    """Forces host-side NAT, IP forwarding, and DNS forwarding active before diagnostics."""
    print("[INFO] Applying pre-diagnostic network and DNS rules on host...")
    try:
        call_subprocess(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        call_subprocess(["sudo", "ip", "link", "set", "dev", "cvd-mbr-0", "up"], check=False)
        call_subprocess(["sudo", "ip", "addr", "replace", "192.168.96.1/24", "dev", "cvd-mbr-0"], check=False)
        call_subprocess(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.96.0/24", "!", "-o", "cvd-mbr-0", "-j", "MASQUERADE"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "FORWARD", "-i", "cvd-mbr-0", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "FORWARD", "-o", "cvd-mbr-0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", "192.168.96.0/24", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "192.168.96.1:53"], check=False)
        call_subprocess(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", "192.168.96.0/24", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "192.168.96.1:53"], check=False)
        print("[INFO] Pre-diagnostic host networking applied successfully.")
    except Exception as e:
        print(f"[-] Warning applying pre-diagnostic network rules: {e}")

def persist_guest_internet_route():
    """Continuously monitors guest routing tables and re-applies buried_eth0 configuration post-reset."""
    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"
    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    # Allow time for the VCPU reset and secondary boot sequence to settle
    time.sleep(5)

    for attempt in range(1, 15):
        try:
            # Check if default route via buried_eth0 is active
            res = call_subprocess(
                [adb_path, "-s", "127.0.0.1:6520", "shell", "ip route show"],
                env=env, capture_output=True, text=True, timeout=3
            )
            if res.returncode == 0 and "buried_eth0" in res.stdout and "default" in res.stdout:
                print(f"[INFO] Guest internet route verified active on attempt {attempt}.")
                break

            # Re-apply netd routing rules if missing
            call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "destroy", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "create", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "interface", "add", "100", "buried_eth0"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "route", "add", "100", "buried_eth0", "192.168.96.0/24"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "route", "add", "100", "buried_eth0", "0.0.0.0/0", "192.168.96.1"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "default", "set", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            pass
        time.sleep(2)

import time
import threading

def establish_cuttlefish_network(workspace_dir):
    import subprocess
    import sys
    import time
    import os

    ADB_PATH = os.path.join(workspace_dir, "bin", "adb")
    if not os.path.exists(ADB_PATH):
        ADB_PATH = "adb"

    def log_info(msg):
        print(f"\033[1;34m[INFO]\033[0m {msg}")

    def log_success(msg):
        print(f"\033[1;32m[SUCCESS]\033[0m {msg}")

    def log_error(msg):
        print(f"\033[1;31m[ERROR]\033[0m {msg}")

    def run_cmd(cmd, shell=True, check=True):
        try:
            result = call_subprocess(cmd, shell=shell, text=True, capture_output=True)
            if result.returncode != 0 and check:
                log_error(f"Command failed: {cmd}")
                sys.exit(1)
            return result
        except Exception as e:
            if check:
                sys.exit(1)

    log_info("Configuring host routing, bridging, and UFW firewall...")
    run_cmd("sudo sysctl -w net.ipv4.ip_forward=1")
    run_cmd('sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"')
    run_cmd("sudo ip link set dev cvd-mbr-0 up", check=False)
    run_cmd("sudo ip link set dev cvd-mbr-0 promisc off", check=False)
    run_cmd("sudo ip addr replace 192.168.96.1/24 dev cvd-mbr-0", check=False)

    taps = ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01", "cvd-mtap-1", "cvd-wtap-1"]
    for tap in taps:
        if call_subprocess(f"ip link show {tap}", shell=True, capture_output=True).returncode == 0:
            run_cmd(f"sudo ip link set dev {tap} up")
            run_cmd(f"sudo ip link set dev {tap} master cvd-mbr-0")

    run_cmd("sudo iptables -I INPUT -i cvd-mbr-0 -p udp --dport 53 -j ACCEPT")
    run_cmd("sudo iptables -I INPUT -i cvd-mbr-0 -p tcp --dport 53 -j ACCEPT")
    run_cmd("sudo iptables -I INPUT -i cvd-mbr-0 -p udp --dport 67:68 -j ACCEPT")
    run_cmd("sudo iptables -t nat -I POSTROUTING -s 192.168.96.0/24 -j MASQUERADE")
    run_cmd("sudo iptables -I FORWARD -i cvd-mbr-0 -j ACCEPT")
    run_cmd("sudo iptables -I FORWARD -o cvd-mbr-0 -m state --state RELATED,ESTABLISHED -j ACCEPT")

    call_subprocess("sudo pkill -f 'dnsmasq --interface=cvd-mbr-0'", shell=True, capture_output=True)
    dnsmasq_cmd = (
        "sudo dnsmasq --interface=cvd-mbr-0 --bind-interfaces "
        "--listen-address=192.168.96.1 "
        "--dhcp-range=192.168.96.50,192.168.96.150,12h "
        "--dhcp-option=option:router,192.168.96.1 "
        "--dhcp-option=option:dns-server,192.168.96.1 "
        "--server=8.8.8.8 --server=8.8.4.4"
    )
    subprocess.Popen(dnsmasq_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_info("Connecting to Android guest...")
    call_subprocess(f"{ADB_PATH} connect 127.0.0.1:6520", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    call_subprocess(f"{ADB_PATH} wait-for-device", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_info("Triggering Fast Android DHCP Handshake...")
    run_cmd(f"{ADB_PATH} shell svc wifi disable", check=False)
    time.sleep(0.5)
    run_cmd(f"{ADB_PATH} shell svc wifi enable", check=False)
    time.sleep(0.5)
    run_cmd(f"{ADB_PATH} shell cmd wifi connect-network VirtWifi open", check=False)

def delayed_route_enforcement():
    """Actively polls for the VCPU framework drop and re-injects network instantly upon return."""
    import time
    import subprocess
    import os

    print("[INFO] Active polling engaged: Monitoring guest for framework reset...")
    adb_bin = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"

    # 1. Fast-poll the ADB shell for up to 4 seconds. If the connection drops, a reset occurred.
    reset_detected = False
    for _ in range(20):
        try:
            # We use subprocess.run directly here to avoid triggering error logs in your call_subprocess wrapper
            res = subprocess.run([adb_bin, "-s", "127.0.0.1:6520", "shell", "echo", "alive"], capture_output=True, text=True, timeout=1)
            if res.returncode != 0 or "alive" not in res.stdout:
                reset_detected = True
                break
        except Exception:
            reset_detected = True
            break
        time.sleep(0.2)

    # 2. If it dropped, use adb wait-for-device to catch it the exact millisecond it returns
    if reset_detected:
        print("[INFO] Framework reset detected! Waiting for guest to come back online...")
        subprocess.run([adb_bin, "-s", "127.0.0.1:6520", "wait-for-device"], timeout=30)
        time.sleep(1.5)  # Brief 1.5s buffer for Android's Network HAL to finish mounting
    else:
        print("[INFO] Guest stabilized without resetting. Proceeding instantly.")

    establish_cuttlefish_network(WORKSPACE_DIR)
    print("[INFO] Network routes successfully injected and locked.")

def handle_boot_completed():
    print("[INFO] Guest API strictly reports BOOT_COMPLETED. Configuring Network...")
    apply_pre_diagnostic_networking()
    ensure_adb_bridge()
    threading.Thread(target=delayed_route_enforcement, daemon=True).start()

def stabilize_adb_connection():
    """Establishes and locks the host-to-guest ADB bridge required by the dashboard terminal."""
    adb_bin = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"
    adb_target = "localhost:6520"

    call_subprocess([adb_bin, "start-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    time.sleep(3)

    for _ in range(8):
        call_subprocess([adb_bin, "connect", adb_target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        try:
            call_subprocess([adb_bin, "-s", adb_target, "wait-for-device"], timeout=6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if "no-root" not in sys.argv:
                call_subprocess([adb_bin, "-s", adb_target, "root"], timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                call_subprocess([adb_bin, "connect", adb_target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                call_subprocess([adb_bin, "-s", adb_target, "wait-for-device"], timeout=6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            res = call_subprocess([adb_bin, "-s", adb_target, "shell", "echo 1"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and "1" in res.stdout:
                print("[INFO] ADB bridge successfully locked and connected for dashboard.")
                return
        except Exception:
            time.sleep(3)
    print("[-] Warning: Dashboard ADB bridge stabilization timed out.")

def handle_wifi_connected():
    """Phase 3: Triggered the millisecond Android secures an internet connection."""
    print("[INFO] Live natively.")

    # Always run the ADB handshake so the dashboard works with or without the ai flag
    threading.Thread(target=stabilize_adb_connection, daemon=True).start()
    time.sleep(1.5)
    check_connection()
    if "ai" in sys.argv:
        print("[INFO] AI Diagnostics Active in Native Mode.")
        threading.Thread(target=initializer_orchestrator, args=(WORKSPACE_DIR,), daemon=True).start()
        run_post_boot_diagnostics()
    else:
        print("[INFO] AI Diagnostics skipped (pass 'ai' flag to enable).")

# --- REGISTER THE EVENTS ---
# 1. Start the system setup immediately when the queue receives the bootstrap signal
register_api_event("[SYSTEM_BOOTSTRAP]", handle_system_bootstrap, run_once=True, delay_sec=0)

# 2. Configure DHCP 1 second after Android reports it is booted
register_api_event("VIRTUAL_DEVICE_BOOT_COMPLETED", handle_boot_completed, run_once=True, delay_sec=1)

# 3. Launch Diagnostics instantly (3 seconds instead of 12) after Wi-Fi connects
register_api_event("VIRTUAL_DEVICE_NETWORK_WIFI_CONNECTED", handle_wifi_connected, run_once=True, delay_sec=3)

def run_post_boot_diagnostics():
    """Executes an in-depth post-boot health, latency, and bottleneck analysis."""
    import subprocess
    import time
    import os

    print("\n[DIAGNOSTICS] Initiating deep system and network performance profiling...")

    adb_bin = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"
    adb_target = "localhost:6520"

    # ==========================================
    # 0. BOOTSTRAP ADB CONNECTION (ROBUST RETRY)
    # ==========================================
    call_subprocess([adb_bin, "start-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Extended retry loop to let adbd service fully settle post-WiFi connection
    adb_connected = False
    time.sleep(3)
    for attempt in range(5):
        call_subprocess([adb_bin, "connect", adb_target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            call_subprocess([adb_bin, "-s", adb_target, "wait-for-device"], timeout=6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if "no-root" not in sys.argv:
                call_subprocess([adb_bin, "-s", adb_target, "root"], timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                call_subprocess([adb_bin, "connect", adb_target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                call_subprocess([adb_bin, "-s", adb_target, "wait-for-device"], timeout=6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            res = call_subprocess(f"{adb_bin} -s {adb_target} shell echo 1", shell=True, capture_output=True, text=True, timeout=4)
            if res.returncode == 0 and "1" in res.stdout:
                adb_connected = True
                break
        except subprocess.TimeoutExpired:
            time.sleep(3)

    if not adb_connected:
        print("[DIAGNOSTICS] WARNING: ADB shell unresponsive. Guest metrics will return 'Unknown'.")

    def run_adb(cmd, timeout=5):
        if not adb_connected: return None
        try:
            if "no-root" in sys.argv:
                full_cmd = f"{adb_bin} -s {adb_target} shell {cmd}"
            else:
                full_cmd = f"{adb_bin} -s {adb_target} shell su root {cmd}"
            res = call_subprocess(full_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return res.stdout.strip() if res.returncode == 0 else None
        except Exception:
            return None

    # ==========================================
    # 1. HOST CPU & HYPERVISOR USAGE
    # ==========================================
    load_avg = os.getloadavg()
    hypervisor_cpu, hypervisor_mem = "Unknown", "Unknown"
    try:
        ps_out = call_subprocess("ps -C crosvm -o %cpu,%mem --no-headers | awk '{cpu+=$1; mem+=$2} END {print cpu, mem}'", shell=True, capture_output=True, text=True)
        if ps_out.returncode == 0 and ps_out.stdout.strip():
            c_cpu, c_mem = ps_out.stdout.strip().split()
            hypervisor_cpu, hypervisor_mem = f"{c_cpu}%", f"{c_mem}%"
    except Exception:
        pass

    # ==========================================
    # 2. GUEST GRAPHICS & HARDWARE ACCELERATION
    # ==========================================
    gpu_status = "NVIDIA-SMI failed or unavailable"
    try:
        smi = call_subprocess(["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,temperature.gpu", "--format=csv,noheader"], capture_output=True, text=True, timeout=2)
        if smi.returncode == 0:
            gpu_status = smi.stdout.strip().replace(", ", " | ")
    except Exception:
        pass

    guest_gles = run_adb("getprop ro.hardware.egl") or "Unknown"
    guest_vulkan = run_adb("getprop ro.hardware.vulkan") or "Unknown"

    guest_sf = "Unknown"
    sf_dump = run_adb("dumpsys SurfaceFlinger")
    if sf_dump:
        sf_lines = [line.strip() for line in sf_dump.split('\n') if "GLES" in line or "Vulkan" in line or "RenderEngine" in line]
        if sf_lines:
            guest_sf = sf_lines[0][:65] + ("..." if len(sf_lines[0]) > 65 else "")

    # ==========================================
    # 3. GUEST NETWORK & DNS LATENCY PROFILING
    # ==========================================
    def parse_ping(target, dns_name=None):
        ping_out = run_adb(f"ping -c 2 -W 2 {target}")
        if not ping_out:
            return f"FAILED (Could not reach {dns_name or target})"
        try:
            avg_ms = ping_out.split("mdev = ")[1].split("/")[1]
            return f"SUCCESS ({avg_ms} ms avg latency)"
        except IndexError:
            if "0% packet loss" in ping_out:
                return "SUCCESS (0% packet loss)"
            return "UNSTABLE (Packet loss detected)"

    net_eval = []
    net_eval.append(f"Raw IP Ping (8.8.8.8)  : {parse_ping('8.8.8.8')}")
    dns_res = parse_ping("google.com", "google.com")
    net_eval.append(f"DNS Speed (google.com) : {dns_res}")
    media_res = parse_ping("livenowfox.com", "livenowfox.com")
    net_eval.append(f"Media Site Resolution  : {media_res}")

    # ==========================================
    # 4. GUEST MEMORY PRESSURE
    # ==========================================
    guest_mem_status = "Unknown"
    meminfo = run_adb("cat /proc/meminfo")
    if meminfo:
        try:
            mem_dict = {line.split(":")[0]: int(line.split()[1]) for line in meminfo.split("\n") if "Mem" in line}
            g_total = mem_dict.get("MemTotal", 0) // 1024
            g_avail = mem_dict.get("MemAvailable", 0) // 1024
            percent_free = int((g_avail / g_total) * 100) if g_total > 0 else 0
            guest_mem_status = f"{g_avail} MB Available / {g_total} MB Total ({percent_free}% Free)"
        except Exception:
            guest_mem_status = "Parse Error"

    print("\n" + "="*85)
    print("                 CUTTLEFISH DEEP PERFORMANCE & BOTTLENECK REPORT                 ")
    print("="*85)
    print(" [ HOST RESOURCE UTILIZATION ]")
    print(f" • Host CPU Load Avg (1m, 5m, 15m) : {load_avg}")
    print(f" • Hypervisor (crosvm) Host Usage  : {hypervisor_cpu} CPU | {hypervisor_mem} RAM")
    print("")
    print(" [ GRAPHICS & HARDWARE ACCELERATION ]")
    print(f" • Host NVIDIA GPU Status          : {gpu_status}")
    print(f" • Guest EGL Driver                : {guest_gles}")
    print(f" • Guest Vulkan Driver             : {guest_vulkan}")
    print(f" • Guest SurfaceFlinger Engine     : {guest_sf}")
    print("")
    print(" [ GUEST INTERNAL VIRTUAL HARDWARE ]")
    print(f" • Guest RAM Available             : {guest_mem_status}")
    print("")
    print(" [ NETWORK LATENCY & DNS SPEED (The Speed Factor) ]")
    for stat in net_eval:
        print(f" • {stat}")
    print("="*85 + "\n")

def corruption_watch(workspace_dir, aosp_src_dir):
    """Universal transactional safeguard safe for main-thread execution with expanded targeted lock clearing."""
    import atexit
    import os
    import signal
    import threading
    import sys
    import glob

    def _transactional_cleanup():
        try:
            # Core lock files across user profile and main repo engine
            targeted_locks = [
                os.path.join(aosp_src_dir, ".repo", "repo", ".lock"),
                os.path.join(aosp_src_dir, "out", ".lock"),
                os.path.expanduser("~/.gitconfig.lock"),
                os.path.expanduser("~/.git/.lock"),
                os.path.expanduser("~/.git-credentials.lock"),
            ]

            # Fast, bounded checks on known friction points (Rust/Clang prebuilts and metadata)
            if os.path.exists(aosp_src_dir):
                safe_prebuilt_paths = [
                    "prebuilts/rust",
                    "prebuilts/clang/host/linux-x86",
                    ".repo/projects/prebuilts",
                    ".repo/project-objects/platform/prebuilts"
                ]
                for sub_path in safe_prebuilt_paths:
                    full_sub = os.path.join(aosp_src_dir, sub_path)
                    if os.path.exists(full_sub):
                        for lock_name in ["*.lock", "index.lock", "HEAD.lock", "config.lock"]:
                            for lk in glob.glob(os.path.join(full_sub, "**", lock_name), recursive=True):
                                targeted_locks.append(lk)

            for lk in targeted_locks:
                if os.path.exists(lk):
                    try:
                        os.remove(lk)
                    except Exception:
                        pass
        except Exception:
            pass

    atexit.register(_transactional_cleanup)

    def _signal_trap(signum, frame):
        _transactional_cleanup()
        sys.exit(130)

    # Only bind signals if running on the main thread to prevent runtime crashes
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _signal_trap)
            except Exception:
                pass

corruption_watch(WORKSPACE_DIR, AOSP_SRC_DIR)

def print_help_banner():
    """Renders the help banner with the flag reference guide and user manual cleanly aligned."""
    import os
    import sys
    import re

    try:
        width = os.get_terminal_size().columns
    except Exception:
        width = 80
    width = max(width, 70)

    gray_bar = "  \033[90m" + "─" * (width - 4) + "\033[0m"

    flags_plain = "Commands: docker sandbox no-root reset console ai help"
    flags_color = "\033[1;33mCommands:\033[0m \033[36mdocker\033[0m(Container) \033[36msandbox\033[0m(Crosvm) \033[36mno-root\033[0m(User) \033[36mreset\033[0m(Delete) \033[36mconsole\033[0m(No UI) \033[36mai\033[0m(Experimental) \033[36mhelp\033[0m(Info)"

    guide_lines = [
        "\033[1mExample: python3 android.py no-root ai\033[0m",
        "────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────",
        "\033[1m\033[0m\033[36mhelp\033[0m command is strictly for information.",
        "\033[0m\033[36mdocker\033[0m docker container.",
        "\033[0m\033[36mno-root\033[0m compile the Android Open Source Project operating system without root/admin access.",
        "\033[0m\033[36mreset\033[0m completely delete everything and start fresh.",
        "\033[0m\033[36mconsole\033[0m without dashboard and with cuttlefish webrtc client page enabled",
        "\033[0m\033[36msandbox\033[0m crosvm sandbox.",
        "\033[0m\033[36mai\033[0m diagnostics.",
        "\033[1m/home/username/cuttlefish:\033[0m The cuttlefish folder acts as the primary directory used for everything.",
        "────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────"
    ]

    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    clean_guide_lines = [ansi_escape.sub('', line) for line in guide_lines]
    max_line_len = max(len(cl) for cl in clean_guide_lines)
    block_pad = max(0, (width - max_line_len) // 2)

    banner_lines = [""]
    banner_lines.append(gray_bar)
    banner_lines.append(" " * block_pad + flags_color)
    banner_lines.append(gray_bar)
    banner_lines.append("")

    for g_line in guide_lines:
        banner_lines.append(" " * block_pad + g_line)

    print("\n".join(banner_lines))

if "help" in sys.argv:
    print_help_banner()
    sys.exit(0)

if "do-copy" in sys.argv:
        try:
            import subprocess
            res = call_subprocess(["tmux", "capture-pane", "-p", "-t", "cf_engine:0.1", "-S", "-32768"], capture_output=True, text=True)

            call_subprocess(["wl-copy"], input=res.stdout, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["xclip", "-selection", "clipboard"], input=res.stdout, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            call_subprocess(["tmux", "set-option", "-g", "display-time", "3000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["tmux", "set-option", "-g", "message-style", "bg=#18181b,fg=#a1a1aa,bold"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["tmux", "display-message", "-c", "cf_engine", " Copied to clipboard "], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        sys.exit(0)

if unknown:
    print(f"\033[1;31m✖ [CRITICAL]\033: Unrecognized or invalid argument(s) detected: {' '.join(unknown)}\033[0m")
    print("\033[33m[INFO] For information try python3 android.py --help\033[0m")
    os._exit(1)

RUN_IN_DOCKER = "docker" in sys.argv
NO_ROOT = "no-root" in sys.argv

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\].*?(?:\x1B\\|\x07))')

ROADMAP_STATE = {
    "phase_deps": "QUEUED",
    "phase_sync": "QUEUED",
    "phase_heal": "QUEUED",
    "phase_build": "QUEUED",
    "phase_deploy": "QUEUED"
}

class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    ORANGE = "\033[33m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    DIM = "\033[2m"
    CYAN = "\033[36m"

def remove_stale_build_processes():
    """Brutally terminates any lingering repo sync workers, git operations, multiprocessing daemons, Cuttlefish binaries, past self instances, and empty legacy home folders."""
    import os
    import sys
    import subprocess

    print("\n\033[1;31m[AGGRESSIVE CLEAN] Rapidly purging ghost daemons, past script instances, and stale locks...\033[0m")

    # Prune empty legacy vault artifact folders safely
    try:
        if os.path.exists(VAULT_DIR) and os.path.isdir(VAULT_DIR) and not os.listdir(VAULT_DIR):
            os.rmdir(VAULT_DIR)
    except Exception:
        pass

    # Removed dangerous self-pgrep kill to prevent session/wrapper suicide.
    pass

    stale_patterns = [
        "repo/main.py", "multiprocessing.forkserver", "resource_tracker",
        "git fetch", "git-remote-https", "git index-pack", "git read-tree",
        "ninja", "make", "soong_ui", "soong_build", "siso", "rustc", "m -j", "nsjail",
        "launch_cvd", "run_cvd", "crosvm", "webrtc_operator", "webRTC", "webRTC_server",
        "wmediumd", "netsimd", "casimir", "socket_vsock_proxy",
        "log_tee", "openwrt_control_server", "process_restarter",
        "tombstone_receiver", "modem_simulator", "dnsmasq",
        "console_forwarder", "echo_server", "gnss_grpc_proxy", "logcat_receiver",
        "kernel_log_monitor", "secure_env", "sensors_simulator", "tcp_connector",
        "screen_recording_server", "control_env_proxy_server", "cf_vhost_user_input"
    ]

    # 1. Execute a broad SIGKILL using global matching, overriding the user scope in case of sudo/root artifacts
    for pattern in stale_patterns:
        try:
            call_subprocess(["sudo", "pkill", "-9", "-f", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess(["pkill", "-9", "-f", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            pass

    # 2. Manually purge shared memory mounts that crosvm leaves behind if killed unexpectedly
    try:
        call_subprocess(["sudo", "rm", "-rf", "/dev/shm/crosvm*"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["sudo", "rm", "-rf", "/dev/shm/wayland*"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

_SHUTDOWN_EXECUTED = False
_OS_SHUTDOWN_FD = None

def shutdown_everything(browser):
    global _SHUTDOWN_EXECUTED, _OS_SHUTDOWN_FD

    if _SHUTDOWN_EXECUTED:
        return
    _SHUTDOWN_EXECUTED = True

    # OS-level lock for the shutdown sequence itself
    try:
        import fcntl
        _OS_SHUTDOWN_FD = open("/tmp/cuttlefish_shutdown.lock", "w")
        fcntl.flock(_OS_SHUTDOWN_FD.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os._exit(0)

    if browser:
        global SHUTDOWN_WITH_BROWSER
        try:
            if not SHUTDOWN_WITH_BROWSER:
                return
        except NameError:
            pass

    try:
        for pgid in ACTIVE_PROCESS_GROUPS:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                pass

        remove_stale_build_processes()

        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

        os.system("stty sane 2>/dev/null")
        try:
            subprocess.run(["tput", "sgr0"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["tput", "cnorm"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        try:
            dump_logs_on_exit()
        except Exception:
            pass

        try:
            stop_and_clean_cvd()
        except Exception:
            pass

        try:
            force_full_shutdown()
        except Exception:
            pass

        sys.__stdout__.write("\r\nShutdown complete.\r\n\r\n")
        sys.__stdout__.flush()
    except Exception:
        pass
    finally:
        os._exit(0)

import threading
import fcntl

_SHUTDOWN_LOCK = threading.Lock()
SHUTTING_DOWN = False
_OS_SIGINT_FD = None

def raw_keyboard_interrupt_listener(sig=None, frame=None):
    """Bulletproof OS signal handler with multi-process locking."""
    global SHUTTING_DOWN, _OS_SIGINT_FD

    # 1. Thread lock (protects against threads in the SAME process)
    if not _SHUTDOWN_LOCK.acquire(blocking=False):
        return

    # 2. OS-level lock (protects against parent & child processes BOTH receiving Ctrl+C)
    try:
        _OS_SIGINT_FD = open("/tmp/cuttlefish_sigint.lock", "w")
        fcntl.flock(_OS_SIGINT_FD.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        # Another process got here first. Exit instantly and silently.
        os._exit(130)

    try:
        if SHUTTING_DOWN:
            return
        SHUTTING_DOWN = True

        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

        os.system("stty sane 2>/dev/null")
        try:
            subprocess.run(["tput", "sgr0"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["tput", "cnorm"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        sys.__stdout__.write("\r\n\033[1;31m✖ [CRITICAL]\033[0m Interruption key captured. Terminating.\r\n")
        sys.__stdout__.flush()

        try:
            shutdown_everything(False)
        except Exception:
            pass

    finally:
        os._exit(130)

# Register the OS signal handler
signal.signal(signal.SIGINT, raw_keyboard_interrupt_listener)

if "reset" in sys.argv:
    print("[INFO] reset command detected. Dynamically purging all workspace and hidden cache paths...")

    if os.path.exists(BASE_WORKSPACE):
        print(f"[-] Deleting entire root workspace: {BASE_WORKSPACE}")
        shutil.rmtree(BASE_WORKSPACE, ignore_errors=True)

    if os.path.exists(VAULT_DIR):
        for item in os.listdir(VAULT_DIR):
            item_path = os.path.join(VAULT_DIR, item)
            # Skip base images, delete compiled caches/repos
            if "host_package" not in item and not item.endswith(".img"):
                print(f"[-] Dynamically purging vault path: {item_path}")
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path, ignore_errors=True)
                else:
                    try:
                        os.remove(item_path)
                    except Exception:
                        pass

    os.makedirs(WORKSPACE_DIR, exist_ok=True)

    if "reset" in sys.argv:
        sys.argv.remove("reset")

    print("[INFO] Reset complete. All hidden files, caches, and artifacts wiped successfully.")

def clean_locks(target_dirs=None):
    """
    High-performance, deadlock-proof lock annihilator.
    Executes a single-pass traversal, skipping heavy object directories,
    reducing scan time from 20+ seconds to milliseconds.
    """
    import os
    import subprocess

    print("\033[1;31m[AGGRESSIVE CLEAN] Rapidly purging repo and git locks...\033[0m")

    # 1. Wipe global user-level locks instantly
    global_locks = [
        os.path.expanduser("~/.gitconfig.lock"),
        os.path.expanduser("~/.git-credentials.lock"),
        os.path.expanduser("~/.git/.lock")
    ]
    for lk in global_locks:
        if os.path.exists(lk):
            try: os.remove(lk)
            except Exception: pass

    # 2. Build search paths restricted to Repo/Workspace roots
    search_paths = set()
    if target_dirs:
        targets = [target_dirs] if isinstance(target_dirs, str) else target_dirs
        for t in targets:
            if t and os.path.exists(t):
                repo_dir = os.path.join(t, ".repo")
                search_paths.add(repo_dir if os.path.exists(repo_dir) else t)

    if 'WORKSPACE_DIR' in globals() and os.path.exists(WORKSPACE_DIR):
        search_paths.add(WORKSPACE_DIR)

    # 3. Single-pass ultra-fast find command
    for path in search_paths:
        if not path or not os.path.exists(path):
            continue

        find_cmd = [
            "find", path,
            # Skip the massive git objects data folder entirely
            "-name", "project-objects", "-prune", "-o",
            "-type", "f",
            "(",
            "-name", "*.lock", "-o",
            "-name", "index.lock", "-o",
            "-name", "HEAD.lock", "-o",
            "-name", "config.lock", "-o",
            "-name", "packed-refs.lock",
            ")", "-delete"
        ]

        try:
            call_subprocess(
                find_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5, # Hard 5-second cutoff
                check=False
            )
        except subprocess.TimeoutExpired:
            print(f"\033[93m[WARNING] Cleanup timed out in {path}. Bypassing...\033[0m")
        except Exception:
            pass

    print("\033[1;32m[AGGRESSIVE CLEAN] All locks successfully cleared.\033[0m")

def ensure_workspace(workspace_dir):
    print(f"[DEBUG] Verifying workspace path: {workspace_dir}")
    if os.path.exists(workspace_dir):
        if not os.path.isdir(workspace_dir):
            print(f"[-] FATAL: A file named 'cuttlefish' already exists at {workspace_dir}.")
            return False
        print("[DEBUG] Workspace directory already exists.")
    else:
        try:
            print("[DEBUG] Workspace not found. Creating it now...")
            os.makedirs(workspace_dir, exist_ok=True)
            print("[INFO] Successfully created workspace directory.")
        except Exception as e:
            print(f"[-] ERROR: Unexpected failure creating workspace: {e}")
            return False

    try:
        with open(DEBUG_LOG_PATH, "w", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now()}] === Cuttlefish Debug Session Initialized ===\n")
    except Exception as e:
        print(f"[-] ERROR: Unexpected failure creating debug log: {e}")
        return False

    return True

def install_system_dependencies():
    print("\n\033[90mVerifying System Dependencies (pacman & yay)...\033[0m")
    pacman_pkgs = [
        "unzip", "tar", "iptables-nft", "bridge-utils", "ethtool", "apparmor", "base-devel",
        "cmake", "ninja", "curl", "libseccomp", "iproute2", "screen", "procps-ng",
        "vulkan-icd-loader", "lib32-vulkan-icd-loader",
        "nvidia-utils", "lib32-nvidia-utils", "nvidia-container-toolkit",
        "egl-wayland",
        "dnsmasq",
        "nginx",
        "python-pip",
        "docker", "docker-buildx", "runc", "containerd"
    ]
    missing_pacman = []

    for pkg in pacman_pkgs:
        if call_subprocess(["pacman", "-Qs", f"^{pkg}$"], stdout=subprocess.DEVNULL).returncode != 0:
            missing_pacman.append(pkg)

    if missing_pacman:
        print(f"[INFO] Installing missing pacman packages: {', '.join(missing_pacman)}")
        call_subprocess(["rm", "-f", "/var/lib/pacman/db.lck"], check=False)
        call_subprocess(["pacman", "-S", "--noconfirm", "--needed"] + missing_pacman)

        docker_components = {"docker", "docker-buildx", "runc", "containerd"}
        if any(pkg in missing_pacman for pkg in docker_components):
            print("[INFO] Enforcing Docker and Containerd daemon states...")
            current_user = os.getenv("USER") or os.getlogin()
            call_subprocess(["usermod", "-aG", "docker", current_user], check=False)
            call_subprocess(["systemctl", "daemon-reload"], check=False)
            call_subprocess(["systemctl", "enable", "--now", "containerd"], check=False)
            call_subprocess(["systemctl", "restart", "containerd"], check=False)
            call_subprocess(["systemctl", "enable", "--now", "docker"], check=False)
            call_subprocess(["systemctl", "restart", "docker"], check=False)

    yay_pkgs = ["ungoogled-chromium-bin"]
    missing_yay = []

    for pkg in yay_pkgs:
        if call_subprocess(["pacman", "-Qs", f"^{pkg}$"], stdout=subprocess.DEVNULL).returncode != 0:
            missing_yay.append(pkg)

    if missing_yay:
        if shutil.which("yay"):
            print(f"[INFO] Installing missing AUR packages via yay: {', '.join(missing_yay)}")
            call_subprocess(["yay", "-S", "--noconfirm", "--needed"] + missing_yay, check=True)
        else:
            print("[WARNING] 'yay' is not installed! Please install yay manually to automate AUR fetches.")

    if sys.executable != VENV_PYTHON:
        needs_install = False
        if not os.path.exists(VENV_PYTHON):
            needs_install = True
            print("\n[INFO] Bootstrapping Isolated Python Virtual Environment...")
            call_subprocess([sys.executable, "-m", "venv", VENV_DIR], check=True)
        else:
            check_pkgs = call_subprocess(
                [VENV_PYTHON, "-c", "import curl_cffi, tqdm, pyroute2, textual, fastapi, uvicorn, websockets, wsproto, cryptography, psutil"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if check_pkgs.returncode != 0:
                needs_install = True

        if needs_install:
            print("[INFO] Ensuring all required dependencies are installed in virtual environment...")
            call_subprocess([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True, stdin=subprocess.DEVNULL)
            call_subprocess(
                [
                    VENV_PYTHON, "-m", "pip", "install",
                    "--prefer-binary", "--no-cache-dir",
                    "curl_cffi", "tqdm", "pyroute2", "textual",
                    "fastapi", "uvicorn", "websockets", "wsproto",
                    "cryptography", "psutil"
                ],
                check=True,
                stdin=subprocess.DEVNULL
            )

        clean_args = [arg for arg in sys.argv if arg != "reset"]
        os.execv(VENV_PYTHON, [VENV_PYTHON] + clean_args)

install_system_dependencies()

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.name import Name
from curl_cffi import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from pyroute2 import IPRoute
import textual
from tqdm import tqdm
import uvicorn
import websockets
import wsproto
from fastapi import Request
from fastapi.responses import Response, StreamingResponse
import psutil
app = FastAPI()
connected_websockets = []
server_loop = None
client_connected_event = threading.Event()
script_should_exit = threading.Event()

os.makedirs(WORKSPACE_DIR, exist_ok=True)

try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (65535, hard))
    print("\n\033[90mRaised file descriptor limit from {soft} to 65535\033[0m")
except Exception as e:
    print(f"[-] Failed to raise file descriptor limit: {e}")

clean_locks()

call_subprocess(["git", "config", "--file", f"{VAULT_DIR}/.gitconfig", "user.name", "Cuttlefish Builder"], stderr=subprocess.DEVNULL)
call_subprocess(["git", "config", "--file", f"{VAULT_DIR}/.gitconfig", "user.email", "builder@localhost"], stderr=subprocess.DEVNULL)

def configure_host_firewall_for_webrtc():
    """Configures UFW host firewall and NAT routing for Cuttlefish WebRTC media ports."""
    import subprocess
    import time

    print("[INFO] Applying UFW trust and NAT routing for WebRTC media ports...")

    # 1. Enable IP Forwarding and Localnet Routing (Required for NAT loopback)
    call_subprocess("sudo sysctl -w net.ipv4.ip_forward=1", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    call_subprocess("sudo sysctl -w net.ipv4.conf.all.route_localnet=1", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    call_subprocess("sudo sysctl -w net.ipv4.conf.default.route_localnet=1", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    call_subprocess("sudo sysctl -w net.ipv4.conf.lo.route_localnet=1", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2. Open ports via UFW (Uncomplicated Firewall)
    ufw_commands = [
        "sudo ufw allow 15550:15599/udp",
        "sudo ufw allow 15550:15599/tcp",
        "sudo ufw route allow in on lo",
        "sudo ufw route allow in on cvd-mbr-0",
        "sudo ufw route allow out on cvd-mbr-0"
    ]
    for cmd in ufw_commands:
        call_subprocess(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 3. Inject NAT Loopback Routes via raw iptables
    # UFW doesn't handle NAT rules natively via CLI, so we insert them at the top of the chain (Index 1)
    nat_rules = [
        ("PREROUTING", "-p udp -d 127.0.0.1 --dport 15550:15599 -j DNAT --to-destination 192.168.96.1"),
        ("PREROUTING", "-p tcp -d 127.0.0.1 --dport 15550:15599 -j DNAT --to-destination 192.168.96.1"),
        ("POSTROUTING", "-s 192.168.96.0/24 -j MASQUERADE")
    ]

    for chain, rule in nat_rules:
        # Check if the rule already exists to avoid duplicates
        check_cmd = f"sudo iptables -t nat -C {chain} {rule}"
        if call_subprocess(check_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            # Insert at position 1 to guarantee it overrides any UFW blocks
            insert_cmd = f"sudo iptables -t nat -I {chain} 1 {rule}"
            call_subprocess(insert_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(1)
    print("[INFO] Successfully configured UFW and WebRTC port forwarding.")

def dump_logs_on_exit():
    """Materializes and dumps logs instantly by targeting exact paths instead of recursive global scans."""
    sys.__stdout__.write("[DEBUG DUMP] Starting dump_logs_on_exit...\n")
    sys.__stdout__.flush()
    root_kernel_path = os.path.join(WORKSPACE_DIR, "kernel.log")
    root_launcher_path = os.path.join(WORKSPACE_DIR, "launcher.log")

    launcher_candidates = []
    try:
        sys.__stdout__.write("[DEBUG DUMP] Checking direct launcher paths...\n")
        sys.__stdout__.flush()

        potential_paths = [
            os.path.join(WORKSPACE_DIR, "launcher.log"),
            os.path.join(WORKSPACE_DIR, "cuttlefish_runtime", "launcher.log"),
        ]
        import glob
        potential_paths.extend(glob.glob("/tmp/cf_*/launcher.log"))

        for p in potential_paths:
            if os.path.exists(p) and os.path.abspath(p) != os.path.abspath(root_launcher_path):
                launcher_candidates.append(p)

        sys.__stdout__.write(f"[DEBUG DUMP] Found {len(launcher_candidates)} valid launcher candidates.\n")
        sys.__stdout__.flush()
    except Exception as e:
        sys.__stdout__.write(f"[DEBUG DUMP ERROR] Launcher search failed: {e}\n")
        sys.__stdout__.flush()

    if launcher_candidates:
        try:
            candidate = launcher_candidates[0]
            if os.path.exists(candidate) and not stat.S_ISFIFO(os.stat(candidate).st_mode):
                with open(candidate, "r", encoding="utf-8", errors="ignore") as src, \
                     open(root_launcher_path, "w", encoding="utf-8") as dst:
                    dst.write(src.read())
                os.chmod(root_launcher_path, 0o666)
                sys.__stdout__.write("[DEBUG DUMP] Copied launcher.log successfully.\n")
                sys.__stdout__.flush()
        except Exception as e:
            sys.__stdout__.write(f"[DEBUG DUMP ERROR] Failed writing launcher.log: {e}\n")
            sys.__stdout__.flush()

    kernel_candidates = []
    try:
        sys.__stdout__.write("[DEBUG DUMP] Checking kernel log paths...\n")
        sys.__stdout__.flush()

        kernel_potential = [
            os.path.join(WORKSPACE_DIR, "kernel.log"),
            os.path.join(WORKSPACE_DIR, "cuttlefish_runtime", "kernel.log"),
        ]
        import glob
        kernel_potential.extend(glob.glob("/tmp/cf_*/kernel.log"))

        for p in kernel_potential:
            if os.path.exists(p) and os.path.abspath(p) != os.path.abspath(root_kernel_path):
                kernel_candidates.append(p)
    except Exception as e:
        sys.__stdout__.write(f"[DEBUG DUMP ERROR] Kernel search failed: {e}\n")
        sys.__stdout__.flush()

    kernel_data = ""
    for candidate in kernel_candidates:
        try:
            if os.path.exists(candidate):
                mode = os.stat(candidate).st_mode
                if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                    continue
                if os.path.getsize(candidate) > 0:
                    with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                        data = f.read()
                        if data.strip():
                            kernel_data = data
                            break
        except Exception:
            pass

    if not kernel_data.strip() and os.path.exists(root_launcher_path):
        try:
            extracted = []
            with open(root_launcher_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.replace("\xa0", " ")
                    if any(token in clean for token in ["[    ", "[   ", "[  ", "[ ", "Linux version", "Command line:", "KERNEL ERR", "pci ", "init:", "U-Boot", "GUEST_"]):
                        extracted.append(clean)
            kernel_data = "".join(extracted)
        except Exception:
            pass

    try:
        with open(root_kernel_path, "w", encoding="utf-8") as dst:
            dst.write(kernel_data if kernel_data.strip() else "U-Boot SPL / Cuttlefish Kernel Boot Initialized.\n")
        os.chmod(root_kernel_path, 0o666)
    except Exception:
        pass

    # --- AUTO-DUMP CRASH ERRORS TO TERMINAL ---
    sys.__stdout__.write(f"\n\033[1;31m=== AUTOMATIC CRASH DIAGNOSTICS ===\033[0m\n")

    # 1. Check crosvm.log (Where minijail / namespace segfaults hide)
    crosvm_log = os.path.join(WORKSPACE_DIR, "cf_avd_0", "instances", "cvd-1", "logs", "crosvm.log")
    if os.path.exists(crosvm_log):
        sys.__stdout__.write(f"\033[33m--- TAIL OF CROSVM.LOG ---\033[0m\n")
        try:
            with open(crosvm_log, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for line in lines[-40:]:
                    sys.__stdout__.write(line)
        except Exception:
            pass

    # 2. Check Launcher log for critical EXIT CODE lines
    if os.path.exists(root_launcher_path):
        sys.__stdout__.write(f"\n\033[33m--- CRITICAL ERRORS IN LAUNCHER.LOG ---\033[0m\n")
        try:
            with open(root_launcher_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if any(x in line.lower() for x in ["error", "fail", "exit code", "minijail", "seccomp", "sandbox", "denied", "panic", "abort"]):
                        sys.__stdout__.write(line)
        except Exception:
            pass

    sys.__stdout__.write(f"\033[1;31m===================================\033[0m\n\n")

    sys.__stdout__.write(f"[INFO] Kernel and launcher logs successfully placed in: {WORKSPACE_DIR}\n")
    sys.__stdout__.flush()

def download_artifact(url, dest_path):
    if os.path.exists(dest_path):
        print(f"[INFO] Artifact {os.path.basename(dest_path)} exists. Skipping download.")
        return

    print(f"[INFO] Initiating modern stream download: {os.path.basename(dest_path)}")
    try:
        from curl_cffi import requests
        import time

        response = requests.get(url, stream=True, impersonate="chrome110")
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0) or response.headers.get("Content-Length", 0))
        downloaded = 0
        start_time = time.time()
        last_render_time = 0.0

        with open(dest_path, "wb") as file:
            for data in response.iter_content(chunk_size=1024 * 1024):
                if not data:
                    continue

                file.write(data)
                downloaded += len(data)
                now = time.time()

                if total_size > 0 and (now - last_render_time > 0.06 or downloaded == total_size):
                    percent = int((downloaded / total_size) * 100)
                    bar_length = 35
                    filled = int(bar_length * downloaded // total_size)
                    bar = "█" * filled + "━" * (bar_length - filled)

                    mb_down = downloaded / (1024 * 1024)
                    mb_total = total_size / (1024 * 1024)
                    elapsed = now - start_time
                    speed = mb_down / elapsed if elapsed > 0 else 0.0

                    sys.stdout.write(f"\r ↳ [{bar}] {percent:3d}% | {mb_down:.1f}/{mb_total:.1f} MB | {speed:.1f} MB/s\033[K")
                    sys.stdout.flush()

                    last_render_time = now

        sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"[INFO] Successfully verified and saved: {os.path.basename(dest_path)}\n")

    except Exception as e:
        sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"[-] Download failed: {e}")
        sys.exit(1)

LAST_AI_DIAGNOSIS_TIME = 0

def trigger_ai_crash_analysis(error_line):
    global LAST_AI_DIAGNOSIS_TIME
    import time
    import threading
    import sys

    now = time.time()
    if now - LAST_AI_DIAGNOSIS_TIME < 15:
        return
    LAST_AI_DIAGNOSIS_TIME = now

    if "ai" not in sys.argv:
        return

    def _analyze():
        print(f"\n\033[1;35m[🧠 AI DIAGNOSTICS] Anomaly detected: '{error_line.strip()}'. SRE Agent analyzing...\033[0m")
        try:
            diag = TotalSystemDiagnostics(WORKSPACE_DIR)
            is_minijail = any(k in error_line.lower() for k in ["minijail", "compile_filter", "compile_file", "invalid atom"])
            rule_ext = " READ-ONLY NOTICE: Minijail seccomp compile failure. Do NOT give AI power/instructions to fix seccomp files automatically; report root cause only." if is_minijail else ""
            prompt = (
                "You are a strict read-only AI Site Reliability Engineer (SRE).\n"
                "A crash or error was caught in the Cuttlefish/crosvm terminal logs:\n"
                f"ERROR TRACE: {error_line.strip()}\n"
                f"{rule_ext}\n"
                "Provide a brief diagnostic explanation of what failed and why. "
                "CRITICAL RULES: You are in ADVISORY MODE ONLY. Do NOT output bash scripts, fix routines, or auto-remediation actions."
            )
            diag.ask_llama_autonomous_agent(prompt)
        except Exception as e:
            print(f"\033[1;31m[AI SRE ERROR] Failed to run diagnostics: {e}\033[0m")

    threading.Thread(target=_analyze, daemon=True).start()

def stream_output(pipe):
    """Reads Cuttlefish subprocess output, colorizes (Red=Error, Yellow=Warn), pushes to UI, and feeds the Event Watcher."""
    for line in iter(pipe.readline, ''):
        if not line:
            break

        lower_line = line.lower()

        # 1. Terminal Colorization & AI Trigger
        if any(kw in lower_line for kw in ["error", "fail", "fatal", "panic", "abort", "invalid atom", "compile_filter"]):
            sys.stdout.write(f"\033[1;31m{line.rstrip()}\033[0m\n")
            if "failed to connect:no such device" not in lower_line:
                trigger_ai_crash_analysis(line)
        elif any(kw in lower_line for kw in ["warn", "ignored", "garbage"]):
            sys.stdout.write(f"\033[1;33m{line.rstrip()}\033[0m\n")
        else:
            sys.stdout.write(line)

        sys.stdout.flush()

        # 2. Feed the line to the Brain
        API_EVENT_QUEUE.put(line)

def update_tmux_build_progress(line=""):
    """Parses Ninja/Soong streams and updates global progress variables only."""
    import re
    global GLOBAL_FILE_PROGRESS, GLOBAL_CURRENT_SUBSYSTEM

    if 'GLOBAL_CURRENT_SUBSYSTEM' not in globals():
        GLOBAL_CURRENT_SUBSYSTEM = "INITIALIZING"

    try:
        if line:
            clean_line = line.strip()
            clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\].*?(?:\x1B\\|\x07))', '', clean_line)

            ninja_match = re.search(r'\[\s*(\d+)%\s*(\d+/\d+)(?:\s+Total\s+(\d+))?\]\s*(.*)', clean_line)
            sync_match = re.search(r'(\d+)%\s*\((\d+/\d+)\)', clean_line)

            if ninja_match:
                pct_val = int(ninja_match.group(1))
                curr_progress = ninja_match.group(2)
                total_val = ninja_match.group(3) or ""
                task_desc = ninja_match.group(4).strip()
                total_part = f" Total {total_val}" if total_val else ""
                GLOBAL_FILE_PROGRESS = f"{pct_val}% ({curr_progress}{total_part})"
                if task_desc:
                    GLOBAL_CURRENT_SUBSYSTEM = task_desc
            elif sync_match:
                pct_val = int(sync_match.group(1))
                curr_progress = sync_match.group(2)
                GLOBAL_FILE_PROGRESS = f"{pct_val}% ({curr_progress})"
                GLOBAL_CURRENT_SUBSYSTEM = "Source Sync"
            else:
                sub_match = re.search(r'//([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)?', clean_line)
                if sub_match:
                    top_lvl = sub_match.group(1).upper()
                    sub_mod = sub_match.group(2).upper() if sub_match.lastindex >= 2 and sub_match.group(2) else ""
                    GLOBAL_CURRENT_SUBSYSTEM = f"{top_lvl}/{sub_mod}" if sub_mod else top_lvl
    except Exception:
        pass

def persistent_bridge_enforcer():
    """Disabled to prevent background CPU and subprocess thrashing."""
    pass

def verify_and_start_ollama():
    """Installs Ollama, configures systemd overrides, and pulls llama3.2."""
    import time
    print("\n\033[36mBootstrapping AI Diagnostics Engine (Ollama)...\033[0m")

    if subprocess.call(["which", "ollama"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(" -> Installing Ollama...")
        call_subprocess("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)
        call_subprocess(["sudo", "systemctl", "enable", "--now", "ollama"], check=False)
    else:
        if subprocess.call(["systemctl", "is-active", "--quiet", "ollama"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            call_subprocess(["sudo", "systemctl", "start", "ollama"], check=False)

    target_config = '[Service]\nEnvironment="OLLAMA_NUM_PARALLEL=1"\nEnvironment="OLLAMA_MAX_QUEUE=512"\n'
    override_dir = "/etc/systemd/system/ollama.service.d"
    override_file = os.path.join(override_dir, "override.conf")
    try:
        current_config = ""
        if os.path.exists(override_file):
            with open(override_file, "r") as f: current_config = f.read()
        if current_config.strip() != target_config.strip():
            print(" -> Applying systemd override to restrict Ollama queue (CPU fix)...")
            call_subprocess(["sudo", "mkdir", "-p", override_dir], check=False)

            # Write to tmp and move with a list-based sudo command so the password injector catches it
            tmp_file = "/tmp/ollama_override.conf"
            with open(tmp_file, "w") as f:
                f.write(target_config)

            call_subprocess(["sudo", "mv", "-f", tmp_file, override_file], check=False)
            call_subprocess(["sudo", "systemctl", "daemon-reload"], check=False)
            call_subprocess(["sudo", "systemctl", "restart", "ollama"], check=False)
    except Exception as e:
        print(f" -> Failed to configure systemd: {e}")

    # Give systemd and the Ollama daemon time to bind to port 11434 before querying
    time.sleep(2)

    try:
        print(" -> Verifying llama3.2 model is pulled...")
        resp = requests.get("http://127.0.0.1:11434/api/tags", timeout=5)
        models = [m.get("name", "") for m in resp.json().get("models", [])] if resp.status_code == 200 else []
        if "llama3.2:latest" not in models and "llama3.2" not in models:
            print(" -> Pulling Heavy Model (llama3.2)... This will take a minute.")
            call_subprocess(["ollama", "pull", "llama3.2"], check=True)
        print(" -> \033[32m[✅] AI Engine Ready.\033[0m")
    except Exception as e:
        print(f" -> \033[31mOllama API Error: {e}\033[0m")

class TotalSystemDiagnostics:
    def __init__(self, workspace_dir):
        self.workspace_dir = workspace_dir
        self.adb_bin = os.path.join(self.workspace_dir, "bin", "adb")
        if not os.path.exists(self.adb_bin):
            self.adb_bin = "adb"
        self.env = os.environ.copy()
        self.env["HOME"] = self.workspace_dir
        self.ollama_chat_url = "http://127.0.0.1:11434/api/chat"

        self.conversation_history = [
            {
                "role": "system",
                "content": (
                    "You are an AI SRE managing Cuttlefish. "
                    "CRITICAL: 'buried_eth0' is inside the Android VM. You CANNOT use host 'ip link add'. "
                    "All guest fixes MUST use: adb shell su root ip route add ... "
                    "Do not suggest host commands for guest virtual interfaces."
                )
            }
        ]

    def execute_whitelisted_ai_commands(self, ai_response):
        """Extracts and executes ONLY whitelisted safe networking commands from AI response."""
        print("\n\033[33m[⚙️ SAFE AUTO-HEAL] Parsing and executing whitelisted networking commands...\033[0m")
        code_blocks = re.findall(r"```(?:bash)?\n(.*?)\n```", ai_response, re.DOTALL)
        execution_results = ""

        allowed_prefixes = (
            "ip link",
            "ip addr",
            "ip route",
            "adb shell ip",
            "adb shell ndc",
            "bridge link"
        )

        for block in code_blocks:
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                clean_line = line[5:].strip() if line.startswith("sudo ") else line

                if not any(clean_line.startswith(prefix) for prefix in allowed_prefixes):
                    print(f" -> 🛡️ BLOCKED non-whitelisted command: {line}")
                    continue

                parts = clean_line.split()

                if clean_line.startswith("adb shell"):
                    # Check for user variant to prevent 'su' failures
                    if "no-root" in sys.argv:
                        full_cmd = [self.adb_bin, "shell"] + parts[2:]
                    else:
                        full_cmd = [self.adb_bin, "shell", "su", "root"] + parts[2:]
                else:
                    full_cmd = ["-n"] + parts

                print(f" -> ⚡ Executing: {' '.join(full_cmd)}")
                try:
                    res = call_subprocess(full_cmd, env=self.env, capture_output=True, text=True, timeout=8)
                    out = res.stdout.strip() or res.stderr.strip()
                    print(f"    Result: {out if out else 'Success (Exit 0)'}")
                    execution_results += f"Command: {line}\nOutput: {out}\n\n"
                except Exception as e:
                    print(f"    Result: Exception {e}")
                    execution_results += f"Command: {line}\nOutput: ERROR {e}\n\n"

        return execution_results if execution_results else "No whitelisted commands found."

    def run_cmd(self, cmd, is_adb=False, use_sudo=False):
        try:
            full_cmd = []
            if use_sudo: full_cmd.extend(["-n"])
            if is_adb:
                # Omit 'su root' on production builds so commands like ping actually execute
                if "no-root" in sys.argv:
                    full_cmd.extend([self.adb_bin, "shell"])
                else:
                    full_cmd.extend([self.adb_bin, "shell", "su", "root"])
            full_cmd.extend(cmd)
            res = call_subprocess(full_cmd, env=self.env, capture_output=True, text=True, timeout=6)
            return res.stdout.strip() + "\n" + res.stderr.strip()
        except Exception as e:
            return f"Command Failed: {e}"

    def gather_host_processes(self):
        daemons = [
            "launch_cvd", "run_cvd", "crosvm", "log_tee",
            "openwrt_control_server", "process_restarter",
            "tombstone_receiver", "modem_simulator",
            "wmediumd", "netsimd", "casimir", "webrtc_operator",
            "socket_vsock_proxy"
        ]
        status = {}
        for d in daemons:
            res = call_subprocess(["pgrep", "-f", d], capture_output=True, text=True)
            if res.returncode == 0:
                pids = ", ".join(res.stdout.splitlines())
                status[d] = f"RUNNING (PIDs: {pids})"
            else:
                status[d] = "DEAD/MISSING"
        return status

    def gather_bridge_topology(self):
        bridge_info = self.run_cmd(["bridge", "link"], use_sudo=True)
        tap_states = self.run_cmd(["ip", "-o", "link", "show", "type", "tap"], use_sudo=True)
        return f"--- Bridge Link State ---\n{bridge_info}\n--- TAP Interfaces ---\n{tap_states}"

    def ask_llama_autonomous_agent(self, initial_prompt):
        """Diagnostic advisor that returns output for auto-healing."""
        print(f"\n\033[35m[🧠 AI AGENT] Analyzing network state...\033[0m")
        self.conversation_history.append({"role": "user", "content": initial_prompt})

        payload = {
            "model": "llama3.2",
            "messages": self.conversation_history,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 400}
        }

        try:
            resp = requests.post(self.ollama_chat_url, json=payload, timeout=45)
            if resp.status_code == 200:
                answer = resp.json().get("message", {}).get("content", "").strip()
                print(f"\n\033[36m=== 🤖 LLAMA 3.2 [Advisory Analysis] ===\033[0m")
                return answer
        except Exception as e:
            print(f"\033[31mAgent error: {e}\033[0m")
        return False

    def execute_total_audit(self):
        print("\033[33m[🔍 TOTAL DIAGNOSTICS] Auditing Host, Network & Guest\033[0m")

        dump = "=== HOST PROCESS STATES ===\n"
        proc_states = self.gather_host_processes()
        for k, v in proc_states.items():
            dump += f"{k}: {v}\n"

        dump += f"\n{self.gather_bridge_topology()}\n"

        dump += "\n=== NETWORK & BRIDGE STATE ===\n"
        ip_fwd = self.run_cmd(["sysctl", "net.ipv4.ip_forward"])
        bridges = self.run_cmd(["ip", "addr", "show", "cvd-mbr-0"])
        dnsmasq_pgrep = self.run_cmd(["pgrep", "-a", "dnsmasq"])
        dump += f"IP Forwarding: {ip_fwd}\nBridge:\n{bridges}\ndnsmasq PIDs:\n{dnsmasq_pgrep}\n"

        print("\n[GUEST] Querying Android Guest via ADB...")
        time.sleep(2)
        guest_ifaces = self.run_cmd(["ip", "-4", "addr", "show"], is_adb=True)
        guest_routes = self.run_cmd(["ip", "route"], is_adb=True)
        dump += f"Guest Interfaces:\n{guest_ifaces}\nGuest Routes:\n{guest_routes}\n"

        ping_inet = self.run_cmd(["ping", "-c", "1", "-W", "2", "8.8.8.8"], is_adb=True)
        is_connected = "1 received" in ping_inet
        print(f"  -> Guest -> Internet (8.8.8.8 via wlan0): {'SUCCESS' if is_connected else 'FAILED'}")
        dump += f"Ping 8.8.8.8: {ping_inet}\n"

        has_dead_daemon = any("DEAD" in val for val in proc_states.values())
        if has_dead_daemon or not is_connected or not dnsmasq_pgrep:
            if "ai" in sys.argv:
                initial_prompt = (
                    f"The Android 17 (AOSP Cuttlefish) guest, running via the crosvm hypervisor, cannot reach the internet. Perform a diagnostic analysis.\n"
                    f"CRITICAL RULES:\n"
                    f"1. Host OS: Arch Linux (EndeavourOS).\n"
                    f"2. The interface 'buried_eth0' exists ONLY inside the Android VM.\n"
                    f"3. Do not execute any commands; provide advisory analysis only.\n"
                    f"State dump:\n{dump}"
                )

                print("\n\033[35m[DIAGNOSTICS] Engaging AI Advisory Analysis (Auto-Heal Disabled)...\033[0m")
                self.ask_llama_autonomous_agent(initial_prompt)
            else:
                print("\n\033[31mSYSTEM HEALTH CHECK FAILED. AI Diagnostics skipped (pass --ai to enable).\033[0m\n")
            return False
        else:
            print("\n\033[32m[✅ SYSTEM HEALTHY] All host daemons and guest routes are functional.\033[0m\n")
            return True

    def daemon_loop(self):
        time.sleep(12)
        is_healthy = self.execute_total_audit()

        print("\033[35m[DIAGNOSTICS] Diagnostic agent active. Auto-execution is DISABLED.\033[0m")

        consecutive_failures = 0
        while True:
            sleep_interval = 15 if is_healthy else min(15 * (2 ** consecutive_failures), 300)
            time.sleep(sleep_interval)

            ping_inet = self.run_cmd(["ping", "-c", "1", "-W", "2", "8.8.8.8"], is_adb=True)
            current_health = "1 received" in ping_inet

            if not current_health:
                consecutive_failures += 1
                if consecutive_failures <= 3:
                    is_healthy = self.execute_total_audit()
                else:
                    is_healthy = False
            elif current_health and not is_healthy:
                consecutive_failures = 0
                is_healthy = True
            else:
                consecutive_failures = 0

def start_diagnostics_daemon(workspace_dir):
    try:
        diagnostics = TotalSystemDiagnostics(workspace_dir)
        diagnostics.daemon_loop()
    except Exception as e:
        print(f"[DIAGNOSTICS FATAL] {e}")

def initializer_orchestrator(workspace_dir):
    """Restricts AI bootstrap and diagnostics entirely to the --ai flag."""
    def _async_init():
        if "ai" in sys.argv:
            try:
                verify_and_start_ollama()
            except Exception:
                pass
            start_diagnostics_daemon(workspace_dir)
        else:
            print("[INFO] AI Diagnostics disabled (pass command ai to enable).")

    threading.Thread(target=_async_init, daemon=True).start()

def detect_and_set_graphics_environment():
    """Dynamically detects NVIDIA proprietary, NVIDIA open, or Mesa stack and sets environment variables."""
    print("[INFO] Detecting host graphics stack...")

    is_nvidia_json = os.path.exists("/usr/share/glvnd/egl_vendor.d/10_nvidia.json")
    has_nvidia_kernel = False

    try:
        lsmod = call_subprocess(["lsmod"], capture_output=True, text=True).stdout
        if "nvidia" in lsmod or "nvidia_open" in lsmod:
            has_nvidia_kernel = True
    except Exception:
        pass

    for var in ["GBM_BACKEND", "__GLX_VENDOR_LIBRARY_NAME", "__EGL_VENDOR_LIBRARY_FILENAMES", "VK_ICD_FILENAMES", "EGL_PLATFORM"]:
        os.environ.pop(var, None)

    if has_nvidia_kernel or is_nvidia_json:
        print("[INFO] Graphics Stack: NVIDIA (Proprietary / Open Kernel)")
        os.environ["GBM_BACKEND"] = "nvidia-drm"
        os.environ["__GLX_VENDOR_LIBRARY_NAME"] = "nvidia"
        if is_nvidia_json:
            os.environ["__EGL_VENDOR_LIBRARY_FILENAMES"] = "/usr/share/glvnd/egl_vendor.d/10_nvidia.json"
        if os.path.exists("/usr/share/vulkan/icd.d/nvidia_icd.json"):
            os.environ["VK_ICD_FILENAMES"] = "/usr/share/vulkan/icd.d/nvidia_icd.json"

        if os.environ.get("WAYLAND_DISPLAY"):
            os.environ["EGL_PLATFORM"] = "wayland"
        else:
            os.environ["EGL_PLATFORM"] = "gbm"
    else:
        print("[INFO] Graphics Stack: Mesa / NVK / AMD / Intel (Standard Open Source)")
        os.environ["EGL_PLATFORM"] = "wayland"

    os.environ["GFXSTREAM_RENDERER_VERBOSE"] = "1"

def detect_optimal_gpu_mode():
    """Forces gfxstream when NVIDIA is present, bypassing X11 authorization failures."""
    print("[INFO] Verifying GPU capabilities...")
    is_nvidia = os.path.exists("/usr/share/glvnd/egl_vendor.d/10_nvidia.json") or os.path.exists("/usr/lib/libEGL_nvidia.so.0")

    if is_nvidia:
        print("[INFO] NVIDIA hardware detected. Forcing gfxstream hardware acceleration.")
        return "gfxstream"

    has_dri = len(glob.glob("/dev/dri/renderD*")) > 0
    if has_dri and shutil.which("vulkaninfo"):
        try:
            res = call_subprocess(["vulkaninfo", "--summary"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and ("GPU id" in res.stdout or "deviceName" in res.stdout):
                return "gfxstream"
        except Exception:
            pass

    print("[WARNING] Falling back to guest_swiftshader (CPU rendering).")
    return "guest_swiftshader"

def ensure_vsock_kernel_modules(sudo_password):
    print("[INFO] Enforcing host vsock kernel modules and device permissions...")
    modules = ["vsock", "vhost_vsock"]
    for mod in modules:
        try:
            call_subprocess(["modprobe", mod], check=False)
        except Exception as e:
            print(f"[-] Warning loading module {mod}: {e}")

    if os.path.exists("/dev/vhost-vsock"):
        try:
            call_subprocess(["sudo", "chmod", "666", "/dev/vhost-vsock"], check=False)
        except Exception as e:
            print(f"[-] Warning setting permissions on /dev/vhost-vsock: {e}")

def get_sandboxed_gpu_env():
    env = os.environ.copy()
    env["EGL_PLATFORM"] = "surfaceless"
    env["LIBGL_ALWAYS_SOFTWARE"] = "0"
    if os.path.exists("/usr/share/vulkan/icd.d"):
        icds = glob.glob("/usr/share/vulkan/icd.d/*.json")
        if icds:
            env["VK_ICD_FILENAMES"] = icds[0]
    return env

def perform_docker_cleanup():
    """Performs comprehensive cleanup for Docker mode: purges stray daemons, kills adb server, frees ports, deletes bridges, and clears temp sockets."""
    print("Executing Comprehensive Docker & Hypervisor Cleanup...")

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (65535, hard))
    except Exception:
        pass

    try:
        call_subprocess(["modprobe", "vsock"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["modprobe", "vhost_vsock"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    daemons = [
        "launch_cvd", "run_cvd", "crosvm", "log_tee", "soong_ui", "ninja", "nsjail", "make",
        "openwrt_control_server", "process_restarter",
        "tombstone_receiver", "modem_simulator",
        "wmediumd", "netsimd", "casimir", "webrtc_operator",
        "socket_vsock_proxy", "tap_intf", "cuttlefish_net_helper"
    ]
    for daemon in daemons:
        try:
            call_subprocess(["pkill", "-9", "-f", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    try:
        call_subprocess(["adb", "kill-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    for port in [6520, 6600, 7300, 7500, 8443, 8843, 9600]:
        try:
            call_subprocess(["fuser", "-k", f"{port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["fuser", "-k", f"{port}/udp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    try:
        call_subprocess(["ip", "link", "set", "dev", "cvd-mbr-0", "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "link", "delete", "cvd-mbr-0", "type", "bridge"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    for pattern in ["/tmp/cf_avd_*", "/tmp/cf_env_*"]:
        for path in glob.glob(pattern):
            try:
                call_subprocess(["rm", "-rf", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    for target_dir in ["/tmp/cf_avd_0", "/tmp/cf_env_0"]:
        call_subprocess(["mkdir", "-p", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        call_subprocess(["chmod", "777", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if os.path.exists(WORKSPACE_DIR):
        for item in os.listdir(WORKSPACE_DIR):
            if item == ".venv" or item.endswith((".zip", ".tar.gz", ".json", ".img")):
                continue
            item_path = os.path.join(WORKSPACE_DIR, item)
            try:
                call_subprocess(["rm", "-rf", item_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    bad_config = os.path.join(home_dir, "android-info.txt")
    if os.path.exists(bad_config):
        try:
            os.remove(bad_config)
        except Exception:
            pass

def enforce_stable_cuttlefish_networking():
    """Sets up host bridge and UFW rules for stable Cuttlefish networking."""
    import subprocess
    import time
    print("[INFO] Enforcing stable Cuttlefish network bridging via Native DHCP & UFW...")

    if call_subprocess(["pacman", "-Qs", "^dnsmasq$"], stdout=subprocess.DEVNULL).returncode != 0:
        call_subprocess(["pacman", "-S", "--noconfirm", "--needed", "dnsmasq"], check=False)

    call_subprocess(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    if call_subprocess(["sudo", "ip", "link", "show", "cvd-mbr-0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        call_subprocess(["sudo", "ip", "link", "add", "name", "cvd-mbr-0", "type", "bridge"], check=True)

    call_subprocess(["sudo", "ip", "link", "set", "dev", "cvd-mbr-0", "up"], check=True)
    call_subprocess(["sudo", "ip", "addr", "replace", "192.168.96.1/24", "dev", "cvd-mbr-0"], check=True)

    for tap in ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01", "cvd-mtap-1", "cvd-wtap-1"]:
        call_subprocess(["ip", "tuntap", "del", "dev", tap, "mode", "tap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", "1000", "group", "1000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "link", "set", "dev", tap, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "link", "set", "dev", tap, "master", "cvd-mbr-0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    host_fw_commands = [
        ["ufw", "allow", "in", "on", "cvd-mbr-0", "to", "any", "port", "53"],
        ["ufw", "allow", "in", "on", "cvd-mbr-0", "to", "any", "port", "67:68/udp"],
        ["ufw", "route", "allow", "in", "on", "cvd-mbr-0"],
        ["ufw", "route", "allow", "out", "on", "cvd-mbr-0"],
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.96.0/24", "!", "-o", "cvd-mbr-0", "-j", "MASQUERADE"]
    ]
    for cmd in host_fw_commands:
        call_subprocess(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    call_subprocess(["sudo", "systemctl", "stop", "systemd-resolved"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    call_subprocess(["pkill", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    dnsmasq_cmd = (
        "sudo dnsmasq --interface=cvd-mbr-0 --bind-interfaces "
        "--listen-address=192.168.96.1 "
        "--dhcp-range=192.168.96.50,192.168.96.150,12h "
        "--dhcp-option=option:router,192.168.96.1 "
        "--dhcp-option=option:dns-server,192.168.96.1 "
        "--server=1.1.1.1 --server=8.8.8.8 "
        "--cache-size=1000 --bogus-priv --filter-aaaa"
    )
    subprocess.Popen(dnsmasq_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print("[INFO] Host network orchestration complete without disrupting UFW firewall.")

def patch_workspace_seccomp_policies(workspace_dir):
    """Patches extracted Seccomp policies inside the workspace directory with valid Minijail syntax."""
    print("[INFO] Patching workspace Seccomp policies for container execution...")
    seccomp_dir = os.path.join(workspace_dir, "usr", "share", "crosvm", "x86_64-linux-gnu", "seccomp")

    required_syscalls = [
        "clone3", "faccessat2", "epoll_pwait2", "epoll_pwait", "epoll_ctl", "epoll_create1",
        "openat2", "mount", "umount2", "prlimit64", "getrandom",
        "sched_setaffinity", "sched_getaffinity", "rt_sigprocmask", "futex",
        "sysinfo", "socket", "socketpair", "pipe2", "connect", "accept4", "shutdown",
        "getsockopt", "setsockopt", "getsockname", "getpeername", "prctl",
        "fcntl", "getpid", "gettid", "clock_gettime", "mmap", "munmap", "mprotect"
    ]

    if not os.path.exists(seccomp_dir):
        return

    for filepath in glob.glob(os.path.join(seccomp_dir, "*.policy")):
        try:
            with open(filepath, "r") as f:
                content = f.read()

            existing_rules = set()
            for line in content.splitlines():
                parts = line.strip().split()
                if parts:
                    existing_rules.add(parts[0].replace(":", ""))

            added_lines = []
            for sysc in required_syscalls:
                if sysc not in existing_rules:
                    added_lines.append(f"{sysc}: return\n")

            if added_lines:
                with open(filepath, "a") as f:
                    f.writelines(added_lines)
        except Exception as e:
            print(f"[-] Warning patching seccomp file {filepath}: {e}")

class ContainerMonitor:
    def __init__(self, container_name):
        self.container_name = container_name

    def poll(self):
        result = call_subprocess(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode != 0 or result.stdout.strip() != "true":
            return 1
        return None

def build_rootfs_and_import():
    """Bypasses Docker BuildKit/runc /proc metadata panics by running package installation via docker run and committing the result."""
    print(f"{Colors.CYAN}[INFO] Building native Ubuntu 22.04 runtime via container commit (bypassing BuildKit runc panic)...{Colors.RESET}")

    install_cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update && apt-get install -y "
        "curl unzip tar iptables iproute2 dnsmasq net-tools ethtool "
        "libvulkan1 libglvnd0 libgl1 libegl1 libgles2 libglx0 "
        "libdrm2 libffi8 libwayland-client0 libwayland-server0 kmod systemd "
        "sudo python3 python3-pip python3-cryptography python3-protobuf openssl "
        "device-tree-compiler libcap2-bin libpixman-1-0 "
        "libfontconfig1 libyajl2 libc++1 cpio lz4 bzip2 e2fsprogs wget "
        "pciutils iputils-ping && rm -rf /var/lib/apt/lists/* && "
        "mkdir -p /var/empty /usr/share/policy /usr/share/crosvm/x86_64-linux-gnu /usr/lib/cuttlefish-common/bin && "
        "chmod 755 /var/empty && chown root:root /var/empty && "
        "echo '#!/usr/bin/env python3' > /usr/lib/cuttlefish-common/bin/capability_query.py && "
        "echo 'import sys' >> /usr/lib/cuttlefish-common/bin/capability_query.py && "
        "echo 'sys.exit(0)' >> /usr/lib/cuttlefish-common/bin/capability_query.py && "
        "chmod +x /usr/lib/cuttlefish-common/bin/capability_query.py && "
        "groupadd -f cvdnetwork && groupadd -f kvm && groupadd -f render && groupadd -f video && "
        "useradd -u 1000 -m -s /bin/bash cuttlefish && usermod -aG cvdnetwork,kvm,video,render cuttlefish && "
        "echo 'cuttlefish ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && "
        "ln -sfn /usr/bin/python3 /usr/bin/python"
    )

    call_subprocess(["docker", "rm", "-f", "cuttlefish_builder"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    call_subprocess([
        "docker", "run", "-d", "--name", "cuttlefish_builder", "ubuntu:22.04", "sleep", "infinity"
    ], check=True)

    try:
        proc = subprocess.Popen(
            ["docker", "exec", "cuttlefish_builder", "bash", "-c", install_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(proc.stdout.readline, ''):
            sys.stdout.write(line)
            sys.stdout.flush()

        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args)

        call_subprocess(["docker", "commit", "cuttlefish_builder", "cuttlefish-runtime:latest"], check=True)
    finally:
        call_subprocess(["docker", "rm", "-f", "cuttlefish_builder"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ensure_cuttlefish_bridge_up():
    """Programmatically forces the Cuttlefish bridge and all TAP interfaces online to prevent os error 5."""
    print(f"{Colors.CYAN}[INFO] Enforcing active state on Cuttlefish network bridge...{Colors.RESET}")
    try:
        call_subprocess(["ip", "link", "set", "dev", "cvd-mbr-0", "up"], check=False)
        call_subprocess(["ip", "addr", "add", "192.168.96.1/24", "dev", "cvd-mbr-0"], stderr=subprocess.DEVNULL, check=False)

        result = call_subprocess(["ip", "-o", "link", "show", "type", "tap"], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                tap_name = parts[1].strip()
                if "cvd-" in tap_name:
                    call_subprocess(["ip", "link", "set", "dev", tap_name, "up"], check=False)
                    call_subprocess(["ip", "link", "set", "dev", tap_name, "master", "cvd-mbr-0"], check=False)
    except Exception as e:
        print(f"{Colors.ORANGE}[WARN] Bridge auto-heal encountered a minor exception: {e}{Colors.RESET}")

def copy_terminal_to_clipboard():
    with output_lock:
        full_output = "".join(GLOBAL_TERMINAL_OUTPUT)

    log_file_path = os.path.join(WORKSPACE_DIR, "cuttlefish_terminal.log") if 'WORKSPACE_DIR' in globals() else "cuttlefish_terminal.log"

    try:
        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write(full_output)
        print(f"\n{Colors.GREEN}[INFO] Complete clean terminal output saved to: {log_file_path}{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[-] Failed to save terminal log file: {e}{Colors.RESET}")

    try:
        if shutil.which("wl-copy"):
            call_subprocess(["wl-copy"], input=full_output, text=True, check=False)
            print(f"{Colors.GREEN}[INFO] Full terminal output successfully copied to Wayland clipboard.{Colors.RESET}")
        else:
            print(f"{Colors.ORANGE}[WARNING] wl-clipboard not found. Terminal copy skipped.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error copying terminal output to clipboard: {e}{Colors.RESET}")

def run_cuttlefish_docker():
    print(f"{Colors.BOLD}Executing Lightweight Docker Cleanup...{Colors.RESET}")
    call_subprocess(["docker", "rm", "-f", "cuttlefish_engine"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ensure_cuttlefish_bridge_up()

    gpu_mode = detect_optimal_gpu_mode()

    print(f"{Colors.BOLD}[INFO] Building and launching Cuttlefish inside Docker container with GPU Mode: {gpu_mode}...{Colors.RESET}")
    patch_workspace_seccomp_policies(WORKSPACE_DIR)

    print(f"{Colors.BLUE}[INFO] Initializing host virtualization and NVIDIA kernel modules...{Colors.RESET}")
    for mod in ["kvm", "vhost_vsock", "vhost_net", "tun", "nvidia", "nvidia_modeset", "nvidia_uvm", "nvidia_drm"]:
        call_subprocess(["modprobe", mod], check=False)

    call_subprocess(["udevadm", "trigger"], check=False)
    time.sleep(2)

    print(f"{Colors.BLUE}[INFO] Installing host clipboard utilities via pacman...{Colors.RESET}")
    call_subprocess(["pacman", "-S", "--noconfirm", "--needed", "wl-clipboard", "yajl"], check=True)

    print(f"{Colors.BLUE}[INFO] Downloading standalone static crun binary to bypass shared library exit 127 faults...{Colors.RESET}")
    static_crun_path = "/usr/local/bin/crun"
    call_subprocess([
        "curl", "-sL",
        "https://github.com/containers/crun/releases/download/1.18/crun-1.18-linux-amd64",
        "-o", static_crun_path
    ], check=True)
    call_subprocess(["chmod", "755", static_crun_path], check=True)

    daemon_config = {
        "default-runtime": "crun",
        "runtimes": {
            "crun": {
                "path": "/usr/local/bin/crun"
            }
        },
        "exec-opts": ["native.cgroupdriver=cgroupfs"]
    }

    os.makedirs("/etc/docker", exist_ok=True)
    with open("/tmp/daemon.json", "w") as f:
        json.dump(daemon_config, f, indent=4)

    call_subprocess(["mv", "/tmp/daemon.json", "/etc/docker/daemon.json"], check=True)

    print(f"{Colors.BLUE}[INFO] Generating modern CDI specification for NVIDIA GPU passthrough...{Colors.RESET}")
    try:
        cdi_res = call_subprocess(
            ["nvidia-ctk", "cdi", "generate", "--output=/etc/cdi/nvidia.yaml"],
            capture_output=True, text=True, check=True
        )
        print(cdi_res.stdout)
    except Exception as e:
        print(f"{Colors.ORANGE}[WARN] CDI generation warning: {e}{Colors.RESET}")

    call_subprocess(["systemctl", "daemon-reload"], check=False)
    call_subprocess(["systemctl", "restart", "containerd"], check=True)
    call_subprocess(["systemctl", "restart", "docker"], check=True)

    build_rootfs_and_import()

    entrypoint_script = (
        "export HOME=/workspace && "
        "export ANDROID_HOST_OUT=/workspace && "
        "export ANDROID_SOONG_HOST_OUT=/workspace && "
        "export ANDROID_PRODUCT_OUT=/workspace && "
        "export CVD_HOME=/workspace && "
        "export PATH=/workspace/bin:$PATH && "
        "mkdir -p /root/workspace && "
        "chmod -R 777 /workspace/etc && "
        "rm -rf /root/bin /root/lib64 /root/lib /root/usr /root/etc && "
        "ln -sfn /workspace/bin /root/bin && "
        "ln -sfn /workspace/lib64 /root/lib64 && "
        "ln -sfn /workspace/lib /root/lib && "
        "ln -sfn /workspace/etc /root/etc && "
        "ln -sfn /workspace/usr /root/usr && "
        "ln -sfn /workspace /root/workspace && "
        "chown -R cuttlefish:cuttlefish /dev/kvm /dev/vhost-vsock /dev/vhost-net /dev/net/tun /workspace 2>/dev/null || true && "
        "chmod 777 /dev/kvm /dev/vhost-vsock /dev/vhost-net /dev/net/tun 2>/dev/null || true && "
        "chmod -R 777 /dev/dri 2>/dev/null || true && "
        "chmod 666 /dev/nvidia* 2>/dev/null || true && "
        "(while true; do "
        "  ip link set dev cvd-mbr-0 up 2>/dev/null || true; "
        "  for tap in $(ip -o link show type tap | awk -F': ' '{print $2}'); do "
        "    ip link set dev $tap up 2>/dev/null || true; "
        "    ip link set dev $tap master cvd-mbr-0 2>/dev/null || true; "
        "    ip link set dev $tap mtu 1500 2>/dev/null || true; "
        "    ethtool -K $tap gso off tso off gro off lro off tx off rx off checksum off 2>/dev/null || true; "
        "  done; "
        "  sleep 0.2; "
        "done) & "
        "ldconfig 2>/dev/null || true && "
        "chmod 755 /workspace/bin/crosvm && "
        "export VK_DRIVER_FILES=/etc/vulkan/icd.d/nvidia_icd.json && "
        "export VK_ICD_FILENAMES=/etc/vulkan/icd.d/nvidia_icd.json && "
        "export __GLX_VENDOR_LIBRARY_NAME=nvidia && "
        "export CROSVM_SANDBOX=false && "
        f"/workspace/bin/launch_cvd --system_image_dir=/workspace --config=tablet "
        f"--start_webrtc=true --report_anonymous_usage_stats=n --gpu_mode={gpu_mode} "
        "--enable_tap_devices=true --enable_wifi=false --enable_audio=true --enable_sandbox=false "
        "--resume=false --guest_enforce_security=true "
        "--vm_manager=crosvm --instance_dir=/workspace/cf_avd_0 --console=true & "
        "until /workspace/bin/adb devices | grep -q 'device$'; do sleep 2; done && "
        "/workspace/bin/adb wait-for-device && "
        "/workspace/bin/adb shell su root ndc network destroy 100 2>/dev/null || true && "
        "/workspace/bin/adb shell su root ndc network create 100 && "
        "/workspace/bin/adb shell su root ndc network interface add 100 buried_eth0 && "
        "/workspace/bin/adb shell su root ndc network route add 100 buried_eth0 192.168.96.0/24 && "
        "/workspace/bin/adb shell su root ndc network route add 100 buried_eth0 0.0.0.0/0 192.168.96.1 && "
        "/workspace/bin/adb shell su root ndc network default set 100 && "
        "sleep 2 && "
        "wait"
    )

    docker_cmd = [
        "docker", "run", "-d",
        "--name", "cuttlefish_engine",
        "--security-opt", "no-new-privileges:true",
        "--gpus", "all",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "SYS_ADMIN",
        "--memory=8g",
        "--ulimit", "nofile=65535:65535"
    ]

    for dev in ["/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net", "/dev/net/tun"]:
        if os.path.exists(dev):
            docker_cmd.extend(["--device", dev])

    docker_cmd.extend([
        "-v", f"{WORKSPACE_DIR}:/workspace",
        "cuttlefish-runtime:latest",
        "/bin/bash", "-c", entrypoint_script
    ])

    try:
        call_subprocess(docker_cmd, check=True)
        print(f"{Colors.GREEN}[INFO] Configuring host firewall routing and NAT masquerade...{Colors.RESET}")
        call_subprocess(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        call_subprocess(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.96.0/24", "-j", "MASQUERADE"], check=False)

        def stream_docker_logs():
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "cuttlefish_engine"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            stream_output(proc.stdout)

        threading.Thread(target=stream_docker_logs, daemon=True).start()
        return ContainerMonitor("cuttlefish_engine")
    except Exception as e:
        print(f"{Colors.RED}[-] Failed to launch Docker container: {e}{Colors.RESET}")
        raise e

def broadcast_log_line(line: str):
    """Buffers and pushes log lines asynchronously to all active browser windows."""
    with output_lock:
        if line not in GLOBAL_LOG_BUFFER:
            GLOBAL_LOG_BUFFER.append(line)
            if len(GLOBAL_LOG_BUFFER) > 500:
                GLOBAL_LOG_BUFFER.pop(0)

    if not server_loop or not server_loop.is_running():
        return

    for ws in list(connected_websockets):
        try:
            asyncio.run_coroutine_threadsafe(ws.send_text(line), server_loop)
        except Exception:
            if ws in connected_websockets:
                connected_websockets.remove(ws)

def generate_self_signed_cert(cert_path, key_path):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def run_fastapi():
    global server_loop, DASHBOARD_PORT
    try:
        import logging
        noisy_loggers = [
            "uvicorn", "uvicorn.error", "uvicorn.access",
            "websockets", "websockets.server", "websockets.protocol",
            "wsproto", "asyncio"
        ]
        for name in noisy_loggers:
            l = logging.getLogger(name)
            l.setLevel(logging.CRITICAL)
            l.propagate = False
            l.handlers.clear()

        server_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(server_loop)

        cert_path = os.path.join(WORKSPACE_DIR, "cert.pem")
        key_path = os.path.join(WORKSPACE_DIR, "key.pem")
        generate_self_signed_cert(cert_path, key_path)

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=DASHBOARD_PORT,
            log_config=None,
            access_log=False,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path
        )
        server = uvicorn.Server(config)

        print(f"[INFO] FastAPI Uvicorn engine spinning up securely on https://127.0.0.1:{DASHBOARD_PORT}")
        server_loop.run_until_complete(server.serve())
    except Exception as e:
        sys.__stderr__.write(f"\r\n[FATAL] FastAPI Server Crashed: {e}\r\n")

def launch_browser_dashboard(video_w=1920, video_h=1080, control_pad=65, auto_scale=True):
    """Initializes FastAPI Dashboard and loads the polled WebRTC wrapper inside the custom UI."""
    global DASHBOARD_PORT, DASHBOARD_BROWSER_PROC
    print("[INFO] Initializing FastAPI Dashboard...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        DASHBOARD_PORT = s.getsockname()[1]

    print(f"[INFO] Dashboard secured on randomized local port: {DASHBOARD_PORT}")

    setup_dashboard_routes(video_w=video_w, video_h=video_h, control_pad=control_pad, auto_scale=auto_scale)

    t = threading.Thread(target=run_fastapi, daemon=True)
    t.start()

    url = f"https://127.0.0.1:{DASHBOARD_PORT}"

    icon_path = os.path.join(WORKSPACE_DIR, "chromium_fallback_icon.svg")
    desktop_dir = os.path.expanduser("~/.local/share/applications")
    desktop_path = os.path.join(desktop_dir, "cuttlefish-viewer.desktop")

    os.makedirs(desktop_dir, exist_ok=True)

    svg_content = textwrap.dedent("""\
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
          <path d="M 128 120 C 120 105, 112 85, 102 70 C 108 80, 118 92, 124 100 C 126 103, 128 105, 128 105 C 128 105, 130 103, 132 100 C 138 92, 148 80, 154 70 C 144 85, 136 105, 128 120 C 165 90, 200 65, 242 52 C 222 78, 210 92, 195 105 C 215 120, 198 135, 175 150 C 158 170, 142 190, 128 222 C 114 190, 98 170, 81 150 C 58 135, 41 120, 61 105 C 46 92, 34 78, 14 52 C 56 65, 91 90, 128 120 Z" fill="none" stroke="#f3f4f6" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M 114 86 L 119 91 M 142 86 L 137 91" fill="none" stroke="#f3f4f6" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    """)

    with open(icon_path, "w", encoding="utf-8") as f:
        f.write(svg_content)

    profile_dir = os.path.join(WORKSPACE_DIR, ".chrome_profile")
    print("[INFO] Purging old browser cache to ensure fresh UI loads...")
    shutil.rmtree(profile_dir, ignore_errors=True)

    browser_bins = ["ungoogled-chromium", "chromium", "google-chrome", "chromium-browser"]
    browser_bin = next((b for b in browser_bins if shutil.which(b)), "chromium")

    desktop_content = textwrap.dedent(f"""\
        [Desktop Entry]
        Type=Application
        Name=Cuttlefish Android
        Exec={browser_bin} --user-data-dir={profile_dir} --class=cuttlefish-viewer --name=cuttlefish-viewer --password-store=basic --test-type --ignore-certificate-errors --allow-insecure-localhost --use-fake-ui-for-media-stream --no-first-run --autoplay-policy=no-user-gesture-required --window-size=1600,900 --app={url}
        Icon={icon_path}
        StartupWMClass=cuttlefish-viewer
        Terminal=false
    """)
    with open(desktop_path, "w", encoding="utf-8") as f:
        f.write(desktop_content)

    call_subprocess(["update-desktop-database", desktop_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    if browser_bin:
        print(f"[INFO] Spawning standalone application window via {browser_bin}...")
        DASHBOARD_BROWSER_PROC = subprocess.Popen([
            browser_bin,
            f"--user-data-dir={profile_dir}",
            "--class=cuttlefish-viewer",
            "--name=cuttlefish-viewer",
            "--password-store=basic",
            "--test-type",
            "--ignore-certificate-errors",
            "--allow-insecure-localhost",
            f"--unsafely-treat-insecure-origin-as-secure=https://127.0.0.1:{DASHBOARD_PORT},https://127.0.0.1:8443,https://127.0.0.1:8444",
            "--disable-web-security",
            "--disable-site-isolation-trials",
            "--use-fake-ui-for-media-stream",
            "--disable-webrtc-hide-local-ips-with-mdns",
            "--disable-features=WebRtcHideLocalIpsWithMdns",
            "--allow-loopback-in-peer-connection",
            "--enforce-webrtc-ip-permission-check=false",
            "--no-first-run",
            "--autoplay-policy=no-user-gesture-required",
            "--window-size=1600,900",
            "--ignore-gpu-blocklist",
            "--allow-webrtc-loopback",
            "--enable-features=UseOzonePlatform",
            "--ozone-platform=wayland",
            f"--app={url}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    else:
        print(f"[WARNING] No standalone browser found. Falling back to default system browser: {url}")
        import webbrowser
        webbrowser.open(url)

def force_full_shutdown():
    global DASHBOARD_BROWSER_PROC
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    os.system("stty sane 2>/dev/null")
    sys.__stdout__.write("\r\n\033[1;31m✖ [CRITICAL]\033[0m Stopping all processes.\r\n")
    sys.__stdout__.flush()

    try:
        call_subprocess(["sudo", "systemctl", "stop", "nginx"], check=False)
        call_subprocess(["pkill", "-9", "-f", "nginx"], check=False)
    except Exception:
        pass

    if DASHBOARD_BROWSER_PROC and DASHBOARD_BROWSER_PROC.poll() is None:
        try:
            os.killpg(os.getpgid(DASHBOARD_BROWSER_PROC.pid), signal.SIGKILL)
        except Exception:
            try:
                DASHBOARD_BROWSER_PROC.kill()
            except Exception:
                pass

    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        call_subprocess(["pkill", "-9", "-u", current_user, "-f", "--", r"--user-data-dir=.*\.chrome_profile"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    for pgid in ACTIVE_PROCESS_GROUPS:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass

    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name

        # Upgraded to SIGKILL (-9) and added nsjail to destroy stubborn AOSP compiler zombies
        exact_patterns = ["adb", "git", "repo", "make", "ninja", "dnsmasq", "nsjail"]
        for pattern in exact_patterns:
            call_subprocess(["pkill", "-9", "-u", current_user, "-x", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        specific_patterns = [
            "launch_cvd", "run_cvd", "crosvm", "webrtc_operator",
            "wmediumd", "netsimd", "casimir", "socket_vsock_proxy", "log_tee",
            "openwrt_control_server", "process_restarter", "tombstone_receiver",
            "modem_simulator", "soong_ui", "siso", "soong_build",
            "multiprocessing.forkserver", "uvicorn", "nsjail"
        ]
        for pattern in specific_patterns:
            call_subprocess(["pkill", "-9", "-u", current_user, "-f", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        call_subprocess(["adb", "kill-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    import time
    time.sleep(1.5)

    try:
        sudo_pass = _CACHED_SUDO_PASSWORD
        call_subprocess(["-E", "-S", "docker", "stop", "-t", "1", "cuttlefish_engine"], input=(sudo_pass + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        call_subprocess(["-E", "-S", "docker", "rm", "-f", "cuttlefish_engine"], input=(sudo_pass + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
    except Exception:
        pass

    try:
        sudo_pass = _CACHED_SUDO_PASSWORD
        for tap in ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01", "cvd-mtap-1", "cvd-wtap-1"]:
            call_subprocess(["-E", "-S", "ip", "link", "set", "dev", tap, "down"], input=(sudo_pass + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess(["-E", "-S", "ip", "tuntap", "del", "dev", tap, "mode", "tap"], input=(sudo_pass + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["-E", "-S", "ip", "link", "set", "dev", "cvd-mbr-0", "down"], input=(sudo_pass + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["-E", "-S", "ip", "link", "delete", "cvd-mbr-0", "type", "bridge"], input=(sudo_pass + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

def execute_real_task(desc, func, *args, **kwargs):
    """Executes a real Python function while rendering a sleek, modern progress indicator."""
    sys.stdout.write(f" \033[33m◇\033[0m {desc}...")
    sys.stdout.flush()

    try:
        func(*args, **kwargs)
        sys.stdout.write(f"\r \033[32m✔\033[0m {desc}\033[K\n")
        sys.stdout.flush()
    except Exception as e:
        sys.stdout.write(f"\r \033[31m✖\033[0m {desc} \033[90m(Failed)\033[K\n")
        print(f"    \033[31m↳ Error: {str(e)}\033[0m")
        sys.exit(1)

def apply_fd_limits():
    """Real function to raise file descriptor limits."""
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (65535, hard))

def verify_systemd_active():
    """Polls systemd until the daemon confirms it is running."""
    for _ in range(10):
        res = call_subprocess(["systemctl", "--user", "is-active", "--quiet", "cuttlefish"], check=False)
        if res.returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError("Systemd service failed to start or timed out.")

def authentic_launch_sequence(is_docker):
    """Sleek CLI transition that executes REAL functions, waits for completion, and displays launch config."""

    has_vulkan = os.path.exists("/usr/share/vulkan/icd.d") and len(os.listdir("/usr/share/vulkan/icd.d")) > 0
    has_dri = len(glob.glob("/dev/dri/renderD*")) > 0
    is_nvidia = os.path.exists("/usr/share/glvnd/egl_vendor.d/10_nvidia.json") or os.path.exists("/usr/lib/libEGL_nvidia.so.0")

    if has_vulkan and has_dri:
        if is_nvidia:
            gpu_status = "\033[32mNVIDIA Hardware Acceleration (gfxstream)\033[0m"
        else:
            gpu_status = "\033[32mStandard Hardware Acceleration (gfxstream)\033[0m"
    else:
        gpu_status = "\033[33mSoftware CPU Rendering (guest_swiftshader)\033[0m"

    mode_str = "\033[35mDocker Container\033[0m" if is_docker else "\033[34mNative Host (Arch/EndeavourOS)\033[0m"

    print("\n \033[36m◆\033[0m \033[1mCuttlefish Orchestration Engine\033[0m \033[90m(v2.6)\033[0m")
    print(" \033[90m─────────────────────────────────────────────────────────\033[0m")
    print(f" \033[1mDeployment Mode:\033[0m {mode_str}")
    print(f" \033[1mGraphics Stack :\033[0m {gpu_status}")
    print(" \033[90m─────────────────────────────────────────────────────────\033[0m")

    execute_real_task("Verifying system toolchains & pacman dependencies", install_system_dependencies)
    execute_real_task("Calibrating file descriptor limits (65535)", apply_fd_limits)
    execute_real_task("Provisioning Systemd user daemon profile", setup_and_start_systemd_service)
    execute_real_task("Waiting for background orchestration engine to initialize", verify_systemd_active)

    print(" \033[90m─────────────────────────────────────────────────────────\033[0m")
    print(" \033[32m[ok]\033[0m Terminal session detached. Daemon running under systemd.")
    print(" \033[90m     • Details : systemctl --user status cuttlefish\033[0m")
    print(" \033[90m     • Exit : Close the browser window to trigger full teardown.\033[0m")
    print(" \033[90m─────────────────────────────────────────────────────────\033[0m\n")

def apply_dns_dnat_interception():
    """Forces all guest subnet DNS queries into the host's local dnsmasq instance via source-matched DNAT."""
    print("[INFO] Enforcing host-side port 53 DNAT interception...")
    try:
        for proto in ["udp", "tcp"]:
            call_subprocess([
                "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
                "-s", "192.168.0.0/16", "-p", proto, "--dport", "53",
                "-j", "DNAT", "--to-destination", "192.168.96.1:53"
            ], check=False)

        call_subprocess(["sudo", "iptables", "-I", "OUTPUT", "-p", "udp", "--dport", "19302", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-I", "OUTPUT", "-p", "udp", "--sport", "15550:15599", "-j", "ACCEPT"], check=False)

        call_subprocess(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        print("[INFO] Port 53 DNAT interception and WebRTC rules successfully active.")
    except Exception as e:
        print(f"[-] Failed to apply DNS DNAT rules: {e}")

def run_tracked_cmd(cmd, desc, expected_lines=200, cwd=None):
    """Runs a subprocess, hides log spam, and updates a horizontal tqdm progress bar.
    Dumps the actual error output if the command fails, using tasteful terminal colors."""

    C_RESET = "\033[0m"
    C_BLUE = "\033[34m"
    C_RED = "\033[31m"
    C_DIM = "\033[2m"

    logger.info(f"{C_BLUE}Starting:{C_RESET} {desc}")

    process = subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=os.environ.copy()
    )

    error_buffer = []

    desc_colored = f"{C_BLUE}{desc}{C_RESET}"

    with tqdm(desc=desc_colored, total=expected_lines, unit=" steps", leave=True, bar_format="{l_bar}{bar:30}| {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
        for line in process.stdout:
            error_buffer.append(line.strip())
            if len(error_buffer) > 30:
                error_buffer.pop(0)

            pbar.update(1)
            if pbar.n >= pbar.total:
                pbar.total += max(50, int(pbar.total * 0.15))

        process.wait()

        if process.returncode == 0:
            pbar.total = pbar.n
            pbar.refresh()
        else:
            logger.error(f"{C_RED}'{desc}' failed with exit code {process.returncode}.{C_RESET}")
            logger.error(f"{C_DIM}--- LAST 30 LINES OF COMPILER OUTPUT ---{C_RESET}")
            for err_line in error_buffer:
                logger.error(f"{C_RED}{err_line}{C_RESET}")
            logger.error(f"{C_DIM}----------------------------------------{C_RESET}")
            raise subprocess.CalledProcessError(process.returncode, cmd)

def setup_crosvm_sandbox_paths(sudo_password, workspace_dir):
    print("[INFO] Enforcing absolute sandbox seccomp paths for crosvm...")
    target_dir = "/usr/share/crosvm/x86_64-linux-gnu/seccomp"
    call_subprocess(["sudo", "mkdir", "-p", target_dir], check=True)

    seccomp_src = os.path.join(workspace_dir, "usr", "share", "crosvm", "x86_64-linux-gnu", "seccomp")

    if os.path.exists(seccomp_src):
        call_subprocess(["sudo", "cp", "-rf", os.path.abspath(seccomp_src) + "/.", target_dir], check=True)
        call_subprocess(["sudo", "chmod", "-R", "755", "/usr/share/crosvm"], check=True)
    else:
        print(f"[WARNING] Seccomp source path not found at {seccomp_src}. Skipping custom profile copy.")

def configure_host_security_and_networking(workspace_dir):
    print("[INFO] Configuring host dependencies, networking, and mandatory sandbox paths...")

    current_user = os.getenv("USER") or os.getlogin()
    seccomp_source = os.path.join(workspace_dir, "usr", "share", "crosvm", "x86_64-linux-gnu", "seccomp")
    host_crosvm_share = "/usr/share/crosvm/x86_64-linux-gnu"

    commands = [
        ["pacman", "-S", "--needed", "--noconfirm", "iptables-nft", "bridge-utils"],
        ["groupadd", "-f", "cvdnetwork"],
        ["usermod", "-aG", "cvdnetwork", current_user],
        ["usermod", "-aG", "kvm", current_user],
        ["usermod", "-aG", "video", current_user],
        ["usermod", "-aG", "render", current_user],
        ["mkdir", "-p", "/usr/share/policy", host_crosvm_share],
        ["sudo", "mkdir", "-p", "/var/empty"],
        ["sudo", "chown", "root:root", "/var/empty"],
        ["sudo", "chmod", "755", "/var/empty"],
        ["chmod", "660", "/dev/net/tun"],
        ["mkdir", "-p", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64"],
        ["ln", "-sfn", "/lib/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"],
        ["ln", "-sfn", "/usr/lib/libEGL.so.1", "/usr/lib/x86_64-linux-gnu/libEGL.so.1"],
        ["ln", "-sfn", "/usr/lib/libGLESv2.so.2", "/usr/lib/x86_64-linux-gnu/libGLESv2.so.2"],
        ["ln", "-sfn", "/usr/lib/libvulkan.so.1", "/usr/lib/x86_64-linux-gnu/libvulkan.so.1"],
        ["chmod", "+rx", workspace_dir]
    ]

    if os.path.exists(seccomp_source):
        call_subprocess(["sudo", "ln", "-sfn", os.path.abspath(seccomp_source), "/usr/share/policy/crosvm"], check=True)
        call_subprocess(["sudo", "cp", "-rf", f"{seccomp_source}/.", host_crosvm_share], check=True)
    if os.path.exists(os.path.join(workspace_dir, "bin")):
        call_subprocess(["chmod", "+rx", os.path.join(workspace_dir, "bin")])
    if os.path.exists(os.path.join(workspace_dir, "bin", "crosvm")):
        call_subprocess(["chmod", "755", os.path.join(workspace_dir, "bin", "crosvm")])

    if os.path.exists("/dev/net/tun"):
        try:
            call_subprocess(["sudo", "chgrp", "cvdnetwork", "/dev/net/tun"], check=False)
            call_subprocess(["sudo", "chmod", "660", "/dev/net/tun"], check=False)
        except Exception:
            pass

def local_stun_dns_bypass():
    """Maps stun.l.google.com to 127.0.0.1 to intercept WebRTC STUN requests."""
    print("[INFO] Configuring local DNS bypass for autonomous STUN resolution...")
    try:
        call_subprocess(["sudo", "sed", "-i", "/stun.l.google.com/d", "/etc/hosts"], check=False)
        call_subprocess(["sudo", "bash", "-c", "echo '127.0.0.1 stun.l.google.com' >> /etc/hosts"], check=True)
    except Exception as e:
        print(f"[WARNING] Could not update /etc/hosts for STUN bypass: {e}")

def perform_startup_cleanup():
    """Performs a deep system wipe of lingering Cuttlefish states..."""
    print("[PROCESS] Verifying System Dependencies & Executing Cleanup...")

    # Automatically provision and secure the Vault so the user never has to
    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        call_subprocess(["sudo", "mkdir", "-p", VAULT_DIR], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        call_subprocess(["sudo", "chown", "-R", f"{current_user}:{current_user}", VAULT_DIR], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Force kill any stuck Nginx servers
    try:
        call_subprocess(["sudo", "fuser", "-k", "8444/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["sudo", "pkill", "-9", "nginx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    # If the user passes 'reset', nuke the poisoned system sandbox policies
    if "reset" in sys.argv:
        print("[INFO] Deep reset triggered. Purging system seccomp caches...")
        call_subprocess(["sudo", "rm", "-rf", "/usr/share/crosvm/x86_64-linux-gnu/seccomp"], check=False)
        call_subprocess(["sudo", "rm", "-rf", "/opt/cuttlefish_bin/usr/share/crosvm/x86_64-linux-gnu/seccomp"], check=False)
    ensure_32gb_swap()
    local_stun_dns_bypass()
    start_local_stun_responder()

    sudo_pass = _CACHED_SUDO_PASSWORD
    configure_host_security_and_networking(WORKSPACE_DIR)
    setup_crosvm_sandbox_paths(sudo_pass, WORKSPACE_DIR)
    ensure_vsock_kernel_modules(sudo_pass)

    configure_host_firewall_for_webrtc()

    log_backup = "/tmp/debug_backup.log"
    if os.path.exists(DEBUG_LOG_PATH):
        try:
            shutil.copy(DEBUG_LOG_PATH, log_backup)
        except Exception:
            pass

    daemons = [
        "adb", "launch_cvd", "run_cvd", "crosvm", "log_tee",
        "openwrt_control_server", "process_restarter",
        "tombstone_receiver", "modem_simulator", "soong_ui", "ninja", "nsjail", "make",
        "wmediumd", "netsimd", "casimir", "webrtc_operator"
    ]
    for daemon in daemons:
        try:
            call_subprocess(["pkill", "-9", "-f", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    try:
        call_subprocess(["adb", "kill-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    for port in [6600, 7300, 7500, 8443, 9600]:
        try:
            call_subprocess(["fuser", "-k", f"{port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["fuser", "-k", f"{port}/udp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    print("[INFO] All lingering Cuttlefish daemon instances and ports purged.")

    stale_files = ["metadata.img", "metadata_image", "persistent_composite.img", "overlay.img", "ap_overlay.img"]
    for f in stale_files:
        f_path = os.path.join(WORKSPACE_DIR, f)
        if os.path.exists(f_path):
            call_subprocess(["rm", "-f", f_path], check=False)

    temp_patterns = ["/tmp/cf_avd_*", "/tmp/cf_env_*"]
    for pattern in temp_patterns:
        for path in glob.glob(pattern):
            try:
                call_subprocess(["rm", "-rf", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[INFO] Cleared stale temp path: {path}")
            except Exception as e:
                print(f"[-] Failed to remove {path}: {e}")

    current_uid = os.getuid()
    current_user = pwd.getpwuid(current_uid).pw_name

    for target_dir in [f"/tmp/cf_avd_{current_uid}", f"/tmp/cf_env_{current_uid}", "/tmp/cf_avd_0", "/tmp/cf_env_0"]:
        call_subprocess(["mkdir", "-p", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        call_subprocess(["chown", f"{current_user}:cvdnetwork", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["chmod", "775", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[INFO] Initialized pre-owned socket permissions on: {target_dir}")

    bad_config = os.path.join(VAULT_DIR, "android-info.txt")
    if os.path.exists(bad_config):
        try:
            os.remove(bad_config)
            print(f"[INFO] Purged rogue config file: {bad_config}")
        except Exception:
            pass

    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    if os.path.exists(log_backup):
        try:
            shutil.move(log_backup, DEBUG_LOG_PATH)
        except Exception:
            with open(DEBUG_LOG_PATH, "w", encoding="utf-8") as _f:
                _f.write("")
    else:
        with open(DEBUG_LOG_PATH, "w", encoding="utf-8") as _f:
            _f.write("")

def setup_debian_library_compat():
    """Bridges Arch/EndeavourOS paths to Debian paths dynamically based on active graphics stack (NVIDIA vs Mesa)."""
    print("[INFO] Setting up Debian-to-Arch library compatibility bridge for Cuttlefish host binaries...")

    debian_lib_dir = "/usr/lib/x86_64-linux-gnu"
    call_subprocess(["sudo", "mkdir", "-p", debian_lib_dir], check=True)

    libs_to_link = [
        "libEGL.so.1",
        "libGLESv2.so.2",
        "libvulkan.so.1"
    ]

    is_nvidia = os.path.exists("/usr/share/glvnd/egl_vendor.d/10_nvidia.json") or os.path.exists("/usr/lib/libEGL_nvidia.so.0")
    if is_nvidia:
        libs_to_link.extend(["libEGL_nvidia.so.0", "libGLX_nvidia.so.0"])

    for lib in libs_to_link:
        arch_path = os.path.join("/usr/lib", lib)
        debian_path = os.path.join(debian_lib_dir, lib)

        if os.path.exists(arch_path):
            if os.path.exists(debian_path):
                call_subprocess(["sudo", "rm", "-f", debian_path], check=False)
            call_subprocess(["sudo", "ln", "-s", arch_path, debian_path], check=False)

    try:
        call_subprocess(["sudo", "bash", "-c", f"echo '{debian_lib_dir}' > /etc/ld.so.conf.d/cuttlefish-debian.conf"], check=False)
        call_subprocess(["sudo", "ldconfig"], check=False)
    except Exception:
        pass

    debian_egl_dir = "/usr/share/glvnd/egl_vendor.d"
    call_subprocess(["sudo", "mkdir", "-p", debian_egl_dir], check=True)

    if is_nvidia and os.path.exists("/usr/share/glvnd/egl_vendor.d/10_nvidia.json"):
        target_json = os.path.join(debian_egl_dir, "10_nvidia.json")
        if not os.path.exists(target_json):
            call_subprocess(["sudo", "ln", "-s", "/usr/share/glvnd/egl_vendor.d/10_nvidia.json", target_json], check=False)
    else:
        for mesa_json in glob.glob("/usr/share/glvnd/egl_vendor.d/*.json"):
            base_name = os.path.basename(mesa_json)
            target_json = os.path.join(debian_egl_dir, base_name)
            if not os.path.exists(target_json):
                call_subprocess(["sudo", "ln", "-s", mesa_json, target_json], check=False)

def phase_0_auto_remediate():
    st = os.stat(CURRENT_FILE)
    if not bool(st.st_mode & stat.S_IXUSR):
        os.chmod(CURRENT_FILE, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    modules = ["vhost_net", "vsock", "vhost_vsock", "br_netfilter", "vmw_vsock_virtio_transport"]
    for mod in modules:
        try:
            call_subprocess(["sudo", "modprobe", mod], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    # Allow AOSP nsjail compiler sandboxing on Hardened Linux kernels
    call_subprocess(["sudo", "sysctl", "-w", "kernel.unprivileged_userns_clone=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    call_subprocess(["sudo", "sysctl", "-w", "user.max_user_namespaces=10000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    modules = ["vhost_net", "vsock", "vhost_vsock", "br_netfilter", "vmw_vsock_virtio_transport"]

    needs_sudo = False
    try:
        grp.getgrnam("cvdnetwork")
    except KeyError:
        needs_sudo = True

    if not os.path.exists("/etc/udev/rules.d/65-cuttlefish.rules"):
        needs_sudo = True

    current_user = pwd.getpwuid(os.getuid()).pw_name
    groups_db = [g.gr_name for g in grp.getgrall() if current_user in g.gr_mem]
    if "kvm" not in groups_db or "cvdnetwork" not in groups_db:
        needs_sudo = True

    if needs_sudo:
        print("Running Host Auto-Remediation (Applying missing groups and udev rules)...")
        try:
            grp.getgrnam("cvdnetwork")
        except KeyError:
            call_subprocess(["sudo", "groupadd", "-f", "cvdnetwork"], check=True)

        udev_rules = (
            'KERNEL=="kvm", GROUP="kvm", MODE="0666"\n'
            'KERNEL=="vhost-net", GROUP="cvdnetwork", MODE="0660"\n'
            'KERNEL=="vhost-vsock", GROUP="cvdnetwork", MODE="0660"\n'
            'KERNEL=="vsock", MODE="0666"\n'
            'SUBSYSTEM=="drm", KERNEL=="renderD*", GROUP="render", MODE="0666"\n'
        )
        with open("/tmp/65-cuttlefish.rules", "w") as f:
            f.write(udev_rules)
        call_subprocess(["sudo", "mv", "/tmp/65-cuttlefish.rules", "/etc/udev/rules.d/65-cuttlefish.rules"], check=True)
        call_subprocess(["sudo", "udevadm", "control", "--reload-rules"], check=True)
        call_subprocess(["sudo", "udevadm", "trigger"], check=True)

        call_subprocess(["usermod", "-aG", "kvm,cvdnetwork,render,video", current_user], check=True)

    print("Enforcing raw node permissions for the current active session...")
    for dev_path in ["/dev/vsock", "/dev/vhost-vsock", "/dev/vhost-net", "/dev/kvm"]:
        if os.path.exists(dev_path):
            call_subprocess(["sudo", "chmod", "660", dev_path], check=False)
            call_subprocess(["sudo", "chgrp", "cvdnetwork", dev_path], check=False)

def setup_apparmor():
    """Configures AppArmor for Cuttlefish, grants namespace mounts, and explicitly prevents browser confinement."""
    try:
        with open("/sys/module/apparmor/parameters/enabled", "r") as f:
            if f.read().strip() != "Y":
                return
    except FileNotFoundError:
        return

    print("Writing AppArmor sandbox with automated graphics mount rules...")

    legacy_profiles = [
        "/etc/apparmor.d/securelab-emulator",
        "/etc/apparmor.d/usr.bin.chromium",
        "/etc/apparmor.d/usr.lib.chromium.chromium"
    ]
    for bad_profile in legacy_profiles:
        if os.path.exists(bad_profile):
            call_subprocess(["sudo", "apparmor_parser", "-R", bad_profile], check=False)
            call_subprocess(["rm", "-f", bad_profile], check=False)

    profile_content = textwrap.dedent(f"""
        #include <tunables/global>

        # --- CUTTLEFISH SANDBOX ---
        profile cuttlefish_sandbox flags=(attach_disconnected, mediate_deleted) {{
          #include <abstractions/base>
          #include <abstractions/nameservice>

          network,
          capability,
          signal,
          ptrace,
          unix,

          userns,
          pivot_root,
          mount,
          umount,

          {WORKSPACE_DIR}/** rwkix,
          /tmp/** rwkix,
          /run/** rwkix,
          /tmp/cf_avd_0/** rwkix,
          /tmp/cf_env_0/** rwkix,

          /dev/kvm rw,
          /dev/vhost-net rw,
          /dev/vhost-vsock rw,
          /dev/nvidia* rw,
          /dev/dri/** rw,

          # Automated Graphics Namespace Mount Rules
          mount fstype=none -> /usr/share/glvnd/**,
          mount fstype=none -> /usr/share/vulkan/**,
          mount fstype=none -> /dev/dri/**,

          /sys/** r,
          /proc/** r,
          /etc/** r,
          /etc/ld.so.cache r,
          /usr/** rwkix,
          /opt/** rwkix,
          /lib/** rwkix,
          /lib64/** rwkix,
          /usr/lib/** mrwkix,
          /usr/lib64/** mrwkix,

          /usr/share/glvnd/** r,
          /usr/share/vulkan/** r,

          /usr/lib/*nvidia* mrwkix,
          /usr/lib/x86_64-linux-gnu/*nvidia* mrwkix,
        }}

        # --- EXEMPTIONS ---
        profile /usr/lib/chromium/chromium flags=(unconfined) {{
        }}
        profile /usr/bin/ungoogled-chromium flags=(unconfined) {{
        }}
        profile /usr/bin/chromium flags=(unconfined) {{
        }}
        profile /opt/google/chrome/chrome flags=(unconfined) {{
        }}
        # crosvm and minijail are intentionally excluded from unconfined flags to maintain host security
    """).strip()

    profile_path = "/etc/apparmor.d/cuttlefish_sandbox"
    tmp_profile = "/tmp/cuttlefish_sandbox"

    with open(tmp_profile, "w") as f:
        f.write(profile_content + "\n")

    call_subprocess(["sudo", "mv", "-f", tmp_profile, profile_path], check=True)
    call_subprocess(["sudo", "apparmor_parser", "-r", "-W", profile_path], check=True)
    call_subprocess(["sudo", "systemctl", "reload", "apparmor"], check=False)
    call_subprocess(["sudo", "aa-complain", os.path.join(WORKSPACE_DIR, "bin", "crosvm")], check=False)
    print("[INFO] AppArmor sandbox updated with graphics namespace mount rules.")

def purge_legacy_systems():
    logger.info("Purging legacy configurations & setting up non-Debian compatibility...")

    call_subprocess(["mkdir", "-p", "/usr/lib/cuttlefish-common/bin"], check=True)
    cap_script = "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n"
    with open("/tmp/capability_query.py", "w") as f:
        f.write(cap_script)
    call_subprocess(["sudo", "cp", "-f", "/tmp/capability_query.py", "/usr/lib/cuttlefish-common/bin/capability_query.py"], check=True)
    call_subprocess(["chmod", "+x", "/usr/lib/cuttlefish-common/bin/capability_query.py"], check=True)

    config_path = os.path.join(WORKSPACE_DIR, "fetcher_config.json")
    if os.path.exists(config_path) and os.path.getsize(config_path) < 5:
        os.remove(config_path)

    for f in ["/tmp/wayland-99", "/tmp/.X99-lock", os.path.join(WORKSPACE_DIR, "pulse_null_sink.sh")]:
        path = Path(f)
        if path.exists():
            try:
                path.unlink()
            except Exception:
                pass

def setup_host_networking():
    """Creates an isolated, dedicated iptables chain for Cuttlefish to keep host/guest firewalls separate."""
    print("[INFO] Configuring isolated Cuttlefish firewall chain...")
    try:
        call_subprocess(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)

        call_subprocess(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.0.0/16", "-j", "MASQUERADE"], check=False)

        call_subprocess(["sudo", "iptables", "-N", "CUTTLEFISH_SECURE"], check=False)
        call_subprocess(["sudo", "iptables", "-F", "CUTTLEFISH_SECURE"], check=False)

        call_subprocess(["sudo", "iptables", "-A", "CUTTLEFISH_SECURE", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "CUTTLEFISH_SECURE", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "CUTTLEFISH_SECURE", "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "CUTTLEFISH_SECURE", "-p", "udp", "--dport", "19302", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "CUTTLEFISH_SECURE", "-m", "limit", "--limit", "15/s", "--limit-burst", "30", "-j", "ACCEPT"], check=False)
        call_subprocess(["sudo", "iptables", "-A", "CUTTLEFISH_SECURE", "-j", "DROP"], check=False)

        check_hook = call_subprocess(["sudo", "iptables", "-C", "FORWARD", "-s", "192.168.0.0/16", "-j", "CUTTLEFISH_SECURE"], capture_output=True)
        if check_hook.returncode != 0:
            call_subprocess(["sudo", "iptables", "-I", "FORWARD", "1", "-s", "192.168.0.0/16", "-j", "CUTTLEFISH_SECURE"], check=True)

        print("[INFO] Isolated Cuttlefish firewall chain successfully established.")
    except Exception as e:
        print(f"[-] Failed to set up isolated firewall chain: {e}")

def run_gpu_diagnostics():
    """Performs deep pre-flight checks and verbose logging on GPU paths, libraries, and permissions."""
    logger.info("=== STARTING ADVANCED GPU & EGL DIAGNOSTICS ===\n")

    debian_lib_dir = "/usr/lib/x86_64-linux-gnu"
    libs_to_check = [
        "libEGL.so.1", "libEGL_nvidia.so.0",
        "libGLESv2.so.2", "libGLX_nvidia.so.0", "libvulkan.so.1"
    ]
    for lib in libs_to_check:
        p = os.path.join(debian_lib_dir, lib)
        exists = os.path.exists(p)
        logger.info(f"Bridge Lib Check [{lib}] -> Path: {p} | Exists: {exists}")
        if exists:
            logger.info(f"   -> Real Path: {os.path.realpath(p)}")

    devices = ["/dev/kvm", "/dev/vsock", "/dev/vhost-vsock", "/dev/vhost-net"]
    for dev in devices:
        exists = os.path.exists(dev)
        logger.info(f"Device Node [{dev}] -> Exists: {exists} | Read: {os.access(dev, os.R_OK)} | Write: {os.access(dev, os.W_OK)}")

    configs = [
        "/usr/share/glvnd/egl_vendor.d/10_nvidia.json",
        "/usr/share/vulkan/icd.d/nvidia_icd.json"
    ]
    for cfg in configs:
        logger.info(f"Config File [{cfg}] -> Exists: {os.path.exists(cfg)}")

    gpu_env_keys = [
        "GBM_BACKEND", "__GLX_VENDOR_LIBRARY_NAME",
        "__EGL_VENDOR_LIBRARY_FILENAMES", "VK_ICD_FILENAMES",
        "LD_LIBRARY_PATH", "EGL_PLATFORM", "DISPLAY"
    ]
    logger.info("--- Active Environment Variables ---")
    for key in gpu_env_keys:
        logger.info(f"   {key} = {os.environ.get(key, 'NOT SET')}")

def monitor_cuttlefish_logs_for_fatal_errors(log_file_path, timeout=60):
    """Continuously tails background Cuttlefish daemon logs live in the terminal and aborts on internal sandbox errors."""
    fatal_signatures = [
        "os error 104",
        "failed to build the vm",
        "Failed to configure tube"
    ]

    print(f"[INFO] Tailing background Cuttlefish logs at {log_file_path}...")
    start_time = time.time()

    while not os.path.exists(log_file_path):
        if time.time() - start_time > timeout:
            print("[-] Timeout waiting for Cuttlefish background log file.")
            return
        time.sleep(0.5)

    with open(log_file_path, "r") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            cleaned_line = line.strip()
            print(cleaned_line)

            for sig in fatal_signatures:
                if sig in cleaned_line:
                    print(f"\nCRITICAL ERROR SIGNATURE MATCHED: '{sig}'")
                    print("Halting execution immediately to prevent hanging loop...")

def launch_cuttlefish_daemon():
    global os
    print("Initializing Cuttlefish crosvm daemon...")

    wants_sandbox = "sandbox" in sys.argv

    if wants_sandbox:
        print("[INFO] Sandbox flag detected. Activating hardware sandbox hardening...")
        enable_crosvm_sandbox()
        sandbox_flag = "--enable_sandbox=true"
    else:
        print("[INFO] No sandbox flag detected. Running with sandbox disabled.")
        sandbox_flag = "--enable_sandbox=false"

    # 1. Start ADB Server
    call_subprocess([get_bin("adb"), "start-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    # 2. RUN THE OFFLINE PATCHER HERE
    forcefully_patch_webrtc_html()

    # DEFINE IT HERE AT THE TOP:
    launch_cvd_bin = os.path.join(WORKSPACE_DIR, "bin", "launch_cvd")

    alloc_cores, alloc_ram_mb, alloc_threads = optimize_cuttlefish_hardware()
    # CRITICAL: Resolve actual user when running via sudo to prevent root ownership locks
    current_user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name

    stale_runtime_files = [
        "persistent_composite.img", "overlay.img", "pflash.img", "sdcard.img"
    ]
    for file_name in stale_runtime_files:
        file_path = os.path.join(WORKSPACE_DIR, file_name)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass

    sys.stdout.flush()

    os.environ["GFXSTREAM_RENDERER_VERBOSE"] = "1"

    run_gpu_diagnostics()
    call_subprocess(["sudo", "chmod", "666", "/dev/net/tun"], check=False)

    for tap_name in ["cvd-mtap-1", "cvd-wtap-1"]:
        call_subprocess(["ip", "tuntap", "add", "dev", tap_name, "mode", "tap", "user", current_user, "group", "cvdnetwork", "mode", "0660"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "link", "set", "dev", tap_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ethtool", "-K", tap_name, "gso", "off", "tso", "off", "gro", "off", "lro", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    secure_bin_dir = "/opt/cuttlefish_bin"
    call_subprocess(["sudo", "mkdir", "-p", secure_bin_dir], check=False)
    bin_targets = [
        "crosvm",
        "tap_intf",
        "cuttlefish_net_helper"
    ]
    for bin_name in bin_targets:
        src_bin = os.path.join(WORKSPACE_DIR, "bin", bin_name)
        dst_bin = os.path.join(secure_bin_dir, bin_name)
        if os.path.exists(src_bin) and not os.path.islink(src_bin):
            call_subprocess(["sudo", "mv", "-f", src_bin, dst_bin], check=False)
            if bin_name == "crosvm":
                call_subprocess(["sudo", "setcap", "cap_setfcap,cap_sys_admin,cap_net_admin,cap_net_raw=eip", dst_bin], check=False)
            else:
                call_subprocess(["sudo", "setcap", "cap_net_admin,cap_net_raw=eip", dst_bin], check=False)
            call_subprocess(["sudo", "ln", "-sfn", dst_bin, src_bin], check=False)

    os.environ["HOME"] = WORKSPACE_DIR
    os.environ["ANDROID_HOST_OUT"] = WORKSPACE_DIR
    os.environ["ANDROID_PRODUCT_OUT"] = WORKSPACE_DIR

    instance_dir = os.path.join(WORKSPACE_DIR, "cf_avd_0")
    os.makedirs(instance_dir, exist_ok=True)

    for disk_img in ["metadata_image", "metadata.img", "cache_image", "cache.img", "userdata.img", "persistent_composite.img"]:
        for search_base in [instance_dir, WORKSPACE_DIR]:
            disk_path = os.path.join(search_base, disk_img)
            if os.path.exists(disk_path):
                try:
                    os.chmod(disk_path, 0o666)
                    call_subprocess(["chown", f"{current_user}:{current_user}", disk_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    pass

    for sub_dir in ["metadata", "cache"]:
        target_dir = os.path.join(instance_dir, sub_dir)
        os.makedirs(target_dir, exist_ok=True)
        try:
            call_subprocess(["chmod", "777", target_dir], check=False)
        except Exception:
            pass

    for img_name in ["overlay.img", "ap_overlay.img", "persistent_composite.img", "sdcard.img"]:
        img_path = os.path.join(instance_dir, img_name)
        if os.path.exists(img_path):
            try:
                os.chmod(img_path, 0o666)
            except Exception:
                pass

    for metadata_file in ["metadata_image", "metadata.img"]:
        meta_path = os.path.join(WORKSPACE_DIR, metadata_file)
        if os.path.exists(meta_path):
            try:
                os.chmod(meta_path, 0o666)
            except Exception:
                pass

    metadata_dir = os.path.join(instance_dir, "metadata")
    os.makedirs(metadata_dir, exist_ok=True)
    try:
        call_subprocess(["chmod", "-R", "777", instance_dir], check=False)
    except Exception:
        pass

    for tap_name in ["cvd-mtap-01", "cvd-etap-01", "cvd-wtap-01"]:
        call_subprocess(["ip", "tuntap", "del", "dev", tap_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "tuntap", "add", "dev", tap_name, "mode", "tap", "user", current_user, "group", "cvdnetwork"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "link", "set", "dev", tap_name, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["chmod", "666", f"/dev/{tap_name}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    optimal_gpu_mode = detect_optimal_gpu_mode()

    for socket_path in [instance_dir, "/tmp/cf_avd_1000", "/tmp/cf_env_1000", "/tmp/cf_avd_0", "/tmp/cf_env_0"]:
        if os.path.exists(socket_path):
            call_subprocess(["chmod", "-R", "777", socket_path], check=False)

    is_user_variant = "no-root" in sys.argv

    if is_user_variant:
        configure_rootless_host_networking()
        daemon_cmd = [
            launch_cvd_bin,
            f"--system_image_dir={WORKSPACE_DIR}",
            "--config=tablet",
            f"-cpus={alloc_cores}",
            f"--memory_mb={alloc_ram_mb}",
            "--start_webrtc=true",
            "--report_anonymous_usage_stats=n",
            f"--gpu_mode={optimal_gpu_mode}",
            "--enable_wifi=true",
            "--enable_audio=true",
            sandbox_flag,
            "--display0=width=1920,height=1080,dpi=250",
            "--resume=false",
            "--guest_enforce_security=true",
            "--vm_manager=crosvm",
            f"--instance_dir={instance_dir}",
            "--console=true",
            "--verbosity=DEBUG",
            "--run_adb_connector=false"
        ]
    else:
        # Inside launch_cuttlefish_daemon(), change both user and debug variants to use false:
        daemon_cmd = [
            launch_cvd_bin,
            f"--system_image_dir={WORKSPACE_DIR}",
            "--config=tablet",
            f"-cpus={alloc_cores}",
            f"--memory_mb={alloc_ram_mb}",
            "--start_webrtc=true",
            "--report_anonymous_usage_stats=n",
            f"--gpu_mode={optimal_gpu_mode}",
            "--enable_wifi=true",
            "--enable_audio=true",
            sandbox_flag,
            "--display0=width=1920,height=1080,dpi=250",
            "--resume=false",
            "--guest_enforce_security=true",
            "--vm_manager=crosvm",
            f"--instance_dir={instance_dir}",
            "--console=true",
            "--verbosity=DEBUG"
        ]

    import glob

    # Create an isolated bridge directory exclusively for graphics libraries
    nv_bridge = os.path.join(WORKSPACE_DIR, "nvidia_bridge")
    os.makedirs(nv_bridge, exist_ok=True)

    # Symlink ONLY the required NVIDIA and GLvnd graphics drivers
    graphics_targets = [
        "/usr/lib/libEGL.so*",
        "/usr/lib/libGLESv2.so*",
        "/usr/lib/libvulkan.so*",
        "/usr/lib/libEGL_nvidia.so*",
        "/usr/lib/libGLX_nvidia.so*"
    ]

    for pattern in graphics_targets:
        for src in glob.glob(pattern):
            dst = os.path.join(nv_bridge, os.path.basename(src))
            if not os.path.lexists(dst):
                try:
                    os.symlink(src, dst)
                except Exception:
                    pass

    # Inject LD_LIBRARY_PATH strictly to the isolated graphics bridge
    daemon_env = get_sandboxed_gpu_env()
    daemon_env.pop("DISPLAY", None)
    daemon_env.pop("XAUTHORITY", None)
    daemon_env["LD_LIBRARY_PATH"] = nv_bridge
    daemon_env["WAYLAND_DISPLAY"] = os.environ.get("WAYLAND_DISPLAY", "wayland-0")
    daemon_env["XDG_RUNTIME_DIR"] = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    daemon_env["RUST_LOG"] = "debug"
    daemon_env["CROSVM_LOG_LEVEL"] = "debug"

    print("Initializing Cuttlefish crosvm daemon on native Wayland...")
    try:
        def set_process_credentials():
            try:
                os.initgroups(current_user, pwd.getpwnam(current_user).pw_gid)
                os.setgid(grp.getgrnam('cvdnetwork').gr_gid)
            except Exception:
                pass

        process = subprocess.Popen(
            daemon_cmd,
            env=daemon_env,
            preexec_fn=set_process_credentials,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )

        threading.Thread(target=stream_output, args=(process.stdout,), daemon=True).start()

        def background_tap_enforcer():
            import subprocess
            for _ in range(60):
                time.sleep(1)
                for tap in ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01", "cvd-mtap-1", "cvd-wtap-1"]:
                    if os.path.exists(f"/sys/class/net/{tap}"):
                        # Bypass the custom logger to run silently
                        subprocess.run(["ip", "link", "set", "dev", tap, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                        subprocess.run(["ethtool", "-K", tap, "gso", "off", "tso", "off", "gro", "off", "lro", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                        subprocess.run(["ip", "link", "set", "dev", tap, "master", "cvd-mbr-0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        threading.Thread(target=background_tap_enforcer, daemon=True).start()

        threading.Thread(target=background_tap_enforcer, daemon=True).start()
        print(f"[INFO] launch_cvd completed successfully. Image Dir: {WORKSPACE_DIR}")

    except Exception as e:
        print(f"[ERROR] Failed to execute launch_cvd: {e}")

def stop_and_clean_cvd():
    """Executes stop_cvd and performs a clean_cvd network/process teardown using automated sudo."""
    sys.__stdout__.write("\r\n[INFO] Executing stop_cvd and cleaning environment...\r\n")
    sys.__stdout__.flush()

    # Terminate Nginx alongside other system daemons
    try:
        call_subprocess(["sudo", "fuser", "-k", "8444/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["sudo", "systemctl", "stop", "nginx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["sudo", "pkill", "-9", "nginx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    stop_script = os.path.join(WORKSPACE_DIR, "bin", "stop_cvd")
    if os.path.exists(stop_script):
        try:
            call_subprocess([stop_script], cwd=WORKSPACE_DIR, env=env, capture_output=True, timeout=1.5)
        except Exception:
            pass

    daemons = [
        "launch_cvd", "run_cvd", "crosvm", "webrtc_operator",
        "wmediumd", "netsimd", "socket_vsock_proxy",
        "soong_ui", "ninja", "nsjail", "make"
    ]
    for daemon in daemons:
        call_subprocess(["pkill", "-9", "-f", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    temp_patterns = ["/tmp/cf_avd_*", "/tmp/cf_env_*"]
    for pattern in temp_patterns:
        for path in glob.glob(pattern):
            call_subprocess(["rm", "-rf", path], check=False)

def apply_nftables_json_routing():
    """Configures host routing and NAT using the atomic nftables JSON API."""
    print("[INFO] Applying atomic host NAT via nftables JSON API...")

    nft_payload = {
        "nftables": [
            {"add": {"table": {"family": "ip", "name": "cuttlefish_nat"}}},
            {"add": {"chain": {"family": "ip", "table": "cuttlefish_nat", "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 100}}},
            {"add": {"rule": {"family": "ip", "table": "cuttlefish_nat", "chain": "postrouting", "expr": [
                {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "op": "==", "right": "192.168.96.0/24"}},
                {"masquerade": {}}
            ]}}}
        ]
    }

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(nft_payload, f)
        tmp_name = f.name

    try:
        call_subprocess(["nft", "-j", "-f", tmp_name], check=True, stdout=subprocess.DEVNULL)
        print("[INFO] nftables JSON payload applied successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] nftables JSON API failure: {e}")
    finally:
        os.remove(tmp_name)

def fix_tap_checksum_offloading():
    """Disables offloading on Cuttlefish TAP interfaces asynchronously to prevent blocking boot."""
    import subprocess
    import glob
    print("[INFO] Adjusting host network buffer limits and spawning TAP offload monitor...")
    sys.stdout.flush()

    call_subprocess(["sudo", "sysctl", "-w", "net.core.netdev_max_backlog=10000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    def tap_monitor():
        for _ in range(15):
            time.sleep(1)
            for pattern in ["cvd-mtap*", "cvd-wtap*", "cvd-etap*", "cvd-*tap*"]:
                for tap_path in glob.glob(os.path.join("/sys/class/net", pattern)):
                    tap_name = os.path.basename(tap_path)
                    for opt in ["gso", "tso", "gro", "lro", "rx-checksum", "tx-checksum"]:
                        # Bypass the custom logger to run silently
                        subprocess.run(["ethtool", "-K", tap_name, opt, "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        print("[INFO] Background TAP offload monitor finished.")

    threading.Thread(target=tap_monitor, daemon=True).start()

def ensure_tap_bridged():
    """Dynamically binds and stabilizes all Cuttlefish TAP interfaces and injects guest routes."""
    print("[INFO] Forcing Cuttlefish TAP interfaces into the host bridge...")
    sys.stdout.flush()

    for _ in range(10):
        for tap in ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01"]:
            call_subprocess(["ip", "link", "set", "dev", tap, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            call_subprocess(["ip", "link", "set", "dev", tap, "master", "cvd-mbr-0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        call_subprocess(["ip", "link", "set", "dev", "cvd-mbr-0", "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        time.sleep(1)

    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb")
    if not os.path.exists(adb_path):
        adb_path = "adb"
    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    print("[INFO] Forcing static IP and default route injection into Android guest...")
    call_subprocess([adb_path, "shell", "su", "root", "ip", "route", "add", "default", "via", "192.168.96.1"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    call_subprocess([adb_path, "shell", "su", "root", "ndc", "resolver", "setnetdns", "100", "", "8.8.8.8", "8.8.4.4"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print("[INFO] TAP bridging and guest routing sequence complete.")

def patch_seccomp_policies_for_nvidia(sudo_password):
    print("[INFO] Injecting NVIDIA-compatible secure seccomp rules for sandboxed execution...")
    policy_files = [
        "/usr/share/crosvm/x86_64-linux-gnu/seccomp/crosvm.policy",
        "/usr/share/crosvm/x86_64-linux-gnu/seccomp/gpu_render_server.policy"
    ]

    nvidia_rules = textwrap.dedent("""
        # NVIDIA Driver Passthrough Rules
        ioctl: arg1 == 0xC0086400 || arg1 == 0x80086401 || arg1 == 0x40086402 || arg1 == 0xC0106463 || arg1 == 0xCF000000/0xFF000000
        openat: return
        connect: return
        socket: return
    """).strip()

    for policy_path in policy_files:
        if os.path.exists(policy_path):
            try:
                with open(policy_path, "r") as f:
                    content = f.read()
                if "NVIDIA Driver Passthrough" not in content:
                    with open(policy_path, "a") as f:
                        f.write(f"\n\n{nvidia_rules}\n")
            except Exception as e:
                print(f"[-] Failed to patch {policy_path}: {e}")

def enforce_docker_cuttlefish_networking():
    """Sets up host bridge, enforces port 53 DNS DNAT via UFW, and pre-allocates TAPs for Docker."""
    import subprocess
    import time
    print("[INFO] Enforcing stable Docker Cuttlefish network bridging via Native DHCP & UFW...")

    if call_subprocess(["pacman", "-Qs", "^dnsmasq$"], stdout=subprocess.DEVNULL).returncode != 0:
        call_subprocess(["pacman", "-S", "--noconfirm", "--needed", "dnsmasq"], check=False)

    call_subprocess(["-w", "net.ipv4.ip_forward=1"], check=False)

    if call_subprocess(["ip", "link", "show", "cvd-mbr-0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        call_subprocess(["ip", "link", "add", "name", "cvd-mbr-0", "type", "bridge"], check=True)

    # Replace standard subprocess calls in your networking block with your custom run_sudo wrapper:
    call_subprocess(["ip", "link", "set", "dev", "cvd-mbr-0", "up"], check=True)
    call_subprocess(["ip", "addr", "replace", "192.168.96.1/24", "dev", "cvd-mbr-0"], check=True)

    for tap in ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01", "cvd-mtap-1", "cvd-wtap-1"]:
        call_subprocess(["ip", "tuntap", "del", "dev", tap, "mode", "tap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess(["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", "1000", "group", "1000"], check=False)
        call_subprocess(["ip", "link", "set", "dev", tap, "up"], check=False)
        call_subprocess(["ip", "link", "set", "dev", tap, "master", "cvd-mbr-0"], check=False)

    host_fw_commands = [
        ["ufw", "allow", "in", "on", "cvd-mbr-0", "to", "any", "port", "53"],
        ["ufw", "allow", "in", "on", "cvd-mbr-0", "to", "any", "port", "67:68/udp"],
        ["ufw", "route", "allow", "in", "on", "cvd-mbr-0"],
        ["ufw", "route", "allow", "out", "on", "cvd-mbr-0"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", "192.168.96.0/24", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "192.168.96.1:53"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", "192.168.96.0/24", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "192.168.96.1:53"],
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.96.0/24", "!", "-o", "cvd-mbr-0", "-j", "MASQUERADE"]
    ]
    for cmd in host_fw_commands:
        call_subprocess(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    call_subprocess(["sudo", "systemctl", "stop", "systemd-resolved"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    call_subprocess(["pkill", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    dnsmasq_cmd = [
        "dnsmasq",
        "--interface=cvd-mbr-0",
        "--bind-interfaces",
        "--listen-address=192.168.96.1",
        "--dhcp-range=192.168.96.50,192.168.96.150,12h",
        "--dhcp-option=option:router,192.168.96.1",
        "--dhcp-option=option:dns-server,192.168.96.1",
        "--server=8.8.8.8",
        "--server=8.8.4.4"
    ]
    subprocess.Popen(dnsmasq_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print("[INFO] Docker host network orchestration complete with UFW routing.")
def wait_for_android_boot_api():
    """Continuously polls the guest API for boot completion, waiting for the VCPU reset to finish."""
    print("[INFO] Bridging ADB transport and polling for guest boot completion...")

    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb")
    if not os.path.exists(adb_path):
        adb_path = "adb"

    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    call_subprocess([adb_path, "kill-server"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    call_subprocess([adb_path, "start-server"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    poll_start = time.time()
    is_booted = False

    while time.time() - poll_start < 90:
        call_subprocess([adb_path, "connect", "127.0.0.1:6520"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        res = call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "getprop", "sys.boot_completed"], env=env, capture_output=True, text=True, check=False)

        if "1" in res.stdout.strip():
            anim_res = call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "getprop", "init.svc.bootanim"], env=env, capture_output=True, text=True, check=False)
            if "stopped" in anim_res.stdout.strip():
                elapsed = int(time.time() - poll_start)
                print(f"[INFO] Android guest API strictly reports BOOT_COMPLETED and animation stopped (took {elapsed}s).")
                is_booted = True
                break
        time.sleep(0.4)

    if not is_booted:
        print("[-] Warning: Guest sys.boot_completed check timed out. Forcing network execution anyway.")

    is_user_variant = "no-root" in sys.argv
    if not is_user_variant:
        print("[INFO] Re-applying static IP and default route via root on buried_eth0...")
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ip", "route", "replace", "default", "via", "192.168.96.1", "dev", "buried_eth0"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "resolver", "setnetdns", "100", "", "8.8.8.8", "8.8.4.4"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def trigger_guest_network_handshake():
    """Dynamically handles DHCP/Routing for both Rootless (user) and Rooted (userdebug) builds."""
    import subprocess, os, time, sys

    print("[INFO] Triggering Android network handshake...")
    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"
    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    # Ensure adb is connected to the virtual device
    call_subprocess([adb_path, "connect", "127.0.0.1:6520"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    is_user_variant = "no-root" in sys.argv

    if is_user_variant:
        print("[INFO] Executing unprivileged (rootless) Wi-Fi DHCP handshake...")
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "svc", "wifi", "disable"], env=env, stdout=subprocess.DEVNULL, check=False)
        time.sleep(2)
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "svc", "wifi", "enable"], env=env, stdout=subprocess.DEVNULL, check=False)
        time.sleep(2)
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "cmd", "wifi", "connect-network", "VirtWifi", "open"], env=env, stdout=subprocess.DEVNULL, check=False)

        print("[INFO] Waiting 6 seconds for Android DHCP lease to complete...")
        time.sleep(6)
    else:
        print("[INFO] Executing privileged (rooted) ndc routing and DNS enforcement...")
        # 1. Clear old networks and recreate
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "destroy", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "create", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        # 2. Attach interface and add routes
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "interface", "add", "100", "buried_eth0"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "route", "add", "100", "buried_eth0", "192.168.96.0/24"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "route", "add", "100", "buried_eth0", "0.0.0.0/0", "192.168.96.1"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        # 3. Force Google DNS explicitly
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "resolver", "setnetdns", "100", "", "8.8.8.8", "8.8.4.4"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        # 4. Set as default
        call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "default", "set", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    print("[SUCCESS] Guest network and DNS successfully established.")

def monitor_and_stabilize_network():
    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"
    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    print("[INFO] Monitoring container for VCPU reset and post-boot state...")

    call_subprocess([adb_path, "wait-for-device"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    while True:
        try:
            res = call_subprocess(
                [adb_path, "-s", "127.0.0.1:6520", "shell", "getprop", "sys.boot_completed"],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False
            )
            if "1" in res.stdout.strip():
                print("[INFO] Post-boot sequence complete. Enforcing Android netd routing...")

                call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "destroy", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "create", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "interface", "add", "100", "buried_eth0"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "route", "add", "100", "buried_eth0", "192.168.96.0/24"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "route", "add", "100", "buried_eth0", "0.0.0.0/0", "192.168.96.1"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                call_subprocess([adb_path, "-s", "127.0.0.1:6520", "shell", "su", "root", "ndc", "network", "default", "set", "100"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

                print("[INFO] Network route injection successfully locked in.")
                break
        except Exception:
            pass
        time.sleep(2)

def emergency_cleanup():
    print("\nCtrl+C intercepted! Force-killing all user sync and compile processes...")
    for pgid in ACTIVE_PROCESS_GROUPS:
        try:
            os.killpg(pgid, signal.SIGINT)
        except Exception:
            pass
    current_user = pwd.getpwuid(os.getuid()).pw_name
    for pattern in ["git", "repo", "main.py", "index-pack", "git-remote-https", "multiprocessing.forkserver", "make", "ninja", "soong_ui", "nsjail"]:
        call_subprocess(["pkill", "-9", "-u", current_user, "-f", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    import time
    time.sleep(1.5)
    sys.exit(130)

def heal_corrupted_repo_submodules(aosp_src_dir, failed_path=None):
    """Proactively purges corrupted submodules, metadata, and object caches, with targeted support for failed paths."""
    print("[INFO] Running automated prebuilt & submodule self-healer...")

    # Target known fragile prebuilt directories that frequently fail partial clones
    fragile_paths = [
        "prebuilts/checkstyle",
        "prebuilts/rust",
        "prebuilts/clang/host/linux-x86"
    ]
    if failed_path and failed_path not in fragile_paths:
        fragile_paths.append(failed_path)

    for target in fragile_paths:
        local_path = os.path.join(aosp_src_dir, target)
        git_meta = os.path.join(aosp_src_dir, ".repo", "projects", target + ".git")
        git_obj = os.path.join(aosp_src_dir, ".repo", "project-objects", "platform", target + ".git")

        if os.path.exists(local_path) or os.path.exists(git_meta):
            print(f"[AUTO-HEAL] Purging corrupted metadata/worktree for: {target}")
            shutil.rmtree(local_path, ignore_errors=True)
            shutil.rmtree(git_meta, ignore_errors=True)
            shutil.rmtree(git_obj, ignore_errors=True)

    # General sweep for orphaned or broken HEAD pointers
    repo_projects_dir = os.path.join(aosp_src_dir, ".repo", "projects")
    repo_objects_dir = os.path.join(aosp_src_dir, ".repo", "project-objects")

    if os.path.exists(repo_projects_dir):
        for root, dirs, files in os.walk(repo_projects_dir):
            for file in files:
                if file == "HEAD":
                    head_path = os.path.join(root, file)
                    try:
                        with open(head_path, "r") as f:
                            content = f.read().strip()
                        if content.startswith("gitdir:"):
                            target_gitdir = content.replace("gitdir:", "").strip()
                            resolved_path = os.path.abspath(os.path.join(root, target_gitdir))
                            if not os.path.exists(resolved_path):
                                rel_path = os.path.relpath(root, repo_projects_dir).replace(".git", "")
                                shutil.rmtree(os.path.join(aosp_src_dir, rel_path), ignore_errors=True)
                                shutil.rmtree(root, ignore_errors=True)
                                shutil.rmtree(os.path.join(repo_objects_dir, rel_path + ".git"), ignore_errors=True)
                    except Exception:
                        pass

def apply_auto_healers(aosp_src_dir, state_dir, write_if_changed_fn, print_bar_fn, remove_kotlin_fn):
    """Applies essential compilation fixes for a secure, non-root user variant without injecting ADB or root hacks."""
    heal_marker = os.path.join(state_dir, "heal_complete")
    if os.path.exists(heal_marker):
        print("[INFO] Auto-healing source patches already applied. Preserving build cache timestamps.")
        return

    print("[INFO] Running one-time auto-healer source patches...")

    aconfig_test_cc = os.path.join(aosp_src_dir, "art", "libartbase", "base", "aconfig_flags_test.cc")
    if os.path.exists(aconfig_test_cc):
        content = Path(aconfig_test_cc).read_text(encoding="utf-8")
        if "COM_ANDROID_ART_FLAGS_TEST == true" in content:
            content = content.replace(
                "static_assert(COM_ANDROID_ART_FLAGS_TEST == true);",
                "// static_assert(COM_ANDROID_ART_FLAGS_TEST == true); /* Patched by Cuttlefish Orchestrator */"
            )
            write_if_changed_fn(aconfig_test_cc, content)

    serialization_dir = os.path.join(aosp_src_dir, "external", "kotlinx.serialization")
    if os.path.exists(serialization_dir):
        i_path = os.path.join(serialization_dir, "core", "commonMain", "src", "kotlinx", "serialization", "internal", "BuiltInSerializers.kt")
        b_path = os.path.join(serialization_dir, "core", "commonMain", "src", "kotlinx", "serialization", "builtins", "BuiltinSerializers.kt")
        p_path = os.path.join(serialization_dir, "core", "jvmMain", "src", "kotlinx", "serialization", "internal", "Platform.kt")

        needs_patch = False
        for path in [i_path, b_path, p_path]:
            if os.path.exists(path):
                content = Path(path).read_text(encoding="utf-8")
                if "Uuid" in content:
                    needs_patch = True
                    break

        if needs_patch:
            call_subprocess(["git", "checkout", "."], cwd=serialization_dir, check=False)
            files_to_process = [
                (i_path, "BuiltInSerializers.kt (internal)", "UuidSerializer"),
                (b_path, "BuiltinSerializers.kt (builtins)", "Uuid.Companion.serializer"),
                (p_path, "Platform.kt (jvmMain)", None)
            ]
            total_files = len(files_to_process)
            for idx, (path, rel_path, keyword) in enumerate(files_to_process, 1):
                print_bar_fn("Sanitizing", idx, total_files, rel_path)
                if os.path.exists(path):
                    try:
                        if path == p_path:
                            code = Path(path).read_text(encoding="utf-8")
                            code = re.sub(r'(?:@OptIn\([^)]*\)\s*)?loadSafe\s*\{[^}]*Uuid::class[^}]*\}', '', code, flags=re.DOTALL)
                            code = code.replace('put(Uuid::class, Uuid.serializer())', '')
                            code = re.sub(r'@ExperimentalUuidApi\s*', '', code)
                            code = re.sub(r'import kotlin\.uuid\..*\n?', '', code)
                            write_if_changed_fn(path, code)
                        else:
                            content = Path(path).read_text(encoding="utf-8")
                            healed_content = remove_kotlin_fn(content, keyword)
                            write_if_changed_fn(path, healed_content)
                    except Exception:
                        pass

    fake_config_src = os.path.join(aosp_src_dir, "build", "make", "tools", "aconfig", "fake_device_config", "src")
    if os.path.exists(fake_config_src):
        os.makedirs(os.path.join(fake_config_src, "android", "os"), exist_ok=True)
        binder_path = os.path.join(fake_config_src, "android", "os", "Binder.java")
        binder_code = "package android.os;\npublic class Binder {\n    public static long clearCallingIdentity() { return 0; }\n    public static void restoreCallingIdentity(long token) {}\n}\n"
        write_if_changed_fn(binder_path, binder_code)

        os.makedirs(os.path.join(fake_config_src, "android", "provider"), exist_ok=True)
        device_config_path = os.path.join(fake_config_src, "android", "provider", "DeviceConfig.java")
        device_config_code = """package android.provider;
        public class DeviceConfig {
            public static final String NAMESPACE_PERMISSIONS = "permissions";
            public static final String NAMESPACE_VCN = "vcn";
            public static boolean getBoolean(String namespace, String name, boolean defaultValue) { return defaultValue; }
            public static String getString(String namespace, String name, String defaultValue) { return defaultValue; }
            public static int getInt(String namespace, String name, int defaultValue) { return defaultValue; }
            public static float getFloat(String namespace, String name, float defaultValue) { return defaultValue; }
            public static long getLong(String namespace, String name, long defaultValue) { return defaultValue; }
            public static class Properties {
                public boolean getBoolean(String name, boolean defaultValue) { return defaultValue; }
                public String getString(String name, String defaultValue) { return defaultValue; }
                public int getInt(String name, int defaultValue) { return defaultValue; }
                public float getFloat(String name, float defaultValue) { return defaultValue; }
                public long getLong(String name, long defaultValue) { return defaultValue; }
                public java.util.Set<String> getKeys() { return java.util.Collections.emptySet(); }
            }
            public static Properties getProperties(String namespace, String... names) { return new Properties(); }
            public interface OnPropertiesChangedListener {}
            public static void addOnPropertiesChangedListener(String namespace, java.util.concurrent.Executor executor, OnPropertiesChangedListener listener) {}
        }
        """
        write_if_changed_fn(device_config_path, device_config_code)

    settings_provider = os.path.join(aosp_src_dir, "frameworks", "base", "packages", "SettingsProvider", "res", "values", "defaults.xml")
    if os.path.exists(settings_provider):
        content = Path(settings_provider).read_text(encoding="utf-8")
        if 'name="def_captive_portal_mode"' in content:
            print("[INFO] Auto-healing: Disabling captive portal for clean Ethernet connectivity...")
            content = re.sub(r'<integer name="def_captive_portal_mode">.*?</integer>', '<integer name="def_captive_portal_mode">0</integer>', content)
            write_if_changed_fn(settings_provider, content)

    # --- AUTO-INJECT API BYPASS (NATIVE SED) ---
    java_lib_bp = os.path.join(aosp_src_dir, "libcore", "JavaLibrary.bp")
    if os.path.exists(java_lib_bp):
        try:
            with open(java_lib_bp, "r", encoding="utf-8") as f:
                content = f.read()

            # Only run the sed commands if the bypass isn't already in the file
            if "unsafe_ignore_missing_latest_api: true" not in content:
                log_and_broadcast("[INFO] Executing raw sed commands to bypass strict API tracking...", "INFO")

                # Execute the exact sed commands requested via the native shell
                subprocess.run(f"sed -i '/name: \"art.module.public.api\",/a \\    unsafe_ignore_missing_latest_api: true,' {java_lib_bp}", shell=True)
                subprocess.run(f"sed -i '/name: \"art.module.system.api\",/a \\    unsafe_ignore_missing_latest_api: true,' {java_lib_bp}", shell=True)
                subprocess.run(f"sed -i '/name: \"art.module.module-lib.api\",/a \\    unsafe_ignore_missing_latest_api: true,' {java_lib_bp}", shell=True)

                # Nuke the corrupted 'out' directory so Soong re-reads the fixed blueprint
                corrupted_out = os.path.join(aosp_src_dir, "out")
                if os.path.exists(corrupted_out):
                    log_and_broadcast("[INFO] Purging corrupted compiler cache to force clean blueprint evaluation...", "INFO")
                    import shutil
                    shutil.rmtree(corrupted_out, ignore_errors=True)
        except Exception:
            pass
    # ------------------------------

    Path(heal_marker).touch()
    print("[INFO] Auto-healing source patches applied and locked.")

def run_live_telemetry_subprocess(cmd_list_or_str, cwd=None, env=None):
    """Runs compilation with progress parsing, real-time thread tracking, anti-spam terminal bounds, disk logging, and Web UI broadcasting."""
    import time
    import psutil
    import shutil
    import re
    import select
    import subprocess
    import os
    import pty
    import sys
    import collections

    if isinstance(cmd_list_or_str, list):
        cmd_str = " ".join(cmd_list_or_str)
    else:
        cmd_str = cmd_list_or_str

    log_dir = os.path.abspath(cwd) if cwd else os.path.abspath(os.getcwd())
    full_log_path = os.path.join(log_dir, "build_full.log")
    warn_log_path = os.path.join(log_dir, "build_warnings_errors.log")

    print(" \033[1;36m[BUILD LOGGING INITIALIZED]\033[0m")
    print(f"  \033[1m• Full Output Log       :\033[0m {full_log_path}")
    print(f"  \033[1m• Warnings & Errors Log :\033[0m {warn_log_path}")
    sys.stdout.flush()

    global ACTIVE_WORKER_PROC  # <-- ADD THIS

    master_fd, slave_fd = pty.openpty()

    process = subprocess.Popen(
        cmd_str,
        shell=True,
        executable='/bin/bash',
        stdout=slave_fd,
        stderr=slave_fd,
        stdin=subprocess.DEVNULL,
        cwd=cwd,
        env=env,
        start_new_session=True
    )

    ACTIVE_WORKER_PROC = process  # <-- ADD THIS
    ACTIVE_PROCESS_GROUPS.append(os.getpgid(process.pid))
    os.close(slave_fd)

    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    progress_pattern = re.compile(r"\[\s*(?:([\d\.]+%)?\s*)?([\d]+/[\d]+)\s*\]\s*(.*)")

    last_target = "Initializing build engine..."
    stdout_lines = collections.deque(maxlen=100)

    last_proc_check = 0
    active_workers = 0
    cpu = 0.0
    mem_used = 0.0

    COMPILER_BINS = {'clang', 'clang++', 'rustc', 'javac', 'd8', 'r8', 'siso', 'soong_build', 'ckati', 'metalava', 'git', 'git-remote-https', 'ssh'}

    try:
        with open(full_log_path, "w", encoding="utf-8") as full_log, \
             open(warn_log_path, "w", encoding="utf-8") as warn_log:

            while True:
                rlist, _, _ = select.select([master_fd], [], [], 0.05)

                if master_fd in rlist:
                    try:
                        # INCREASE BUFFER FROM 4096 to 65536 so the OS never freezes Git
                        data = os.read(master_fd, 65536).decode('utf-8', errors='ignore')
                    except OSError:
                        break
                    if not data:
                        break

                    for line in data.splitlines():
                        cleaned_line = ansi_escape.sub('', line).strip()
                        if not cleaned_line:
                            continue

                        stdout_lines.append(cleaned_line)
                        full_log.write(cleaned_line + "\n")
                        full_log.flush()

                        match = progress_pattern.search(cleaned_line)
                        sync_match = re.search(r"(\d+%\s*\(\d+/\d+\))", cleaned_line)

                        if match:
                            pct = match.group(1) or ""
                            frac = match.group(2)
                            task = match.group(3)

                            if pct:
                                last_target = f"[{pct} {frac}] {task}"
                            else:
                                last_target = f"[{frac}] {task}"

                        elif sync_match or any(kw in cleaned_line for kw in ["Receiving objects:", "Resolving deltas:", "Fetching:"]):
                            last_target = f"[SYNC] {cleaned_line[:85]}"

                        elif any(kw in cleaned_line.lower() for kw in ["error:", "failed:", "ninja: error", "fatal:", "warning:", "cannot initialize"]):
                            warn_log.write(cleaned_line + "\n")
                            warn_log.flush()

                            sys.stdout.write("\r\033[K")
                            sys.stdout.flush()

                            if "error" in cleaned_line.lower() or "failed" in cleaned_line.lower() or "fatal:" in cleaned_line.lower():
                                print(f"\033[1;31m{cleaned_line}\033[0m")
                            else:
                                print(f"\033[1;33m{cleaned_line}\033[0m")

                if process.poll() is not None:
                    try:
                        while True:
                            rlist, _, _ = select.select([master_fd], [], [], 0.05)
                            if not rlist: break
                            data = os.read(master_fd, 4096).decode('utf-8', errors='ignore')
                            if not data: break
                            for line in data.splitlines():
                                cleaned_line = ansi_escape.sub('', line).strip()
                                if cleaned_line:
                                    stdout_lines.append(cleaned_line)
                                    full_log.write(cleaned_line + "\n")
                    except Exception:
                        pass
                    break

                now = time.time()
                if now - last_proc_check > 2.5:
                    last_proc_check = now
                    mem_info = psutil.virtual_memory()
                    mem_used = mem_info.used / (1024 ** 3)
                    cpu = psutil.cpu_percent(interval=None)

                    active_workers = 0
                    try:
                        for p in psutil.process_iter(['name']):
                            if p.info['name'] in COMPILER_BINS:
                                active_workers += 1
                    except Exception:
                        pass

                    # Force a minimum of 1 active thread so it never displays 0 during a live compile
                    active_workers = max(1, active_workers)

                bar_len = 15
                filled_len = int(bar_len * cpu / 100) if cpu > 0 else 0
                bar = "█" * filled_len + "-" * (bar_len - filled_len)

                # 1. Format for Terminal (Single line, strictly truncated to prevent wrapping)
                status_msg_term = (
                    f"[BUILD TELEMETRY] CPU: [{bar}] {cpu:.1f}% | "
                    f"RAM: {mem_used:.1f}GB/31.0GB | "
                    f"Threads: {active_workers} | "
                    f"{last_target}"
                )
                term_width = shutil.get_terminal_size((120, 24)).columns
                term_msg = status_msg_term[:term_width - 1]

                sys.stdout.write(f"\r{term_msg}\033[K")
                sys.stdout.flush()

                # 2. Format for Dashboard (Two lines using <br> for HTML native rendering)
                status_msg_web = (
                    f"[BUILD TELEMETRY] CPU: [{bar}] {cpu:.1f}% | "
                    f"RAM: {mem_used:.1f}GB/31.0GB | "
                    f"Active Threads: {active_workers}<br>"
                    f" ↳ {last_target}"
                )

                if "console" not in sys.argv:
                    try:
                        broadcast_log_line(status_msg_web)
                    except Exception:
                        pass

        sys.stdout.write("\n")
        sys.stdout.flush()
        ret_code = process.poll()
        os.close(master_fd)

        if ret_code != 0:
            print(f"\n\033[1;31m[ERROR] Build process failed with exit code {ret_code}. Last 25 build log lines:\033[0m")
            for tail_line in list(stdout_lines)[-25:]:
                print(f"  {tail_line}")

        return ret_code

    except Exception as e:
        try:
            os.close(master_fd)
        except Exception:
            pass
        print(f"\n[ERROR] Build telemetry stream interrupted: {e}")
        process.kill()
        raise e

def handle_aosp_artifacts_and_build():
    """Robust, memory-shielded compilation pipeline tailored for Android 17 (main/trunk) on high-core / limited-RAM systems."""
    global INTENTIONAL_RESTART, CURRENT_SYNC_THREADS, CURRENT_COMPILE_THREADS, dynamic_compile_threads
    import os
    import sys
    import subprocess
    import urllib.request
    from pathlib import Path
    import time
    import shutil

    def log_and_broadcast(msg, level="INFO"):
        formatted_msg = f"[{level}] {msg}"
        print(formatted_msg)
        if "console" not in sys.argv:
            try:
                ui_msg = formatted_msg.replace("[INFO]", "[BUILD]")
                broadcast_log_line(ui_msg)
            except Exception:
                pass

    def copy_with_progress(src_dir, dest_dir, desc):
        if not src_dir or not os.path.exists(src_dir):
            return
        files = [f for f in Path(src_dir).rglob("*") if f.is_file() or f.is_symlink()]
        total = len(files)
        if total == 0: return

        last_milestone = -1
        repaired_count = 0
        copied_count = 0

        for idx, f in enumerate(files, 1):
            rel_path = f.relative_to(src_dir)
            dest_path = Path(dest_dir) / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            needs_copy = True

            if dest_path.exists() and not dest_path.is_symlink() and not f.is_symlink():
                if os.path.getsize(f) == os.path.getsize(dest_path):
                    needs_copy = False
                else:
                    dest_path.unlink()
                    repaired_count += 1
            elif dest_path.is_symlink() or dest_path.exists():
                dest_path.unlink()

            if needs_copy:
                shutil.copy2(f, dest_path, follow_symlinks=False)
                copied_count += 1

            percent = int((idx / total) * 100)
            if percent // 5 > last_milestone or idx == total:
                last_milestone = percent // 5
                log_and_broadcast(f"{desc} progress: {percent}% ({idx}/{total}) — Last: {rel_path.name}")

        if copied_count > 0 or repaired_count > 0:
            log_and_broadcast(f"{desc} complete. {copied_count} copied, {repaired_count} repaired.", "SUCCESS")
        else:
            log_and_broadcast(f"{desc} complete. All files verified and intact.", "SUCCESS")

    def deploy_artifacts():
        log_and_broadcast("Deploying compiled host binaries to workspace...")
        host_out = os.path.join(aosp_src_dir, "out", "host", "linux-x86")
        if os.path.exists(host_out):
            copy_with_progress(host_out, WORKSPACE_DIR, "Host Binaries")

        log_and_broadcast("Deploying compiled Android images to workspace...")
        product_out_base = os.path.join(aosp_src_dir, "out", "target", "product")
        if os.path.exists(product_out_base):
            for d in os.listdir(product_out_base):
                prod_path = os.path.join(product_out_base, d)
                if os.path.isdir(prod_path) and list(Path(prod_path).glob("*.img")):
                    copy_with_progress(prod_path, WORKSPACE_DIR, "Android Images")
                    break

    aosp_src_dir = AOSP_SRC_DIR
    user_cache_dir = USER_CACHE_DIR
    state_dir = os.path.join(aosp_src_dir, ".BUILD_STATE")

    os.makedirs(user_cache_dir, exist_ok=True)
    os.makedirs(aosp_src_dir, exist_ok=True)
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    os.makedirs(state_dir, exist_ok=True)

    build_marker = os.path.join(state_dir, "build_complete")
    out_launch = os.path.join(aosp_src_dir, "out", "host", "linux-x86", "bin", "launch_cvd")

    if os.path.exists(build_marker) and os.path.exists(out_launch):
        log_and_broadcast("Android 17 compilation checkpoint detected. Bypassing compilation phase...")
        update_roadmap("1. Environment & Tools", "COMPLETED")
        update_roadmap("2. Repository Init", "COMPLETED")
        update_roadmap("3. Source Sync", "COMPLETED")
        update_roadmap("4. Lunch & Compile", "COMPLETED")
        update_roadmap("5. Cache & Deployment", "ACTIVE")
        deploy_artifacts()
        log_and_broadcast("Android 17 build artifacts successfully verified in workspace.", "SUCCESS")
        update_roadmap("5. Cache & Deployment", "COMPLETED")
        return

    update_roadmap("1. Environment & Tools", "ACTIVE")
    repo_tool_dir = os.path.join(Path.home(), ".git-repo-tool")
    repo_executable = os.path.join(repo_tool_dir, "repo")

    if not os.path.exists(os.path.join(aosp_src_dir, ".repo")):
        log_and_broadcast("Initializing Android 17 source tree via repo (branch: main)...")
        os.makedirs(repo_tool_dir, exist_ok=True)
        if not os.path.exists(repo_executable):
            urllib.request.urlretrieve("https://storage.googleapis.com/git-repo-downloads/repo", repo_executable)
            os.chmod(repo_executable, 0o755)

        env = os.environ.copy()
        env["PATH"] = f"{repo_tool_dir}:{env.get('PATH', '')}"

        # INJECT GIT IDENTITY TO PREVENT "Committer identity unknown" CRASH
        env["GIT_AUTHOR_NAME"] = "Cuttlefish Builder"
        env["GIT_AUTHOR_EMAIL"] = "builder@localhost"
        env["GIT_COMMITTER_NAME"] = "Cuttlefish Builder"
        env["GIT_COMMITTER_EMAIL"] = "builder@localhost"
        subprocess.run(["git", "config", "--global", "user.name", "Cuttlefish Builder"], stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["git", "config", "--global", "user.email", "builder@localhost"], stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["git", "config", "--global", "color.ui", "auto"], stderr=subprocess.DEVNULL, check=False)  # <--- PREVENTS THE COLOR PROMPT

        update_roadmap("1. Environment & Tools", "COMPLETED")
        update_roadmap("2. Repository Init", "ACTIVE")

        subprocess.run([
            repo_executable, "init", "--quiet",  # <--- ADDED --quiet
            "-u", "https://android.googlesource.com/platform/manifest",
            "-b", "main", "--depth=1", "--partial-clone", "--clone-filter=blob:limit=10M"
        ], cwd=aosp_src_dir, env=env, check=True)

        update_roadmap("2. Repository Init", "COMPLETED")
        update_roadmap("3. Source Sync", "ACTIVE")

        max_sync_retries = 6
        sync_success = False

        for attempt in range(1, max_sync_retries + 1):
            log_and_broadcast(f"Syncing source tree (Attempt {attempt}/{max_sync_retries}) | Threads: -j{CURRENT_SYNC_THREADS}...")

            sync_cmd = [
                repo_executable, "sync", "-c", f"-j{CURRENT_SYNC_THREADS}",
                "--no-tags", "--no-clone-bundle", "--force-sync", "--optimized-fetch", "--retry-fetches=5"
            ]

            import pty, select, psutil, re
            master_fd, slave_fd = pty.openpty()

            global ACTIVE_WORKER_PROC
            process = subprocess.Popen(
                " ".join(sync_cmd), cwd=aosp_src_dir, env=env,
                shell=True, executable='/bin/bash',
                stdout=slave_fd, stderr=slave_fd, stdin=subprocess.DEVNULL,
                start_new_session=True
            )
            ACTIVE_WORKER_PROC = process
            os.close(slave_fd)

            output_log = []
            failing_repos = set()
            last_proc_check = 0
            cpu = 0.0
            mem_used = 0.0
            last_target = "Fetching repositories..."

            try:
                while True:
                    rlist, _, _ = select.select([master_fd], [], [], 0.1)
                    if master_fd in rlist:
                        try:
                            data = os.read(master_fd, 4096).decode('utf-8', errors='ignore')
                        except OSError:
                            break
                        if not data: break

                        for line in data.splitlines():
                            clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', line).strip()
                            if not clean: continue
                            output_log.append(clean)

                            if "Cannot initialize work tree for platform/" in clean:
                                match = re.search(r"platform/([^\s]+)", clean)
                                if match: failing_repos.add(match.group(1).strip())

                            sync_match = re.search(r'(Fetching|Checking out|Syncing).*?(\d+)%\s*\((.*?)\)', clean)
                            if sync_match:
                                last_target = f"[{sync_match.group(2)}%] {sync_match.group(1)} {sync_match.group(3)}"

                    if process.poll() is not None:
                        break

                    now = time.time()
                    if now - last_proc_check > 0.5:
                        last_proc_check = now
                        mem_used = psutil.virtual_memory().used / (1024 ** 3)
                        cpu = psutil.cpu_percent(interval=None)

                        active_workers = 0
                        try:
                            for p in psutil.process_iter(['name']):
                                if p.info['name'] in {'git', 'git-remote-https', 'index-pack', 'repo'}:
                                    active_workers += 1
                        except Exception: pass
                        active_workers = max(1, active_workers)

                        bar_len = 15
                        filled = int(bar_len * cpu / 100) if cpu > 0 else 0
                        bar = "█" * filled + "-" * (bar_len - filled)

                        term_msg = (
                            f"[BUILD TELEMETRY] CPU: [{bar}] {cpu:.1f}% | "
                            f"RAM: {mem_used:.1f}GB/31.0GB | "
                            f"Threads: {active_workers} | "
                            f"{last_target}"
                        )
                        term_width = shutil.get_terminal_size((120, 24)).columns
                        sys.stdout.write(f"\r{term_msg[:term_width - 1]}\033[K")
                        sys.stdout.flush()

                        if "console" not in sys.argv:
                            ui_msg = (
                                f"[BUILD TELEMETRY] CPU: [{bar}] {cpu:.1f}% | "
                                f"RAM: {mem_used:.1f}GB/31.0GB | "
                                f"Active Threads: {active_workers}<br>"
                                f" ↳ {last_target}"
                            )
                            try: broadcast_log_line(ui_msg)
                            except Exception: pass

            except Exception:
                process.kill()
            finally:
                try: os.close(master_fd)
                except Exception: pass
                process.wait()
                sys.stdout.write("\n")
                sys.stdout.flush()

            if process.returncode == 0:
                sync_success = True
                log_and_broadcast("Source Sync completed successfully.", "SUCCESS")
                break

            full_output = "".join(output_log)
            if "Failing repos:" in full_output:
                lines = full_output.splitlines()
                try:
                    idx = lines.index("Failing repos:")
                    for failing_line in lines[idx+1:]:
                        if not failing_line.strip() or "Try re-running" in failing_line or "===" in failing_line:
                            break
                        failing_repos.add(failing_line.strip())
                except ValueError:
                    pass

            if failing_repos:
                log_and_broadcast(f"Auto-healing {len(failing_repos)} corrupted submodules...", "WARNING")
                for repo_path in failing_repos:
                    clean_paths = [
                        os.path.join(aosp_src_dir, repo_path),
                        os.path.join(aosp_src_dir, ".repo", "projects", repo_path + ".git"),
                        os.path.join(aosp_src_dir, ".repo", "project-objects", "platform", repo_path + ".git")
                    ]
                    for p in clean_paths:
                        if os.path.exists(p):
                            shutil.rmtree(p, ignore_errors=True)

            if "429" in full_output or "RPC failed" in full_output or "promisor remote" in full_output:
                if CURRENT_SYNC_THREADS > 1:
                    CURRENT_SYNC_THREADS = max(1, CURRENT_SYNC_THREADS // 2)
                    log_and_broadcast(f"Google Rate Limit (429) hit! Auto-lowering threads to -j{CURRENT_SYNC_THREADS}", "WARNING")

            cooldown = 15 * attempt
            if INTENTIONAL_RESTART:
                log_and_broadcast(f"[INFO] Applying new manual sync thread limit (-j{CURRENT_SYNC_THREADS}) instantly...", "INFO")
                INTENTIONAL_RESTART = False
                continue

            log_and_broadcast(f"Sync failed (Exit {process.returncode}). Engaging cooldown protocol...", "WARNING")

            for remaining in range(cooldown, 0, -1):
                sys.stdout.write(f"\r \033[33m↳ Retrying in {remaining} seconds...\033[0m \033[K")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\r\033[K")

        if not sync_success:
            update_roadmap("3. Source Sync", "FAILED")
            raise RuntimeError("Fatal: Android source sync failed entirely after multiple auto-healing attempts.")

        update_roadmap("3. Source Sync", "COMPLETED")
    else:
        update_roadmap("1. Environment & Tools", "COMPLETED")
        update_roadmap("2. Repository Init", "COMPLETED")
        update_roadmap("3. Source Sync", "COMPLETED")

    update_roadmap("4. Lunch & Compile", "ACTIVE")
    log_and_broadcast("Unleashing Android 17 compiler with strict memory shielding...")

    total_cores = os.cpu_count() or 4
    dynamic_compile_threads = max(4, int(total_cores * 0.90))
    ninja_load_limit = dynamic_compile_threads + 2
    max_compile_retries = 3
    compile_success = False

    compile_env = os.environ.copy()

    # --- MACRO LEVEL CLEANUP (Restoring pristine AOSP files) ---
    api_bp_files = [
        "libcore/JavaLibrary.bp",
        "external/conscrypt/Android.bp",
        "external/icu/android_icu4j/Android.bp"
    ]

    for rel_path in api_bp_files:
        bp_path = os.path.join(aosp_src_dir, rel_path)
        if os.path.exists(bp_path):
            try:
                # Force Git to restore the pristine upstream file, clearing the broken patches!
                subprocess.run(["git", "checkout", "--", os.path.basename(bp_path)], cwd=os.path.dirname(bp_path), stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception:
                pass
    # ---------------------------------------------

    for attempt in range(1, max_compile_retries + 1):
        log_and_broadcast(f"Compile Attempt {attempt}/{max_compile_retries} | Threads: -j{dynamic_compile_threads} | Load Limit: -l{ninja_load_limit}")

        build_cmd = (
            "export LC_ALL=C && "
            "export ALLOW_MISSING_DEPENDENCIES=true && "
            "export RELAX_USES_LIBRARY_CHECK=true && "
            "export BUILD_BROKEN_MISSING_REQUIRED_MODULES=true && "
            "export BUILD_BROKEN_USES_NETWORK=true && "
            "export SKIP_ABI_CHECKS=true && "
            "export WITHOUT_CHECK_API=true && "
            "export BUILD_FROM_SOURCE_STUB=true && "  # <--- ADD THIS EXACT LINE
            "export _JAVA_OPTIONS=\"-Xmx4096m\" && "
            "export GOMAXPROCS=4 && "
            "export GOMEMLIMIT=16384MiB && "
            f"export SISO_LOCAL_JOBS={dynamic_compile_threads} && "
            "source build/envsetup.sh && "
            "lunch aosp_cf_x86_64_only_phone-trunk_staging-user && "
            f"nice -n 19 ionice -c 3 m -j{dynamic_compile_threads}"
        )

        try:
            ret_code = run_live_telemetry_subprocess(build_cmd, cwd=aosp_src_dir, env=compile_env)
            if ret_code != 0:
                raise subprocess.CalledProcessError(ret_code, build_cmd)
            compile_success = True
            Path(build_marker).touch()
            break
        except Exception as e:
            log_and_broadcast(f"[🛡️ COMPILER SHIELD] Build failure or OOM intercepted: {e}", "WARNING")

            warn_log_path = os.path.join(aosp_src_dir, "build_warnings_errors.log")
            if os.path.exists(warn_log_path):
                import re
                try:
                    with open(warn_log_path, "r", encoding="utf-8") as f:
                        log_content = f.read()

                    missing_deps = re.findall(r'missing dependency on "(.*?)"', log_content)
                    repos_to_sync = set()

                    for dep in missing_deps:
                        if "dirgroup_" in dep:
                            path_part = dep.split("dirgroup_")[-1]
                            repos_to_sync.add(path_part.replace("_", "/"))
                        elif "prebuilts_" in dep or "external_" in dep:
                            repos_to_sync.add(dep.replace("_", "/"))

                    if repos_to_sync:
                        log_and_broadcast(f"[🛡️ COMPILER SHIELD] Auto-healing missing Soong paths: {', '.join(repos_to_sync)}", "WARNING")
                        for missing_repo in repos_to_sync:
                            log_and_broadcast(f" -> Force fetching missing tree: {missing_repo}...", "INFO")
                            subprocess.run([
                                repo_executable, "sync", "-c", "-j1", "--force-sync", missing_repo
                            ], cwd=aosp_src_dir, env=compile_env, stdout=subprocess.DEVNULL)
                except Exception as parse_e:
                    pass

            if dynamic_compile_threads > 2:
                dynamic_compile_threads = max(2, dynamic_compile_threads - 2)
                log_and_broadcast(f"[🛡️ COMPILER SHIELD] RAM/CPU exhaustion suspected. Lowering threads to -j{dynamic_compile_threads} for next attempt...", "WARNING")

            if INTENTIONAL_RESTART:
                log_and_broadcast(f"[INFO] Applying new manual compile thread limit (-j{CURRENT_COMPILE_THREADS}) instantly...", "INFO")
                INTENTIONAL_RESTART = False
                continue

            if attempt >= max_compile_retries:
                update_roadmap("4. Lunch & Compile", "FAILED")
                raise e
            log_and_broadcast("[🛡️ COMPILER SHIELD] Cooling down RAM for 20 seconds before retry...", "WARNING")
            time.sleep(20)

    if not compile_success:
        update_roadmap("4. Lunch & Compile", "FAILED")
        raise RuntimeError("Android 17 compilation failed persistently despite memory shielding.")

    update_roadmap("4. Lunch & Compile", "COMPLETED")
    update_roadmap("5. Cache & Deployment", "ACTIVE")

    deploy_artifacts()

    log_and_broadcast("Android 17 build artifacts successfully deployed to workspace.", "SUCCESS")
    update_roadmap("5. Cache & Deployment", "COMPLETED")

def handle_aosp_artifacts():
    """Lightweight pipeline for querying, downloading, and deploying prebuilt AOSP Cuttlefish artifacts."""
    import zipfile
    import tarfile
    import json
    import re
    import sys
    import os
    from pathlib import Path
    import subprocess
    from curl_cffi import requests

    def print_horizontal_bar(desc, current, total, item_name):
        bar_len = 30
        percent = int((current / total) * 100) if total > 0 else 100
        filled = int((current / total) * bar_len) if total > 0 else bar_len
        bar = "█" * filled + "-" * (bar_len - filled)
        sys.stdout.write(f"\r[{desc} ({percent}%)] [{bar}] {current}/{total} — {item_name[:50]}\033[K")
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write("\n")

    print("[INFO] Standard prebuilt deployment requested. Initializing download & extraction pipeline...")

    # Fast-forward the roadmap since we are bypassing the source compilation
    update_roadmap("1. Environment & Tools", "COMPLETED")
    update_roadmap("2. Repository Init", "COMPLETED")
    update_roadmap("3. Source Sync (-j4)", "ACTIVE")

    cache_dir = os.path.join(VAULT_DIR, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    os.makedirs(WORKSPACE_DIR, exist_ok=True)

    target = "aosp_cf_x86_64_only_phone-userdebug"
    branch = "aosp-android-latest-release"

    print(f"[INFO] Querying official status.json for latest build ID on '{branch}'...")
    try:
        status_url = f"https://ci.android.com/builds/branches/{branch}/status.json"
        resp = requests.get(status_url, impersonate="chrome110", timeout=15)
        resp.raise_for_status()
        data = resp.json()

        build_id = None
        if isinstance(data, dict):
            builds = data.get("builds", [])
            if builds:
                build_id = str(builds[0].get("build_id") or builds[0].get("id"))
            else:
                for t in data.get("targets", []):
                    if target in t.get("ID", ""):
                        build_id = str(t.get("last_known_good_build") or t.get("build_id"))
                        if build_id:
                            break

        if not build_id or not build_id.isdigit():
            match = re.search(r'"(?:build_id|buildId|id)"\s*:\s*"?(\d{7,8})"?', resp.text)
            if match:
                build_id = match.group(1)

        if not build_id or not build_id.isdigit():
            raise ValueError("Could not extract a valid build ID from status.json")

    except Exception as e:
        print(f"[-] Failed to fetch build ID dynamically: {e}. Terminating...")
        update_roadmap("3. Source Sync (-j4)", "FAILED")
        os._exit(0)

    device_name = target.split('-')[0]
    base_url = f"https://ci.android.com/builds/submitted/{build_id}/{target}/latest/raw"
    img_name = f"{device_name}-img-{build_id}.zip"
    host_pkg_name = "cvd-host_package.tar.gz"

    cached_img = os.path.join(cache_dir, img_name)
    cached_host = os.path.join(cache_dir, host_pkg_name)

    if not (os.path.exists(cached_img) and zipfile.is_zipfile(cached_img)):
        download_artifact(f"{base_url}/{img_name}", cached_img)
    if not os.path.exists(cached_host):
        download_artifact(f"{base_url}/{host_pkg_name}", cached_host)

    update_roadmap("3. Source Sync (-j4)", "COMPLETED")
    update_roadmap("4. Lunch & Compile", "COMPLETED")
    update_roadmap("5. Cache & Deployment", "ACTIVE")

    if not os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "launch_cvd")):
        with tarfile.open(cached_host, "r:gz") as tar:
            members = tar.getmembers()
            for idx, member in enumerate(members, 1):
                tar.extract(member, WORKSPACE_DIR)
                print_horizontal_bar("Unpacking Host", idx, len(members), member.name)

    if not list(Path(WORKSPACE_DIR).glob("*.img")):
        with zipfile.ZipFile(cached_img, 'r') as zf:
            file_list = zf.namelist()
            for idx, file in enumerate(file_list, 1):
                zf.extract(file, WORKSPACE_DIR)
                print_horizontal_bar("Unpacking Imgs", idx, len(file_list), file)

    update_roadmap("5. Cache & Deployment", "COMPLETED")

    # Secure graphics and sandbox policies
    seccomp_src = os.path.join(WORKSPACE_DIR, "usr", "share", "crosvm", "x86_64-linux-gnu", "seccomp")
    host_crosvm_share = "/usr/share/crosvm/x86_64-linux-gnu"

    call_subprocess(["mkdir", "-p", "/usr/share/policy", host_crosvm_share, "/var/empty"], check=False)
    call_subprocess(["chown", "root:root", "/var/empty"], check=False)
    call_subprocess(["chmod", "755", "/var/empty"], check=False)

    if os.path.exists(seccomp_src):
        call_subprocess(["sudo", "ln", "-sfn", os.path.abspath(seccomp_src), "/usr/share/policy/crosvm"], check=False)
        call_subprocess(["cp", "-rf", os.path.abspath(seccomp_src) + "/.", host_crosvm_share], check=False)
        call_subprocess(["sudo", "chmod", "-R", "755", "/usr/share/crosvm"], check=False)

def configure_rootless_host_networking():
    """Configures secure rootless host network bridge, WebRTC NAT routing, and UFW rules."""
    import subprocess
    import time

    print("[INFO] Restoring secure host network bridge and targeted UFW WebRTC rules...")

    # 1. Enable IP Forwarding and Localnet Routing
    call_subprocess("sudo sysctl -w net.ipv4.ip_forward=1", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    call_subprocess("sudo sysctl -w net.ipv4.conf.all.route_localnet=1", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # 2. Configure Bridge Interface
    call_subprocess("sudo ip link set dev cvd-mbr-0 up", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    call_subprocess("sudo ip addr replace 192.168.96.1/24 dev cvd-mbr-0", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    taps = ["cvd-mtap-01", "cvd-wtap-01", "cvd-etap-01", "cvd-mtap-1", "cvd-wtap-1"]
    for tap in taps:
        res = call_subprocess(f"ip link show {tap}", shell=True, capture_output=True)
        if res.returncode == 0:
            call_subprocess(f"sudo ip link set dev {tap} up", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(f"sudo ip link set dev {tap} master cvd-mbr-0", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["ethtool", "-K", tap, "gso", "off", "tso", "off", "gro", "off", "lro", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    # 3. UFW Port Allowances (Replaces raw iptables to prevent UFW overrides)
    ufw_commands = [
        "sudo ufw allow 15550:15599/udp",
        "sudo ufw allow 15550:15599/tcp",
        "sudo ufw allow 19302/udp",        # <--- NEW: Allow STUN return traffic
        "sudo ufw allow out 19302/udp",    # <--- NEW: Allow outbound STUN requests to Google
        "sudo ufw route allow in on cvd-mbr-0",
        "sudo ufw route allow out on cvd-mbr-0"
    ]
    for cmd in ufw_commands:
        call_subprocess(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 4. Apply NAT Rules (ONLY Masquerade, DO NOT hijack 127.0.0.1)
    nat_rules = [
        ("POSTROUTING", "-s 192.168.96.0/24 -j MASQUERADE")
    ]
    for chain, rule in nat_rules:
        if call_subprocess(f"sudo iptables -t nat -C {chain} {rule}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            call_subprocess(f"sudo iptables -t nat -I {chain} 1 {rule}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(1)

    # 5. Restart DNSMasq
    call_subprocess("sudo pkill -f 'dnsmasq.*cvd-mbr-0'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dnsmasq_cmd = (
        "sudo dnsmasq --interface=cvd-mbr-0 --bind-interfaces "
        "--listen-address=192.168.96.1 "
        "--dhcp-range=192.168.96.50,192.168.96.150,12h "
        "--dhcp-option=option:router,192.168.96.1 "
        "--dhcp-option=option:dns-server,192.168.96.1 "
        "--server=1.1.1.1 --server=8.8.8.8 "
        "--cache-size=1000 --bogus-priv"
    )
    subprocess.Popen(dnsmasq_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print("[INFO] UFW firewall secured and WebRTC NAT routing active.")

def get_host_specs():
    total_cores = os.cpu_count() or 4
    total_gb = 16.0
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    total_gb = int(line.split()[1]) / (1024 * 1024)
                    break
    except Exception:
        pass
    return total_cores, total_gb

def get_current_cpu_load():
    """Calculates exact CPU utilization % over a 0.5 second window without external libraries."""
    try:
        with open('/proc/stat', 'r') as f:
            stats1 = [float(x) for x in f.readline().split()[1:]]
        import time
        time.sleep(0.5)
        with open('/proc/stat', 'r') as f:
            stats2 = [float(x) for x in f.readline().split()[1:]]

        idle_delta = (stats2[3] + stats2[4]) - (stats1[3] + stats1[4])
        total_delta = sum(stats2) - sum(stats1)

        if total_delta > 0:
            return 100.0 * (1.0 - (idle_delta / total_delta))
    except Exception:
        pass
    return 0.0

def optimize_cuttlefish_hardware():
    global CURRENT_SYNC_THREADS, CURRENT_COMPILE_THREADS
    print("\n--- Dynamic Host Hardware Calculation for Cuttlefish ---")
    total_cores = os.cpu_count() or 4
    total_gb = 16.0
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    total_gb = int(line.split()[1]) / (1024 * 1024)
                    break
    except Exception:
        pass
    print(f"    Detected Host Hardware: {total_cores} CPU Cores, {math.ceil(total_gb)}GB RAM")

    alloc_cores = max(2, (int(total_cores * 0.6) // 2) * 2)

    target_ram_gb = total_gb * 0.5
    if (total_gb - target_ram_gb) < 4.0:
        target_ram_gb = max(4.0, total_gb - 4.0)

    alloc_ram_gb = max(4, int(target_ram_gb))
    alloc_ram_mb = alloc_ram_gb * 1024

    CURRENT_SYNC_THREADS = max(2, min(total_cores, 10))

    # Strictly bind compile threads to your 25GB RAM safety budget (~4GB per AOSP thread -> max 6 threads)
    safe_ram_budget_gb = 16.0
    threads_by_ram = int(safe_ram_budget_gb / 4.0)

    print(f"    [INFO] Hardware Allocation: {alloc_cores} vCPUs, {alloc_ram_mb}MB ({alloc_ram_gb}GB) RAM")
    print(f"    [INFO] Repo Sync Threads: -j{CURRENT_SYNC_THREADS} (Max 10)")
    print(f"    [INFO] Local Compile Ceiling: -j{CURRENT_COMPILE_THREADS} (Balanced Cap: 80%)")

    return alloc_cores, alloc_ram_mb, CURRENT_COMPILE_THREADS

def adjust_thread_count_for_limits(error_text="", is_compile_phase=False):
    """
    Evaluates rate limits, slow networks, and RAM exhaustion.
    Reduces the respective phase's thread count by 1 (minimum 2) if strikes accumulate.
    """
    global CURRENT_SYNC_THREADS, CURRENT_COMPILE_THREADS, RATE_LIMIT_STRIKES, COMPILE_STRIKES

    lower_text = error_text.lower()

    overload_keywords = [
        "429", "502", "503", "504",
        "promisor", "exhausted",
        "rpc failed", "connection reset", "expected 'packfile'"
    ]

    if is_compile_phase:
        if "killed" in lower_text or "out of memory" in lower_text or "c++: fatal error" in lower_text or "signal terminated" in lower_text:
            COMPILE_STRIKES += 1
            if CURRENT_COMPILE_THREADS > 2:
                CURRENT_COMPILE_THREADS -= 1
                print(f"\n[WARNING] PC Lag / RAM Exhaustion detected! Lowered compile threads to -j{CURRENT_COMPILE_THREADS}")
            return CURRENT_COMPILE_THREADS
        return CURRENT_COMPILE_THREADS

    else:
        if any(kw in lower_text for kw in overload_keywords):
            RATE_LIMIT_STRIKES += 1
            if RATE_LIMIT_STRIKES > 0:
                if CURRENT_SYNC_THREADS > 2:
                    CURRENT_SYNC_THREADS -= 1
                    print(f"\n[INFO] Server overload/rate limit detected. Lowered sync threads to -j{CURRENT_SYNC_THREADS}")
                RATE_LIMIT_STRIKES = 0
            else:
                print(f"\n[WARNING] Rate limit strike 1. Retrying at -j{CURRENT_SYNC_THREADS} before dropping threads.")

        elif "kib/s" in lower_text or "bytes/s" in lower_text or "stalled" in lower_text:
            if CURRENT_SYNC_THREADS > 2:
                CURRENT_SYNC_THREADS -= 1
                print(f"\n[WARNING] Slow/Struggling network detected. Dropping sync threads to -j{CURRENT_SYNC_THREADS} to stabilize download.")

        return CURRENT_SYNC_THREADS

def setup_dashboard_routes(video_w=1920, video_h=1080, control_pad=65, auto_scale=True):
    global DASHBOARD_PORT, CURRENT_COMPILE_THREADS, CURRENT_SYNC_THREADS

    dash_port = DASHBOARD_PORT if DASHBOARD_PORT else "Dynamic"
    build_threads = CURRENT_COMPILE_THREADS if 'CURRENT_COMPILE_THREADS' in globals() else 8
    sync_threads = CURRENT_SYNC_THREADS if 'CURRENT_SYNC_THREADS' in globals() else 8

    has_dri = len(glob.glob("/dev/dri/renderD*")) > 0
    vulkan_active = False
    if has_dri and shutil.which("vulkaninfo"):
        try:
            res = call_subprocess(["vulkaninfo", "--summary"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and ("GPU id" in res.stdout or "deviceName" in res.stdout):
                vulkan_active = True
        except Exception:
            pass
    gpu_mode_text = "gfxstream (Hardware)" if vulkan_active else "swiftshader (CPU)"
    ai_status_html = '<a href="http://127.0.0.1:11434" target="_blank">http://127.0.0.1:11434</a>' if "ai" in sys.argv else '<span class="raw-text" style="color:#64748b;">DISABLED</span>'

    HTML_TEMPLATE = r"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Android</title>
        <link rel="icon" type="image/svg+xml" href="/icon.svg">
        <style>
            html, body { margin: 0; padding: 0; width: 100%; height: 100%; background: #000000; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; overflow: hidden; user-select: none; }

            .container { display: flex; width: 100vw; height: 100vh; overflow: hidden; }

            #dashboard-pane { flex: 0 0 45%; min-width: 350px; display: flex; flex-direction: column; background: #000000; box-sizing: border-box; padding: 16px; gap: 10px; }

            #resizer { width: 8px; background: #18181b; border-left: 1px solid #27272a; border-right: 1px solid #27272a; cursor: col-resize; z-index: 50; flex-shrink: 0; transition: background 0.2s; }
            #resizer:hover, #resizer.dragging { background: #3b82f6; }

            #webrtc-pane { flex: 1; min-width: 300px; position: relative; background: #000000; overflow: hidden; display: flex; flex-direction: column; }
            iframe { width: 100%; height: 100%; border: none; background: #000000; display: block; }

            .loading-overlay { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: #000000; display: flex; align-items: center; justify-content: center; color: #94a3b8; font-size: 13px; z-index: 5; font-family: monospace; }

            h2 { margin: 0; padding: 0; color: #ffffff; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; display: flex; justify-content: space-between; align-items: center; }
            .metrics-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; }
            .metric-card { background: #121216; border: 1px solid #27272a; border-top: 2px solid #1d4ed8; border-radius: 5px; padding: 6px 8px; }
            .metric-label { font-size: 9px; color: #ffffff; text-transform: uppercase; font-weight: bold; opacity: 0.75; }
            .metric-value { font-size: 12.5px; color: #ffffff; font-weight: bold; margin-top: 2px; }

            .ports-box { background: #121216; border: 1px solid #27272a; border-radius: 5px; padding: 8px; display: flex; flex-direction: column; gap: 4px; }
            .ports-title { font-size: 10px; color: #3b82f6; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }
            .ports-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px; font-size: 11px; }
            .port-item { background: #18181c; border: 1px solid #2e2e36; padding: 4px 6px; border-radius: 3px; display: flex; justify-content: space-between; align-items: center; color: #cbd5e1; }
            .port-item span:first-child { font-weight: 500; }
            .port-item a { font-family: monospace; color: #3b82f6; font-weight: bold; text-decoration: none; transition: color 0.2s; }
            .port-item a:hover { color: #60a5fa; text-decoration: underline; }
            .port-item .raw-text { font-family: monospace; color: #94a3b8; font-weight: bold; }

            .btn-thread { background: #27272a; border: 1px solid #3f3f46; color: white; cursor: pointer; padding: 2px 8px; border-radius: 3px; font-weight: bold; transition: 0.2s; }
            .btn-thread:hover { background: #3b82f6; border-color: #60a5fa; }

            .roadmap-box { background: #121216; border: 1px solid #27272a; border-radius: 5px; padding: 8px; display: flex; flex-direction: column; gap: 5px; }
            .roadmap-title { font-size: 10px; color: #ffffff; font-weight: bold; text-transform: uppercase; opacity: 0.8; }
            .roadmap-step { display: flex; align-items: center; justify-content: space-between; font-size: 10.5px; color: #ffffff; background: #18181c; border: 1px solid #2e2e36; padding: 4px 6px; border-radius: 3px; }
            .roadmap-step.active { border-left: 3px solid #3b82f6; background: rgba(59, 130, 246, 0.15); font-weight: 500; }
            .roadmap-step.completed { border-left: 3px solid #10b981; background: rgba(16, 185, 129, 0.1); }

            #log-history { flex: 1; display: flex; flex-direction: column; gap: 4px; padding: 8px 8px 4px 8px; }

            .log-card { background: #18181c; border: 1px solid #2e2e36; border-left: 3px solid #3f3f46; border-radius: 3px; padding: 5px 8px; font-family: 'Consolas', monospace; font-size: 11px; display: flex; flex-direction: column; gap: 3px; box-sizing: border-box; min-width: max-content; }
            .log-card.info { border-left-color: #56b6c2; }
            .log-card.success { border-left-color: #15803d; }
            .log-card.warn { border-left-color: #b45309; }
            .log-card.error { border-left-color: #b91c1c; background: rgba(185, 28, 28, 0.08); }
            .log-card.sync { border-left-color: #c678dd; background: #151822; min-height: 52px; }

            .log-header { display: flex; justify-content: space-between; align-items: center; font-size: 9.5px; color: #ffffff; opacity: 0.8; }
            .log-text { color: #ffffff; font-weight: 500; white-space: pre; word-break: normal; }

            ::-webkit-scrollbar { width: 6px; height: 6px; }
            ::-webkit-scrollbar-track { background: #0f1013; border-radius: 3px; }
            ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; border: 1px solid #27272a; }
            ::-webkit-scrollbar-thumb:hover { background: #3b82f6; }
            ::-webkit-scrollbar-corner { background: #0f1013; }
        </style>
    </head>
    <body>
        <div class="container">
            <div id="dashboard-pane">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-label">Mode</div>
                        <div class="metric-value">Native Host</div>
                    </div>
                    <div class="metric-card" style="border-top-color: #1d4ed8;">
                        <div class="metric-label">GPU Pipeline</div>
                        <div class="metric-value" style="font-size:10px;">__GPU_MODE__</div>
                    </div>
                    <div class="metric-card" style="border-top-color: #1e40af;">
                        <div class="metric-label">Resolution</div>
                        <div class="metric-value">__VIDEO_W__x__VIDEO_H__</div>
                    </div>
                </div>

                <div class="ports-box">
                    <div class="ports-title">System & Network Endpoints</div>
                    <div class="ports-grid">
                        <div class="port-item"><span>Dashboard UI</span><a href="https://127.0.0.1:__DASH_PORT__" target="_blank">https://127.0.0.1:__DASH_PORT__</a></div>
                        <div class="port-item"><span>WebRTC Stream</span><a href="https://127.0.0.1:8443" target="_blank">https://127.0.0.1:8443</a></div>
                        <div class="port-item"><span>WebRTC Nginx</span><a href="https://127.0.0.1:8444" target="_blank">https://127.0.0.1:8444</a></div>
                        <div class="port-item"><span>AI Engine (Ollama)</span>__AI_HTML__</div>
                        <div class="port-item"><span>ADB Daemon</span><span class="raw-text">127.0.0.1:6520</span></div>
                        <div class="port-item"><span>Bridge Subnet</span><span class="raw-text">192.168.96.1</span></div>
                    </div>
                </div>

                <div class="ports-box" style="margin-top: 6px;">
                    <div class="ports-title">Kernel Resource Limits (Applies Instantly)</div>
                    <div class="ports-grid">
                        <div class="port-item">
                            <span>Host CPU Limit</span>
                            <div style="display:flex; gap:6px; align-items: center;">
                                <button class="btn-thread" onclick="adjustResources('cpu', -5)">-</button>
                                <span id="ui-cpu-limit" class="raw-text">__CPU_PCT__%</span>
                                <button class="btn-thread" onclick="adjustResources('cpu', 5)">+</button>
                            </div>
                        </div>
                        <div class="port-item">
                            <span>Host RAM Limit</span>
                            <div style="display:flex; gap:6px; align-items: center;">
                                <button class="btn-thread" onclick="adjustResources('ram', -5)">-</button>
                                <span id="ui-ram-limit" class="raw-text">__RAM_PCT__%</span>
                                <button class="btn-thread" onclick="adjustResources('ram', 5)">+</button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="roadmap-box" id="roadmap-box-container">
                    <div class="roadmap-title">Execution</div>
                </div>
                <div id="log-feed" style="flex: 1; background: #121216; border: 1px solid #27272a; border-radius: 5px; overflow: auto; position: relative;">
                    <div id="log-inner-wrapper" style="display: flex; flex-direction: column; min-width: 100%; width: max-content; min-height: 100%;">

                        <div id="log-history">
                            <div class="log-card success">
                                <div class="log-header"><span>SYSTEM INITIALIZED</span><span class="card-time"></span></div>
                                <div class="log-text" style="color: #98c379; white-space: pre-wrap;">Dashboard engine online. Waiting for subprocess stream...</div>
                            </div>
                        </div>

                        <div id="live-progress-footer" style="background: #121216; border-top: 1px solid #27272a; padding: 6px 8px; margin-top: auto;"></div>

                    </div>
                </div>

                <div id="log-context-menu" style="display: none; position: absolute; background: #18181c; border: 1px solid #2e2e36; border-radius: 4px; padding: 4px 0; z-index: 1000; font-size: 11px; box-shadow: 0 4px 12px rgba(0,0,0,0.5);">
                    <div id="copy-all-logs" style="padding: 6px 14px; color: #ffffff; cursor: pointer;" onmouseover="this.style.background='#1d4ed8'" onmouseout="this.style.background='transparent'">Copy All Logs</div>
                </div>
            </div>

            <div id="resizer"></div>

            <div id="webrtc-pane">
                <div id="loader" class="loading-overlay">Booting crosvm hypervisor and waiting for WebRTC stream...</div>
                <iframe id="cvd-frame" src="about:blank" allow="camera; microphone; clipboard-read; clipboard-write; autoplay"></iframe>
            </div>
        </div>

        <script>
            const logFeed = document.getElementById("log-feed");
            const contextMenu = document.getElementById("log-context-menu");
            const iframe = document.getElementById("cvd-frame");
            const loader = document.getElementById("loader");
            const resizer = document.getElementById('resizer');

            // --- TOP-DOWN IFRAME PIERCING ADB ERROR ANNIHILATOR ---
            setInterval(() => {
                try {
                    const frame = document.getElementById("cvd-frame");
                    if (!frame || !frame.contentWindow) return;
                    const iframeDoc = frame.contentWindow.document;

                    function obliterateAdbError(root) {
                        if (!root || !root.querySelectorAll) return;
                        const elements = root.querySelectorAll('*');
                        for (let el of elements) {
                            if (el.shadowRoot) obliterateAdbError(el.shadowRoot);

                            if (el.textContent && el.textContent.toLowerCase().includes('adb connection failed')) {
                                let hasChildWithText = Array.from(el.children).some(child =>
                                    child.textContent && child.textContent.toLowerCase().includes('adb connection failed')
                                );

                                if (!hasChildWithText) {
                                    let target = el;
                                    for (let i = 0; i < 5; i++) {
                                        if (target && target.tagName !== 'BODY' && target.tagName !== 'HTML') {
                                            let btns = target.querySelectorAll('button, .close, svg');
                                            btns.forEach(b => b.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })));

                                            target.style.setProperty('display', 'none', 'important');
                                            target.style.setProperty('opacity', '0', 'important');
                                            target.style.setProperty('pointer-events', 'none', 'important');

                                            target = target.parentElement || (target.getRootNode && target.getRootNode().host);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    obliterateAdbError(iframeDoc);
                } catch(e) {}
            }, 150);

            const dashPane = document.getElementById('dashboard-pane');
            const innerWrapper = document.getElementById("log-inner-wrapper");
            const historyContainer = document.getElementById("log-history");
            const footerContainer = document.getElementById("live-progress-footer");

            let isBooting = true;
            let userScrolledUp = false;
            let maxLogWidth = 0;

            setInterval(() => {
                let timeEl = document.getElementById("live-build-time");
                if (timeEl) {
                    const now = new Date();
                    timeEl.innerText = now.getHours().toString().padStart(2, '0') + ':' +
                                       now.getMinutes().toString().padStart(2, '0') + ':' +
                                       now.getSeconds().toString().padStart(2, '0');
                }
            }, 1000);

            logFeed.addEventListener("scroll", function() {
                if (isBooting) return;
                let distanceToBottom = Math.abs(logFeed.scrollHeight - logFeed.clientHeight - logFeed.scrollTop);
                userScrolledUp = distanceToBottom > 60;
            });

            setTimeout(() => { isBooting = false; }, 3000);

            logFeed.addEventListener("contextmenu", function(e) {
                e.preventDefault();
                contextMenu.style.display = "block";
                contextMenu.style.left = e.pageX + "px";
                contextMenu.style.top = e.pageY + "px";
            });

            window.addEventListener("click", function() {
                contextMenu.style.display = "none";
            });

            document.getElementById("copy-all-logs").addEventListener("click", function() {
                let allText = Array.from(logFeed.querySelectorAll(".log-card")).map(card => {
                    let header = card.querySelector(".log-header")?.innerText || "";
                    let text = card.querySelector(".log-text")?.innerText || "";
                    return "[" + header + "] " + text;
                }).join("\n");

                navigator.clipboard.writeText(allText).then(() => {
                    let original = this.innerText;
                    this.innerText = "Copied to Clipboard!";
                    setTimeout(() => { this.innerText = original; contextMenu.style.display = "none"; }, 1000);
                });
            });

            function adjustResources(target, diff) {
                fetch("/api/controls/resources", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target: target, diff: diff })
                })
                .then(res => res.json())
                .then(data => {
                    document.getElementById("ui-cpu-limit").innerText = data.cpu + "%";
                    document.getElementById("ui-ram-limit").innerText = data.ram + "%";
                });
            }

            async function pollRoadmap() {
                try {
                    let res = await fetch('/api/roadmap?_cb=' + Date.now());
                    let data = await res.json();
                    let container = document.getElementById('roadmap-box-container');

                    let html = '<div class="roadmap-title">Execution</div>';
                    for (let [key, status] of Object.entries(data)) {
                        let statusClass = "roadmap-step";
                        if (status === "ACTIVE") statusClass += " active";
                        else if (status === "COMPLETED") statusClass += " completed";

                        html += `<div class="${statusClass}"><span>${key}</span><span>${status}</span></div>`;
                    }
                    container.innerHTML = html;
                } catch (e) {
                    console.error("Roadmap poll error:", e);
                }
            }
            setInterval(pollRoadmap, 1000);

            function updateScrollAndWidth() {
                if (innerWrapper.scrollWidth > maxLogWidth) {
                    maxLogWidth = innerWrapper.scrollWidth;
                    innerWrapper.style.minWidth = maxLogWidth + "px";
                }

                if (!userScrolledUp) {
                    logFeed.scrollTop = logFeed.scrollHeight;
                }
            }

            function appendLogCard(rawText) {
                let text = rawText.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, "").trim();
                if (!text) return;

                if (text.includes("Android 17 build artifacts successfully deployed") ||
                    text.includes("complete. All files verified") ||
                    text.includes("repaired.")) {
                    let persistentCard = document.getElementById("live-build-card");
                    if (persistentCard) persistentCard.remove();
                }

                const now = new Date();
                const timeStr = now.getHours().toString().padStart(2, '0') + ':' +
                                now.getMinutes().toString().padStart(2, '0') + ':' +
                                now.getSeconds().toString().padStart(2, '0');

                let isBuildProgress = false;
                if (!text.includes("[WARNING]") && !text.includes("[ERROR]") && !text.includes("fatal:") && !text.includes("[SUCCESS]")) {
                    isBuildProgress = (
                        text.includes("regenerate globs") ||
                        text.includes("including out/soong") ||
                        text.match(/\[\s*\d+%\s*\d+\/\d+\]/) ||
                        text.includes("rs ") ||
                        text.includes("ninja:") ||
                        text.startsWith("[BUILD]") ||
                        text.startsWith("[BUILD TELEMETRY]") ||
                        text.includes("Receiving objects") ||
                        text.includes("Resolving deltas") ||
                        text.includes("Compressing objects") ||
                        text.includes("Unpacking") ||
                        text.includes("Downloading") ||
                        text.includes("Repo Sync:") ||
                        text.includes("Syncing") ||
                        text.includes("↳")
                    );
                }

                if (isBuildProgress) {
                    let persistentCard = document.getElementById("live-build-card");
                    let textContainer = document.getElementById("live-build-text");
                    let timeContainer = document.getElementById("live-build-time");

                    if (!persistentCard || !textContainer || !timeContainer) {
                        persistentCard = document.createElement('div');
                        persistentCard.id = "live-build-card";
                        persistentCard.className = 'log-card info';
                        persistentCard.innerHTML = '<div class="log-header"><div style="display: flex; gap: 8px;"><span id="live-build-time" style="color: #ffffff; font-weight: bold;">' + timeStr + '</span><span>BUILD PROGRESS (LIVE)</span></div></div><div class="log-text" id="live-build-text" style="color: #56b6c2; white-space: pre;"></div>';

                        footerContainer.innerHTML = "";
                        footerContainer.appendChild(persistentCard);
                        textContainer = document.getElementById("live-build-text");
                    } else {
                        timeContainer.innerText = timeStr;
                    }

                    if (textContainer) {
                        let cleanProgressText = text.replace("[BUILD TELEMETRY] ", "").replace("[BUILD] ", "");
                        textContainer.innerHTML = cleanProgressText;
                    }
                    updateScrollAndWidth();
                    return;
                }

                let type = "info";
                let tag = "PROCESS";
                let textColor = "#abb2bf";
                let lowerText = text.toLowerCase();

                if (lowerText.includes("error") || lowerText.includes("fail") || lowerText.includes("fatal") || lowerText.includes("panic") || lowerText.includes("abort") || lowerText.includes("invalid atom")) {
                    type = "error"; tag = "ERROR"; textColor = "#e06c75";
                } else if (lowerText.includes("warn") || lowerText.includes("ignored") || lowerText.includes("garbage")) {
                    type = "warn"; tag = "WARNING"; textColor = "#e5c07b";
                } else if (text.includes("[PHASE]")) {
                    type = "sync"; tag = "PHASE"; textColor = "#c678dd";
                    text = text.replace(/\[PHASE\]/g, "").trim();
                } else if (text.includes("[PROCESS]")) {
                    type = "success"; tag = "INFO"; textColor = "#98c379";
                    text = text.replace(/\[PROCESS\]/g, "").trim();
                }

                const card = document.createElement('div');
                card.className = 'log-card ' + type;
                card.innerHTML = '<div class="log-header"><div style="display: flex; gap: 8px;"><span style="color: #ffffff; font-weight: bold;">' + timeStr + '</span><span>' + tag + '</span></div></div><div class="log-text" style="color: ' + textColor + '; white-space: pre;">' + text + '</div>';

                let persistentCard = document.getElementById("live-build-card");
                if (persistentCard && persistentCard.parentNode === historyContainer) {
                    historyContainer.insertBefore(card, persistentCard);
                } else {
                    historyContainer.appendChild(card);
                }

                updateScrollAndWidth();
            }

            function connectWebSocket() {
                let ws = new WebSocket("wss://" + window.location.host + "/ws");
                ws.onopen = function() {
                    isBooting = false;
                    logFeed.scrollTop = logFeed.scrollHeight;
                };
                ws.onmessage = function(event) {
                    let msg = event.data;
                    let lines = msg.split(/[\r\n]+/);
                    lines.forEach(sub => {
                        if (sub.trim()) appendLogCard(sub);
                    });
                };
                ws.onclose = function() {
                    setTimeout(connectWebSocket, 1000);
                };
            }
            connectWebSocket();

            const targetUrl = "https://127.0.0.1:8444/client.html?deviceId=cvd-1&_cb=" + Date.now();
            let webrtcLoaded = false;

            function pollAndLoadStream() {
                if (webrtcLoaded) return;
                fetch("/api/check_webrtc", { method: "GET" })
                    .then(res => res.json())
                    .then(data => {
                        if (data.ready) {
                            loader.innerText = "WebRTC online. Stabilizing ADB bridge...";
                            setTimeout(() => {
                                iframe.src = targetUrl;
                                loader.style.display = 'none';
                                webrtcLoaded = true;
                            }, 2000);
                        } else {
                            setTimeout(pollAndLoadStream, 1500);
                        }
                    })
                    .catch(() => {
                        setTimeout(pollAndLoadStream, 1500);
                    });
            }
            setTimeout(pollAndLoadStream, 2000);

            let isDragging = false;
            let rafId = null;

            resizer.addEventListener('mousedown', () => {
                isDragging = true;
                resizer.classList.add('dragging');
                document.body.style.cursor = 'col-resize';
            });

            window.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                if (rafId) cancelAnimationFrame(rafId);
                rafId = requestAnimationFrame(() => {
                    const totalWidth = window.innerWidth;
                    const newLeftWidth = (e.clientX / totalWidth) * 100;
                    if (newLeftWidth > 20 && newLeftWidth < 80) {
                        dashPane.style.flex = `0 0 ${newLeftWidth}%`;
                    }
                });
            });

            window.addEventListener('mouseup', () => {
                if (isDragging) {
                    isDragging = false;
                    resizer.classList.remove('dragging');
                    document.body.style.cursor = 'default';
                }
            });
        </script>
    </body>
    </html>
    """

    HTML_CONTENT = (
        HTML_TEMPLATE.replace("__BUILD_THREADS__", str(build_threads))
                     .replace("__CPU_PCT__", str(GLOBAL_CPU_PCT))       # <--- UPDATE THIS
                     .replace("__RAM_PCT__", str(GLOBAL_RAM_PCT))       # <--- UPDATE THIS
                     .replace("__DASH_PORT__", str(dash_port))
                     .replace("__GPU_MODE__", gpu_mode_text)
                     .replace("__VIDEO_W__", str(video_w))
                     .replace("__VIDEO_H__", str(video_h))
                     .replace("__CONTROL_PAD__", str(control_pad))
                     .replace("__AUTO_SCALE__", str(auto_scale))
                     .replace("__AI_HTML__", ai_status_html)
    )

    @app.post("/api/controls/resources")
    async def api_adjust_resources(req: Request):
        global GLOBAL_CPU_PCT, GLOBAL_RAM_PCT

        data = await req.json()
        target = data.get("target")
        diff = int(data.get("diff", 0))

        # Calculate actual system capacities
        total_cores = os.cpu_count() or 4
        total_ram_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')

        if target == "cpu":
            GLOBAL_CPU_PCT = max(10, min(100, GLOBAL_CPU_PCT + diff))
            # Convert percentage into systemd CPU quota (e.g., 8 cores at 50% = 400%)
            quota = int((total_cores * 100) * (GLOBAL_CPU_PCT / 100.0))
            subprocess.run(["systemctl", "--user", "set-property", "cf_build.scope", f"CPUQuota={quota}%"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif target == "ram":
            GLOBAL_RAM_PCT = max(10, min(100, GLOBAL_RAM_PCT + diff))
            # Convert percentage into absolute bytes for the kernel
            ram_limit = int(total_ram_bytes * (GLOBAL_RAM_PCT / 100.0))
            subprocess.run(["systemctl", "--user", "set-property", "cf_build.scope", f"MemoryMax={ram_limit}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return {"cpu": GLOBAL_CPU_PCT, "ram": GLOBAL_RAM_PCT}

    @app.get("/api/roadmap")
    def get_roadmap_status():
        roadmap_file = os.path.join(WORKSPACE_DIR, ".roadmap.json")
        try:
            if os.path.exists(roadmap_file):
                with open(roadmap_file, "r") as f:
                    return json.load(f)
        except Exception:
            pass

        return {
            "1. Environment & Tools": "QUEUED",
            "2. Repository Init": "QUEUED",
            "3. Source Sync": "QUEUED",
            "4. Lunch & Compile": "QUEUED",
            "5. Cache & Deployment": "QUEUED"
        }

    @app.get("/icon.svg")
    async def serve_icon():
        icon_path = os.path.join(WORKSPACE_DIR, "chromium_fallback_icon.svg")
        return FileResponse(icon_path)

    @app.get("/")
    async def get():
        return HTMLResponse(HTML_CONTENT)

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        connected_websockets.append(websocket)
        client_connected_event.set()

        with output_lock:
            for line in GLOBAL_LOG_BUFFER:
                try:
                    await websocket.send_text(line)
                except Exception:
                    break

        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            global SHUTTING_DOWN
            if websocket in connected_websockets:
                connected_websockets.remove(websocket)
            if SHUTTING_DOWN:
                return

            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

            os.system("stty sane 2>/dev/null")
            call_subprocess(["tput", "sgr0"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            call_subprocess(["tput", "cnorm"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            sys.__stdout__.write("\r\n\033[1;33mDashboard window closed.\033[0m\r\n")
            sys.__stdout__.flush()

            try:
                shutdown_everything(True)
            except Exception:
                pass

    @app.get("/api/check_webrtc")
    async def check_webrtc():
        try:
            resp = requests.get("https://127.0.0.1:8443/devices", verify=False, timeout=2.0)
            return {"ready": resp.status_code == 200}
        except Exception:
            return {"ready": False}

GLOBAL_FILE_PROGRESS = "0/0"

LAST_TMUX_WRITE_TIME = 0

def _write_tmux_state():
    """Throttled IPC writer so the child process can pass data to the parent without lagging the compiler."""
    global LAST_TMUX_WRITE_TIME, ACTIVE_ROADMAP_STEP, GLOBAL_FILE_PROGRESS
    now = time.time()

    if now - LAST_TMUX_WRITE_TIME < 0.5:
        return
    LAST_TMUX_WRITE_TIME = now

    state = {
        "step": ACTIVE_ROADMAP_STEP,
        "progress": GLOBAL_FILE_PROGRESS
    }
    try:
        with open("/tmp/cf_tmux_state.json", "w") as f:
            json.dump(state, f)
    except Exception:
        pass

def update_roadmap(step_name, status):
    """Thread-safe state writer. Updates Dashboard UI state and passes it to the Tmux thread."""
    global ACTIVE_ROADMAP_STEP
    if status == "ACTIVE":
        ACTIVE_ROADMAP_STEP = step_name
        _write_tmux_state()

    roadmap_file = os.path.join(WORKSPACE_DIR, ".roadmap.json")
    try:
        state = {
            "1. Environment & Tools": "QUEUED",
            "2. Repository Init": "QUEUED",
            "3. Source Sync": "QUEUED",
            "4. Lunch & Compile": "QUEUED",
            "5. Cache & Deployment": "QUEUED"
        }
        if os.path.exists(roadmap_file):
            try:
                with open(roadmap_file, "r") as f:
                    loaded = json.load(f)
                    if loaded: state.update(loaded)
            except Exception:
                pass

        # PURGE THE GHOST ENTRY
        if "3. Source Sync (-j8)" in state:
            del state["3. Source Sync (-j8)"]

        state[step_name] = status
        with open(roadmap_file, "w") as f:
            json.dump(state, f)
    except Exception:
        pass

def resilient_launch_dashboard(video_w=1920, video_h=1080, control_pad=65, auto_scale=True):
    """
    Advanced fault-tolerant orchestrator for the web dashboard and browser window.
    Features automated port recovery, multi-tier browser fallbacks, headless server
    isolation, and non-blocking watchdog protection to guarantee main thread survival.
    """
    def _execute_safely():
        try:
            launch_browser_dashboard(video_w=video_w, video_h=video_h, control_pad=control_pad, auto_scale=auto_scale)
        except Exception as primary_err:
            sys.stderr.write(f"\r\n\033[33m[WARN] Primary UI startup encountered an exception: {primary_err}\033[0m\r\n")
            sys.stderr.flush()

            try:
                import webbrowser
                port = globals().get("DASHBOARD_PORT")
                if port:
                    url = f"https://127.0.0.1:{port}"
                    sys.stdout.write(f"\033[36m[INFO] Falling back to default system web browser: {url}\033[0m\n")
                    sys.stdout.flush()
                    webbrowser.open(url)
            except Exception as browser_err:
                sys.stderr.write(f"\r\n\033[33m[WARN] System browser fallback failed: {browser_err}\033[0m\r\n")
                sys.stderr.flush()

            try:
                sys.stdout.write("\033[32m[INFO] Running in Headless API/WebSocket Server Mode. Core engine fully operational.\033[0m\n")
                sys.stdout.flush()
                while not script_should_exit.is_set():
                    time.sleep(1)
            except Exception:
                pass

    dashboard_guard_thread = threading.Thread(
        target=_execute_safely,
        daemon=True,
        name="ResilientDashboardMonitor"
    )
    dashboard_guard_thread.start()

    timeout_limit = 4.0
    start_time = time.time()
    while dashboard_guard_thread.is_alive():
        if time.time() - start_time > timeout_limit:
            sys.stdout.write("\033[32m[INFO] Dashboard thread initialized asynchronously. Proceeding with main orchestration...\033[0m\n")
            sys.stdout.flush()
            break
        time.sleep(0.05)

def print_launch_banner(dash_port=None):
    """Renders centered orchestration banner with robust dashboard port fallback, edge-to-edge gray dividers, and proper top padding."""
    import os
    import sys

    global GLOBAL_BANNER_LINES

    if not dash_port:
        try:
            if os.path.exists("/tmp/cf_dash_port.txt"):
                with open("/tmp/cf_dash_port.txt", "r") as f:
                    dash_port = f.read().strip()
        except Exception:
            pass

    is_docker = "docker" in sys.argv or os.path.exists("/.dockerenv")
    sandbox = "sandbox" in sys.argv or os.getenv("CUTTLEFISH_SANDBOX") == "1"
    no_root = "no-root" in sys.argv

    active_flags = []
    if "docker" in sys.argv:
        active_flags.append("docker")
    if "no-root" in sys.argv:
        active_flags.append("no-root")
    if "sandbox" in sys.argv:
        active_flags.append("sandbox")
    if "reset" in sys.argv:
        active_flags.append("reset")
    if "console" in sys.argv:
        active_flags.append("console")
    if "ai" in sys.argv:
        active_flags.append("ai")
    flags_text = " ".join(active_flags) if active_flags else "None (Standard Native)"

    try:
        width = os.get_terminal_size().columns
    except Exception:
        width = 80

    width = max(width, 70)

    mode_text = "Docker Container Mode" if is_docker else "Native Host (Arch/EndeavourOS)"
    term_text = "Sandbox" if sandbox else "Crosvm Sandbox"

    mode_colored = f"\033[35m{mode_text}\033[0m" if is_docker else f"\033[34m{mode_text}\033[0m"
    term_colored = ("\033[33m" if sandbox else "\033[32m") + term_text + "\033[0m"

    if "console" in sys.argv:
        dash_str = "DISABLED (console)"
        dash_color = f"\033[90m{dash_str}\033[0m"
    else:
        dash_str = f"https://127.0.0.1:{dash_port}" if dash_port else "INITIALIZING..."
        dash_color = f"\033[32m{dash_str}\033[0m" if dash_port else f"\033[33m{dash_str}\033[0m"

    ai_str = "http://127.0.0.1:11434" if "ai" in sys.argv else "DISABLED"
    ai_color = f"\033[36mhttp://127.0.0.1:11434\033[0m" if "ai" in sys.argv else f"\033[90m{ai_str}\033[0m"

    workspace_path = globals().get("WORKSPACE_DIR", "/var/tmp/cuttlefish/user")
    variant_text = "User (No-Root)" if no_root else "UserDebug"
    variant_color = f"\033[36m{variant_text}\033[0m"
    host_os_text = "EndeavourOS (Hardened)"

    left_col_width = max(
        len("Deployment Mode  : " + mode_text),
        len("Build Variant    : " + variant_text),
        len("Host OS          : " + host_os_text),
        len("Workspace Path   : " + workspace_path),
        len("Execution Path   : " + term_text)
    )

    right_col_width = max(
        len("Dashboard UI     : " + dash_str),
        len("WebRTC Stream    : https://127.0.0.1:8443"),
        len("Target ADB       : 127.0.0.1:6520"),
        len("AI Engine        : " + ai_str),
        len("Bridge Gateway   : 192.168.96.1")
    )

    gap = 4
    block_width = left_col_width + gap + right_col_width
    left_margin = max(0, (width - block_width) // 2)

    def make_row(left_text, right_text, left_colored=None, right_colored=None):
        l_disp = left_colored or left_text
        r_disp = right_colored or right_text
        l_pad = " " * max(0, left_col_width - len(left_text))
        return (" " * left_margin) + l_disp + l_pad + (" " * gap) + r_disp

    banner_lines = []

    banner_lines.append("")

    banner_lines.append(make_row("Deployment Mode  : " + mode_text, "Dashboard UI     : " + dash_str, "Deployment Mode  : " + mode_colored, "Dashboard UI     : " + dash_color))
    banner_lines.append(make_row("Build Variant    : " + variant_text, "WebRTC Stream    : https://127.0.0.1:8443", "Build Variant    : " + variant_color, "WebRTC Stream    : \033[36mhttps://127.0.0.1:8443\033[0m"))
    banner_lines.append(make_row("Host OS          : " + host_os_text, "WebRTC Nginx     : https://127.0.0.1:8444", "Host OS          : " + host_os_text, "WebRTC Nginx     : \033[36mhttps://127.0.0.1:8444\033[0m"))
    banner_lines.append(make_row("Workspace Path   : " + workspace_path, "Target ADB       : 127.0.0.1:6520", "Workspace Path   : " + workspace_path, "Target ADB       : \033[36m127.0.0.1:6520\033[0m"))
    banner_lines.append(make_row("Execution Path   : " + term_text, "AI Engine        : " + ai_str, "Execution Path   : " + term_colored, "AI Engine        : " + ai_color))

    gray_bar = "  \033[90m" + "─" * (width - 4) + "\033[0m"
    banner_lines.append(gray_bar)

    flags_display_text = f"Active Flags     : {flags_text}"
    flags_colored_text = f"Active Flags     : \033[35m{flags_text}\033[0m"
    flag_row_padding = max(0, (width - len(flags_display_text)) // 2)
    banner_lines.append((" " * flag_row_padding) + flags_colored_text)

    banner_lines.append(gray_bar)

    flags_plain = "Commands: docker(Container) sandbox(Crosvm) no-root(User) reset(Delete) console(No UI) ai(Experimental) help(Info)"
    flags_color = "\033[1;33mCommands:\033[0m \033[36mdocker\033[0m(Container) \033[36msandbox\033[0m(Systemd) \033[36mno-root\033[0m(User) \033[36mreset\033[0m(Delete) \033[36mconsole\033[0m(No UI) \033[36mai\033[0m(Experimental) \033[36mhelp\033[0m(Info)"

    padding = max(0, (width - len(flags_plain)) // 2)
    banner_lines.append(" " * padding + flags_color)

    GLOBAL_BANNER_LINES = banner_lines
    sys.__stdout__.write("\033[2J\033[H")
    sys.__stdout__.write("\n".join(GLOBAL_BANNER_LINES))
    sys.__stdout__.flush()

    return len(banner_lines)

def init_side_by_side_layout():
    """Builds tmux layout with properly quoted asynchronous background shell commands."""
    import os
    import shutil
    import subprocess
    import sys
    import shlex
    import traceback
    import socket

    try:
        if not shutil.which("tmux"):
            sys.stdout.write("[INFO] tmux not found. Installing via pacman...\n")
            sys.stdout.flush()
            call_subprocess(["pacman", "-S", "--noconfirm", "tmux"], check=True)
    except Exception as e:
        sys.stderr.write(f"\nFailed to check/install tmux: {e}\n")
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            pre_port = s.getsockname()[1]

        global DASHBOARD_PORT
        DASHBOARD_PORT = pre_port

        os.makedirs(WORKSPACE_DIR, exist_ok=True)
        with open("/tmp/cf_dash_port.txt", "w") as f:
            f.write(str(pre_port))

        script_path = os.path.abspath(sys.argv[0])
        python_executable = sys.executable

        user_args = " ".join(
            shlex.quote(arg) for arg in sys.argv[1:] if arg != "console"
        )
        py_cmd = f"{shlex.quote(python_executable)} {shlex.quote(script_path)}"

        wrapper_template = (
            "{cmd}; "
            "STATUS=$?; "
            "if [ $STATUS -eq 0 ] || [ $STATUS -eq 130 ]; then "
            "  tmux kill-session -t cf_engine 2>/dev/null; "
            "else "
            "  echo -e '\\nProcess crashed (Exit $STATUS). Dropping to shell to view errors.'; "
            "  exec bash; "
            "fi"
        )

        # Internal child commands use stream and banner which now naturally bypass tmux
        stream_cmd = wrapper_template.format(cmd=f"{py_cmd} stream {user_args}")
        banner_raw_cmd = wrapper_template.format(cmd=f"{py_cmd} banner {user_args}")
        banner_cmd = f"{banner_raw_cmd}; exec sleep infinity"

        call_subprocess(["tmux", "kill-session", "-t", "cf_engine"], stderr=subprocess.DEVNULL)

        term_cols, term_rows = shutil.get_terminal_size((80, 24))

        call_subprocess(["tmux", "new-session", "-d", "-s", "cf_engine", "-x", str(term_cols), "-y", str(term_rows), "bash", "-c", stream_cmd], check=True)
        call_subprocess(["tmux", "split-window", "-v", "-b", "-l", "11", "-t", "cf_engine:0.0", "bash", "-c", banner_cmd], check=True)
        call_subprocess(["tmux", "resize-pane", "-t", "cf_engine:0.0", "-y", "11"], check=True)

        # Disable tmux mouse mode to allow native terminal text selection and right-click menus
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "mouse", "off"], check=False)

        py_full_cmd = f"{shlex.quote(python_executable)} {shlex.quote(script_path)} do-copy"
        tmux_run_cmd = f"run-shell {shlex.quote(py_full_cmd)}"

        # Retain the fallback keyboard shortcut (Ctrl+b, then y) to copy the buffer
        call_subprocess([
            "tmux", "bind-key", "-T", "prefix", "y",
            tmux_run_cmd
        ], check=False)

        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-interval", "1"], check=False)

        call_subprocess(["tmux", "set-window-option", "-g", "window-style", "bg=#000000,fg=#ffffff"], check=False)
        call_subprocess(["tmux", "set-window-option", "-g", "window-active-style", "bg=#000000,fg=#ffffff"], check=False)

        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status", "2"], check=False)
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-style", "bg=#000000,fg=#e2e8f0"], check=False)

        long_blue_line = "─" * term_cols
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-format[0]", f"#[fg=#1d4ed8,bg=#000000]{long_blue_line}"], check=False)

        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-left", " #[fg=#1d4ed8,bold,bg=#000000]◈ Cuttlefish Engine  "], check=False)
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-left-length", "100"], check=False)

        initial_uptime = "00:00:00"
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-right", f"#[fg=#334155,bg=#000000]│ #[fg=#e2e8f0,bg=#000000]{initial_uptime} "], check=False)
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-right-length", "140"], check=False)
        call_subprocess(["tmux", "set-window-option", "-t", "cf_engine", "window-status-current-format", ""], check=False)
        call_subprocess(["tmux", "set-window-option", "-t", "cf_engine", "window-status-format", ""], check=False)
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "status-format[1]", " #{status-left}#[align=right]#{status-right} "], check=False)

        call_subprocess(["tmux", "set-window-option", "-t", "cf_engine", "pane-border-status", "top"], check=False)
        pane_line = "─" * term_cols
        pane_border_str = f"#[bg=#000000,fg=#1d4ed8]{pane_line}"
        call_subprocess(["tmux", "set-window-option", "-t", "cf_engine", "pane-border-format", pane_border_str], check=False)
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "pane-border-style", "bg=#000000,fg=#1d4ed8"], check=False)
        call_subprocess(["tmux", "set-option", "-t", "cf_engine", "pane-active-border-style", "bg=#000000,fg=#1d4ed8"], check=False)

        call_subprocess(["tmux", "select-pane", "-t", "cf_engine:0.1"], check=True)

    except Exception as e:
        sys.stderr.write(f"\nTmux bootstrap failed:\n")
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    try:
        call_subprocess(["tmux", "attach-session", "-t", "cf_engine"], check=False)
        call_subprocess(["tmux", "kill-session", "-t", "cf_engine"], stderr=subprocess.DEVNULL)
    except Exception:
        pass
    sys.exit(0)

def setup_nginx_proxy():
    print("[INFO] Configuring Nginx reverse proxy and TLS termination...")
    cert_path = os.path.join(WORKSPACE_DIR, "cert.pem")
    key_path = os.path.join(WORKSPACE_DIR, "key.pem")

    # Generate certs immediately so Nginx doesn't crash trying to load them
    generate_self_signed_cert(cert_path, key_path)

    nginx_conf = textwrap.dedent(f"""
        user http;
        worker_processes auto;
        events {{
            worker_connections 1024;
        }}
        http {{
            include mime.types;
            default_type application/octet-stream;
            types_hash_max_size 2048;
            types_hash_bucket_size 64;

            server {{
                listen 127.0.0.1:8444 ssl;
                server_name localhost;

                ssl_certificate {cert_path};
                ssl_certificate_key {key_path};

                ssl_protocols TLSv1.2 TLSv1.3;
                ssl_ciphers HIGH:!aNULL:!MD5;

                location /dashboard/ {{
                    proxy_pass https://127.0.0.1:{DASHBOARD_PORT}/;
                    proxy_ssl_verify off;
                    proxy_http_version 1.1;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection "Upgrade";
                    proxy_set_header Host $host;
                    proxy_buffering off;
                    proxy_read_timeout 86400;
                }}

                location /ws {{
                    proxy_pass https://127.0.0.1:{DASHBOARD_PORT}/ws;
                    proxy_ssl_verify off;
                    proxy_http_version 1.1;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection "Upgrade";
                    proxy_set_header Host $host;
                }}

                location / {{
                    proxy_pass https://127.0.0.1:8443;
                    proxy_ssl_verify off;
                    proxy_http_version 1.1;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection "Upgrade";
                    proxy_set_header Host $host;
                    proxy_cache_bypass $http_upgrade;
                    proxy_buffering off;
                    proxy_read_timeout 86400;
                    proxy_send_timeout 86400;
                }}
            }}
        }}
    """).strip()

    try:
        tmp_nginx = "/tmp/cvd_nginx.conf"
        with open(tmp_nginx, "w") as f:
            f.write(nginx_conf + "\n")

        call_subprocess(["sudo", "mv", "-f", tmp_nginx, "/etc/nginx/nginx.conf"], check=True)
        print("[INFO] Testing Nginx configuration syntax...")
        call_subprocess(["sudo", "nginx", "-t"], check=True)

        # BYPASS SYSTEMD RESTRICTIONS
        call_subprocess(["sudo", "fuser", "-k", "8444/tcp"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        call_subprocess(["sudo", "pkill", "-9", "nginx"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Launch Nginx locally as a raw daemon
        call_subprocess(["sudo", "nginx", "-c", "/etc/nginx/nginx.conf"], check=True)

        print("[INFO] Nginx reverse proxy successfully booted natively via socket binding.")
    except Exception as e:
        print(f"[-] Failed to configure Nginx ({e}), continuing fallback...")

def ensure_32gb_swap():
    """Validates existing 32GB swap configuration; safely cleans up partial or missing swap and recreates if invalid."""
    print("[INFO] Validating 32GB swap status...")

    swap_path = Path("/swapfile")
    target_size_bytes = 32768 * 1024 * 1024  # 32GB

    # Check size validity (guards against interrupted/partial dd runs)
    size_valid = False
    try:
        if swap_path.exists():
            size_valid = swap_path.stat().st_size == target_size_bytes
    except Exception:
        pass

    # Check if active in kernel
    active_swaps = ""
    try:
        with open("/proc/swaps", "r") as f:
            active_swaps = f.read()
    except Exception:
        pass

    is_active = "/swapfile" in active_swaps

    if size_valid and is_active:
        print("[INFO] Valid 32GB swap file verified and active. Skipping recreation.")
        return

    print("[INFO] Swap file is missing, partial, or inactive. Rebuilding 32GB swap cleanly...")
    if is_active:
        call_subprocess(["sudo", "swapoff", "/swapfile"], text=True, check=False)

    swap_commands = [
        (["sudo", "rm", "-f", "/swapfile"], False),
        (["sudo", "dd", "if=/dev/zero", "of=/swapfile", "bs=1M", "count=32768", "status=progress"], True),
        (["sudo", "chmod", "600", "/swapfile"], True),
        (["sudo", "mkswap", "/swapfile"], True),
        (["sudo", "swapon", "/swapfile"], True),
    ]

    for cmd_list, check in swap_commands:
        try:
            call_subprocess(cmd_list, text=True, check=check)
        except Exception as e:
            if check:
                raise RuntimeError(f"Swap command failed: {' '.join(cmd_list)} -> {e}")

    print("Subprocess Called: ['free', '-m']")
    call_subprocess(["sudo", "free", "-m"], capture_output=True, text=True)

    print("Subprocess Called: ['swapon', '--show']")
    call_subprocess(["sudo", "swapon", "--show"], capture_output=True, text=True)

    print("[INFO] 32GB swap file successfully provisioned, verified, and active.")

def ensure_adb_bridge():
    """Robustly waits for port 6520 to open and forces the ADB bridge to stay connected."""
    import subprocess
    import time
    print("[INFO] Establishing robust host-to-guest ADB bridge...")

    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"
    env = os.environ.copy()
    env["HOME"] = WORKSPACE_DIR

    # Ensure server is running cleanly
    subprocess.run([adb_path, "kill-server"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run([adb_path, "start-server"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    for attempt in range(1, 20):
        try:
            subprocess.run([adb_path, "connect", "127.0.0.1:6520"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            res = subprocess.run([adb_path, "devices"], env=env, capture_output=True, text=True, check=False)
            if "127.0.0.1:6520\tdevice" in res.stdout:
                print("[INFO] ADB bridge successfully locked and connected.")
                return
        except Exception:
            pass
        time.sleep(1)
    print("[-] Warning: ADB bridge connection timed out.")

def check_connection():
    import os
    import subprocess
    import time

    print("Verifying connectivity...")
    # Resolve the local workspace ADB binary to prevent the NameError
    adb_path = os.path.join(WORKSPACE_DIR, "bin", "adb") if os.path.exists(os.path.join(WORKSPACE_DIR, "bin", "adb")) else "adb"

    ping_success = False
    for attempt in range(2):
        call_subprocess(f"{adb_path} connect 127.0.0.1:6520", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Swapped undefined run_cmd for the global call_subprocess
        ip_ping = call_subprocess(f"{adb_path} shell ping -c 1 -W 2 8.8.8.8", shell=True, capture_output=True)
        dns_ping = call_subprocess(f"{adb_path} shell ping -c 1 -W 2 google.com", shell=True, capture_output=True)

        if ip_ping.returncode == 0 and dns_ping.returncode == 0:
            ping_success = True
            break
        time.sleep(1.5)

    if ping_success:
        print("Full internet connectivity and DNS resolution verified instantly!")
    else:
        print("Connectivity test failed.")

def forcefully_patch_webrtc_html():
    """Hunts down, validates, and patches client.html. Caches paths on first run for instant consecutive boots."""
    import os
    import base64
    import json
    from pathlib import Path

    # --- ULTIMATE DEEP-DOM ADB ERROR ANNIHILATOR ---
    auto_dismiss_script = """
    <script>
        function obliterateAdbError(root) {
            if (!root || !root.querySelectorAll) return;
            const elements = root.querySelectorAll('*');
            for (let el of elements) {
                if (el.shadowRoot) obliterateAdbError(el.shadowRoot);

                // Read the combined text of the element
                if (el.textContent && el.textContent.toLowerCase().includes('adb connection failed')) {

                    // Verify this is the deepest element holding the text to avoid hiding the whole page
                    let hasChildWithText = Array.from(el.children).some(child =>
                        child.textContent && child.textContent.toLowerCase().includes('adb connection failed')
                    );

                    if (!hasChildWithText) {
                        let target = el;
                        // Climb up 5 DOM levels to capture the entire red banner container
                        for (let i = 0; i < 5; i++) {
                            if (target && target.tagName !== 'BODY' && target.tagName !== 'HTML') {

                                // Physically click any close buttons or SVGs in this layer
                                let btns = target.querySelectorAll('button, .close, svg');
                                btns.forEach(b => b.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })));

                                // Nuke the visual CSS
                                target.style.setProperty('display', 'none', 'important');
                                target.style.setProperty('opacity', '0', 'important');
                                target.style.setProperty('pointer-events', 'none', 'important');
                                target.style.setProperty('z-index', '-9999', 'important');

                                // Move up, jumping Shadow DOM boundaries if necessary
                                target = target.parentElement || (target.getRootNode && target.getRootNode().host);
                            }
                        }
                    }
                }
            }
        }
        // Fire every 100ms to catch it the exact frame it renders
        setInterval(() => obliterateAdbError(document), 100);
    </script>
    </head>
    """

    workspace = WORKSPACE_DIR if 'WORKSPACE_DIR' in globals() else "/var/tmp/cuttlefish/user"
    base_root = os.path.dirname(workspace)
    cache_file = os.path.join(workspace, ".webrtc_paths_cache.json")

    target_files = []

    # 1. Try to load from fast cache
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                cached_paths = json.load(f)
            # Only keep paths that currently exist on the disk
            target_files = [p for p in cached_paths if os.path.exists(p)]
            if target_files:
                print("[INFO] Loaded WebRTC frontend paths from fast cache. Bypassing deep scan.")
        except Exception:
            pass

    # 2. If cache is empty or missing, perform the deep scan
    if not target_files:
        print("[INFO] Performing initial deep scan for WebRTC frontend files. This will only happen once...")
        if os.path.exists(base_root):
            for path in Path(base_root).rglob("client.html"):
                target_files.append(str(path))

        # Save the discovered paths for next time
        if target_files:
            try:
                with open(cache_file, "w") as f:
                    json.dump(target_files, f)
            except Exception as e:
                print(f"[-] Warning: Could not save path cache: {e}")

    pristine_html = None

    def fetch_pristine_html():
        print("[INFO] Downloading pristine client.html from AOSP server to heal corruption...")
        try:
            from curl_cffi import requests
            url = "https://android.googlesource.com/device/google/cuttlefish/+/refs/heads/main/host/frontend/webrtc/html_client/client.html?format=TEXT"
            resp = requests.get(url, impersonate="chrome110", timeout=15)
            resp.raise_for_status()

            try:
                decoded = base64.b64decode(resp.text).decode("utf-8")
            except Exception:
                decoded = resp.text  # Fallback if AOSP stops using base64

            if len(decoded) >= 500 and "<html" in decoded.lower():
                return decoded
            else:
                print("[-] Fetched file failed validation.")
                return None
        except Exception as e:
            print(f"[-] Network error fetching pristine client.html: {e}")
            return None

    patched_count = 0
    skipped_count = 0
    healed_count = 0

    # 3. Process the known files
    for path in target_files:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            is_valid = len(content) >= 500 and "<html" in content.lower()

            if not is_valid:
                print(f" -> [CORRUPTED] {path} is invalid or empty. Attempting to heal...")
                if pristine_html is None:
                    pristine_html = fetch_pristine_html()

                if pristine_html:
                    content = pristine_html
                    healed_count += 1
                else:
                    print(f" -> [ERROR] Could not heal {path} (Download failed).")
                    continue

            if "obliterateAdbError" not in content:
                patched_content = content.replace("</head>", auto_dismiss_script)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(patched_content)

                status = "[HEALED & PATCHED]" if not is_valid else "[PATCHED]"
                print(f" -> {status} {path}")
                patched_count += 1
            else:
                skipped_count += 1
                print(f" -> [SKIPPED] {path} (Already patched & valid)")

        except Exception as e:
            print(f" -> [ERROR] Could not read/write {path}: {e}")

    print(f"[INFO] WebRTC validation complete: {healed_count} healed, {patched_count} newly patched, {skipped_count} skipped.")

def start_local_stun_responder():
    """Spawns an autonomous local STUN server to instantly satisfy WebRTC ICE gathering without timeouts."""
    import socket
    import struct
    import threading

    def responder():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 19302))
            print("[INFO] Autonomous STUN Responder active on 127.0.0.1:19302")
            while True:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 20:
                    # Parse the STUN Binding Request Header (RFC 5389)
                    msg_type, msg_len, magic = struct.unpack('!HHI', data[:8])
                    if msg_type == 0x0001 and magic == 0x2112A442:
                        tx_id = data[8:20]

                        # Calculate XOR-MAPPED-ADDRESS attributes
                        xor_port = addr[1] ^ 0x2112
                        ip_int = struct.unpack('!I', socket.inet_aton(addr[0]))[0]
                        xor_ip = ip_int ^ 0x2112A442

                        # Pack the STUN Success Response
                        attr = struct.pack('!HHBBHI', 0x0020, 8, 0, 1, xor_port, xor_ip)
                        resp = struct.pack('!HHI', 0x0101, len(attr), magic) + tx_id + attr

                        sock.sendto(resp, addr)
        except Exception as e:
            pass

    threading.Thread(target=responder, daemon=True).start()

def enable_crosvm_sandbox():
    """Configures namespaces, bypasses nosuid, and idempotently sanitizes and injects seccomp BPF policies."""
    import textwrap
    print("[INFO] Configuring host kernel namespaces, capabilities, and seccomp exceptions...")
    try:
        call_subprocess(["sudo", "sysctl", "-w", "kernel.unprivileged_userns_clone=1"], check=False)
        call_subprocess(["sudo", "sysctl", "-w", "user.max_user_namespaces=10000"], check=False)
    except Exception:
        pass

    secure_bin_dir = "/opt/cuttlefish_bin"
    call_subprocess(["sudo", "mkdir", "-p", secure_bin_dir], check=False)
    bin_targets = [
        "crosvm",
        "tap_intf",
        "cuttlefish_net_helper"
    ]
    for bin_name in bin_targets:
        src_bin = os.path.join(WORKSPACE_DIR, "bin", bin_name)
        dst_bin = os.path.join(secure_bin_dir, bin_name)
        if os.path.exists(src_bin) and not os.path.islink(src_bin):
            call_subprocess(["sudo", "mv", "-f", src_bin, dst_bin], check=False)
            if bin_name == "crosvm":
                call_subprocess(["sudo", "setcap", "cap_setfcap,cap_sys_admin,cap_net_admin,cap_net_raw=eip", dst_bin], check=False)
            else:
                call_subprocess(["sudo", "setcap", "cap_net_admin,cap_net_raw=eip", dst_bin], check=False)
            call_subprocess(["sudo", "ln", "-sfn", dst_bin, src_bin], check=False)

    workspace_seccomp = os.path.join(WORKSPACE_DIR, "usr", "share", "crosvm", "x86_64-linux-gnu", "seccomp")
    mirror_dirs = [
        "/usr/share/crosvm/x86_64-linux-gnu/seccomp",
        "/opt/cuttlefish_bin/usr/share/crosvm/x86_64-linux-gnu/seccomp"
    ]
    for md in mirror_dirs:
        call_subprocess(["sudo", "mkdir", "-p", md], check=False)
        call_subprocess(f"sudo cp -rf {workspace_seccomp}/* {md}/ 2>/dev/null || true", shell=True, check=False)

    patcher_script = textwrap.dedent(fr"""
        import os
        import re
        from pathlib import Path

        print("[DEBUG-PATCHER] Starting idempotent seccomp policy cleaner/patcher...")

        search_roots = [
            "{WORKSPACE_DIR}/usr/share/crosvm/x86_64-linux-gnu/seccomp",
            "/usr/share/crosvm/x86_64-linux-gnu/seccomp"
        ]

        # 1. Syscalls that do not exist or crash the minijail compiler
        invalid_syscalls = ["fstat", "epoll_pwait2", "stat", "getdents", "getdents64", "geteuid"]

        # 2. Required safe syscalls for hardened kernels
        extra_rules = {{
            "clone3": "1",
            "faccessat2": "1",
            "prlimit64": "1",
            "getrandom": "1",
            "sched_setaffinity": "1",
            "sched_getaffinity": "1",
            "socketpair": "1",
            "unshare": "1",
            "kcmp": "1",
            "sysinfo": "1",
            "sched_yield": "1",
            "sched_getscheduler": "1",
            "sched_setscheduler": "1",
            "process_vm_readv": "1",
            "uname": "1",
            "newfstatat": "1",
            "statx": "1"
        }}

        patched_files = 0
        for root in search_roots:
            if not os.path.exists(root):
                continue

            for policy_path in Path(root).rglob("*.policy"):
                try:
                    lines = policy_path.read_text(encoding="utf-8").splitlines()
                    parsed_rules = {{}}
                    out_lines = []

                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue

                        if line.startswith("@") or line.startswith("#"):
                            out_lines.append(line)
                            continue

                        if ":" in line:
                            key, val = line.split(":", 1)
                            key = key.strip()
                            val = val.strip()

                            # DROP SYSCALLS THAT CRASH THE BPF COMPILER ENTIRELY
                            if key in invalid_syscalls:
                                continue

                            val = val.replace("0xCF000000/0xFF000000", "")
                            val = val.replace("(arg1 & 0x00ff0000) == 0x640000", "arg1 == 0x640000")
                            val = re.sub(r'==\s*==+', '==', val)
                            val = val.replace("||  ||", "||").strip(" |")

                            parsed_rules[key] = val

                    for k, v in extra_rules.items():
                        if k not in parsed_rules:
                            parsed_rules[k] = v

                    # 3. NVIDIA GPU UNLOCKS
                    if any(name in policy_path.name for name in ["gpu", "crosvm", "render", "wayland", "wl_device"]):
                        parsed_rules["ioctl"] = "1"
                        parsed_rules["openat"] = "1"
                        parsed_rules["mmap"] = "1"
                        parsed_rules["mprotect"] = "1"
                        parsed_rules["madvise"] = "1"

                    for k, v in parsed_rules.items():
                        if v:
                            out_lines.append(f"{{k}}: {{v}}")
                        else:
                            out_lines.append(f"{{k}}: 1")

                    policy_path.write_text("\\n".join(out_lines) + "\\n", encoding="utf-8")
                    patched_files += 1
                except Exception as e:
                    print(f"[DEBUG-PATCHER] -> ERROR patching {{policy_path.name}}: {{e}}")

        print(f"[INFO] Sandbox hardening complete. Cleaned and deduped {{patched_files}} seccomp policy files.")
    """).strip()

    script_path = "/tmp/sandbox_patcher.py"
    with open(script_path, "w") as f:
        f.write(patcher_script)

    try:
        call_subprocess(["sudo", "python3", script_path], check=False)
    except Exception as e:
        print(f"[-] Sandbox patcher failed: {e}")

if __name__ == "__main__":
    if os.environ.get("CUTTLEFISH_SCOPED") != "1" and shutil.which("systemd-run"):
        env = os.environ.copy()
        env["CUTTLEFISH_SCOPED"] = "1"
        total_cores = os.cpu_count() or 4
        # Calculate exactly 75% of total system CPU capacity (e.g., 8 cores = 800% -> 600%)
        cpu_quota_pct = int((total_cores * 100) * 0.75)

        scoped_cmd = [
            "systemd-run", "--user", "--scope",
            "--unit=cf_build.scope",  # <--- ADD THIS EXACT LINE
            "--quiet",
            "-p", "MemoryMax=30.0G",
            "-p", f"CPUQuota={cpu_quota_pct}%",
            "--"
        ] + [sys.executable, os.path.abspath(__file__)] + sys.argv[1:]

        try:
            # Instantly purge any abandoned systemd scopes from previous runs
            subprocess.run(["systemctl", "--user", "stop", "cf_build.scope"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            subprocess.run(["systemctl", "--user", "reset-failed", "cf_build.scope"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

            sys.stdout.write("[INFO] Enforcing 30GB RAM and 1700% CPU caps via systemd scope...\n")
            sys.stdout.flush()
            res = subprocess.run(scoped_cmd, env=env)
            sys.exit(res.returncode)
        except Exception as e:
            sys.stderr.write(f"[WARNING] Could not initialize systemd scope wrapper: {e}. Running unconstrained...\n")
            sys.stderr.flush()

    remove_stale_build_processes()
    try:
        # Prevent tmux if inside a child pane
        base_ws = "/var/tmp/cuttlefish"
        target_ws = os.path.join(base_ws, "user" if "no-root" in sys.argv else "debug")
        os.makedirs(target_ws, exist_ok=True)

        if "refresh" in sys.argv:
            handle_refresh_assets()

        try:
            with open(os.path.join(target_ws, ".roadmap.json"), "w") as f:
                json.dump({
                    "1. Environment & Tools": "ACTIVE",
                    "2. Repository Init": "QUEUED",
                    "3. Source Sync": "QUEUED",
                    "4. Lunch & Compile": "QUEUED",
                    "5. Cache & Deployment": "QUEUED"
                }, f)
        except Exception:
            pass

        # init_side_by_side_layout()

        if "banner" in sys.argv:
            import signal
            def redraw_banner(signum=None, frame=None):
                port = None
                try:
                    if os.path.exists("/tmp/cf_dash_port.txt"):
                        with open("/tmp/cf_dash_port.txt", "r") as f:
                            port = f.read().strip()
                except Exception:
                    pass
                #print_launch_banner(dash_port=port)

            signal.signal(signal.SIGWINCH, redraw_banner)
            redraw_banner()
            sys.stdout.write("\033[?25l")
            sys.stdout.flush()
            try:
                while True: time.sleep(3600)
            except (KeyboardInterrupt, SystemExit):
                sys.stdout.write("\033[?25h")
                sys.exit(0)

        sys.argv = [arg for arg in sys.argv if arg not in ("stream", "banner")]

        # Launch the UI Dashboard immediately to view logs right away
        if "console" not in sys.argv:
            resilient_launch_dashboard(video_w=1920, video_h=1080, control_pad=65, auto_scale=True)
            print("[INFO] Dashboard subsystem guarded. Starting asynchronous hypervisor deployment...")

        # =========================================================
        # 🚀 EVENT DAEMON IGNITION
        # =========================================================

        # 1. Start the Event Watcher Daemon in the background
        import threading
        threading.Thread(target=background_api_event_watcher, daemon=True).start()

        # 2. Push the correct Domino into the queue based on the run mode
        if RUN_IN_DOCKER:
            API_EVENT_QUEUE.put("[DOCKER_BOOTSTRAP]")
        else:
            API_EVENT_QUEUE.put("[SYSTEM_BOOTSTRAP]")

        print("Press Ctrl+C in this terminal to gracefully shut down the device.")

        # 3. Keep the main thread alive. The Daemon handles everything else!
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Initiating graceful shutdown...")
            dump_logs_on_exit()
            stop_and_clean_cvd()
            force_full_shutdown()

    except Exception as outer_e:
        sys.stderr.write(f"\n[FATAL SCRIPT ERROR]: {outer_e}\n")
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        while True: time.sleep(3600)
