import os
import sys
import subprocess

if os.environ.get("SANDBOX_ACTIVE") != "1":
    os.system('clear')

    # Unconditionally clear the old boot log on host startup
    try: os.remove(os.path.abspath("mm_boot.log"))
    except Exception: pass

    VENV_DIR = os.path.abspath("venv")
    VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")
    if sys.executable != VENV_PYTHON:
        print("[BOOTSTRAP] Checking for virtual environment (venv)...", flush=True)
        if not os.path.exists(VENV_PYTHON):
            print("[BOOTSTRAP] Creating new virtual environment...", flush=True)
            subprocess.check_call([sys.executable, "-m", "venv", "venv"])
        print("[BOOTSTRAP] Switching execution to virtual environment...", flush=True)

        # Directly replace the current process with the venv Python interpreter
        os.execv(VENV_PYTHON, [VENV_PYTHON, os.path.abspath(sys.argv[0])] + sys.argv[1:])

import signal
import json
import faulthandler
import time
import threading
import re
import uuid
import hashlib
import shutil
from datetime import datetime, timedelta, timezone
import tempfile
import pathlib
import glob
import site
import concurrent.futures
import urllib.request
import urllib.parse
import email.utils
import xml.etree.ElementTree as ET
import ctypes
import random
import asyncio
import base64
import gzip
import zlib

class MultiLayerSandbox:
    PR_SET_NO_NEW_PRIVS = 38
    PR_SET_DUMPABLE = 14
    SYS_landlock_create_ruleset = 444
    SYS_landlock_add_rule = 445
    SYS_landlock_restrict_self = 446
    LANDLOCK_ACCESS_FS_EXECUTE = (1 << 0)
    LANDLOCK_ACCESS_FS_WRITE_FILE = (1 << 1)
    LANDLOCK_ACCESS_FS_READ_FILE = (1 << 2)
    LANDLOCK_ACCESS_FS_READ_DIR = (1 << 3)
    LANDLOCK_ACCESS_FS_REMOVE_DIR = (1 << 4)
    LANDLOCK_ACCESS_FS_REMOVE_FILE = (1 << 5)
    LANDLOCK_ACCESS_FS_MAKE_CHAR = (1 << 6)
    LANDLOCK_ACCESS_FS_MAKE_DIR = (1 << 7)
    LANDLOCK_ACCESS_FS_MAKE_REG = (1 << 8)
    LANDLOCK_ACCESS_FS_MAKE_SOCK = (1 << 9)
    LANDLOCK_ACCESS_FS_MAKE_FIFO = (1 << 10)
    LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1 << 11)
    LANDLOCK_ACCESS_FS_MAKE_SYM = (1 << 12)

    @classmethod
    def generate_seccomp_bpf(cls):
        import struct
        BPF_LD = 0x00; BPF_W = 0x00; BPF_ABS = 0x20
        BPF_JMP = 0x05; BPF_JEQ = 0x10; BPF_K = 0x00
        BPF_RET = 0x06
        SECCOMP_RET_ALLOW = 0x7fff0000
        SECCOMP_RET_ERRNO = 0x00050000 | 1
        AUDIT_ARCH_X86_64 = 0xc000003e

        # Hardened blocklist targeting privilege escalation and container breakout vectors
        blocked_syscalls = [
            101,  # ptrace
            155,  # pivot_root
            161,  # chroot
            165,  # mount
            166,  # umount2
            246,  # kexec_load
            248,  # add_key
            249,  # request_key
            250,  # keyctl
            272,  # unshare
            278,  # vmsplice
            298,  # perf_event_open
            308,  # setns
            310,  # process_vm_readv
            311,  # process_vm_writev
            312,  # kcmp
            320,  # kexec_file_load
            321,  # bpf
            323,  # userfaultfd
        ]
        def stmt(code, k): return struct.pack("HBBI", code, 0, 0, k)
        def jump(code, k, jt, jf): return struct.pack("HBBI", code, jt, jf, k)
        instructions = []
        instructions.append(stmt(BPF_LD | BPF_W | BPF_ABS, 4))
        instructions.append(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, len(blocked_syscalls) + 1))
        instructions.append(stmt(BPF_LD | BPF_W | BPF_ABS, 0))
        for i, syscall in enumerate(blocked_syscalls):
            instructions.append(jump(BPF_JMP | BPF_JEQ | BPF_K, syscall, len(blocked_syscalls) - i, 0))
        instructions.append(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
        instructions.append(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO))
        bpf_bytecode = b"".join(instructions)
        try:
            fd = os.memfd_create("seccomp_bpf")
            os.write(fd, bpf_bytecode)
            os.lseek(fd, 0, os.SEEK_SET)
            os.set_inheritable(fd, True)
            return fd
        except Exception as e:
            print(f"[SANDBOX-L4] [WARNING] Failed to mount Seccomp memory file: {e}", flush=True)
            return None

    @classmethod
    def enforce_layer3_privilege_locks(cls):
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.prctl(cls.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            print("[SANDBOX-L3] [WARNING] Failed to set PR_SET_NO_NEW_PRIVS.", flush=True)
        else:
            print("[SANDBOX-L3] [SUCCESS] PR_SET_NO_NEW_PRIVS locked. Root escalation impossible.", flush=True)
        libc.prctl(cls.PR_SET_DUMPABLE, 0, 0, 0, 0)

        import resource
        try:
            # Disable core dumps to protect against memory scraping
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            print("[SANDBOX-L3] [SUCCESS] Strict resource limits (RLIMIT) applied.", flush=True)
        except Exception:
            pass

    @classmethod
    def enforce_layer2_landlock(cls, allowed_write_paths: list):
        cls.enforce_layer3_privilege_locks()
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        class LandlockRulesetAttr(ctypes.Structure):
            _fields_ = [("handled_access_fs", ctypes.c_uint64)]
        class LandlockPathBeneathAttr(ctypes.Structure):
            _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]
        all_fs_access = (
            cls.LANDLOCK_ACCESS_FS_EXECUTE | cls.LANDLOCK_ACCESS_FS_WRITE_FILE |
            cls.LANDLOCK_ACCESS_FS_READ_FILE | cls.LANDLOCK_ACCESS_FS_READ_DIR |
            cls.LANDLOCK_ACCESS_FS_REMOVE_DIR | cls.LANDLOCK_ACCESS_FS_REMOVE_FILE |
            cls.LANDLOCK_ACCESS_FS_MAKE_CHAR | cls.LANDLOCK_ACCESS_FS_MAKE_DIR |
            cls.LANDLOCK_ACCESS_FS_MAKE_REG | cls.LANDLOCK_ACCESS_FS_MAKE_SOCK |
            cls.LANDLOCK_ACCESS_FS_MAKE_FIFO | cls.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            cls.LANDLOCK_ACCESS_FS_MAKE_SYM
        )
        attr = LandlockRulesetAttr(handled_access_fs=all_fs_access)
        ruleset_fd = libc.syscall(cls.SYS_landlock_create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if ruleset_fd < 0:
            print("[SANDBOX-L2] [WARNING] Kernel rejected Landlock LSM.", flush=True)
            return
        try:
            print(f"[SANDBOX-L2] Enforcing Kernel Filesystem Locks...", flush=True)
            for path in allowed_write_paths + ["/dev", "/dev/dri", "/dev/shm"]:
                if os.path.exists(path):
                    try:
                        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
                        pb = LandlockPathBeneathAttr(allowed_access=all_fs_access, parent_fd=fd)
                        libc.syscall(cls.SYS_landlock_add_rule, ruleset_fd, 1, ctypes.byref(pb), 0)
                        os.close(fd)
                        print(f"[SANDBOX-L2] \t-> R/W Access Granted: {path}", flush=True)
                    except OSError:
                        pass
            ro_access = (cls.LANDLOCK_ACCESS_FS_EXECUTE | cls.LANDLOCK_ACCESS_FS_READ_FILE | cls.LANDLOCK_ACCESS_FS_READ_DIR)
            for ro_path in ["/usr", "/etc", "/lib", "/lib64", "/proc", "/sys", "/run"]:
                if os.path.exists(ro_path):
                    try:
                        fd = os.open(ro_path, os.O_PATH | os.O_CLOEXEC)
                        pb = LandlockPathBeneathAttr(allowed_access=ro_access, parent_fd=fd)
                        libc.syscall(cls.SYS_landlock_add_rule, ruleset_fd, 1, ctypes.byref(pb), 0)
                        os.close(fd)
                        print(f"[SANDBOX-L2] \t-> R/O Access Granted: {ro_path}", flush=True)
                    except OSError:
                        pass
            libc.syscall(cls.SYS_landlock_restrict_self, ruleset_fd, 0)
            print("[SANDBOX-L2] [SUCCESS] Kernel VFS Lockdown complete.", flush=True)
        finally:
            os.close(ruleset_fd)

    @classmethod
    def execute_layer1_containment(cls):
        print("\n" + "="*60, flush=True)
        print("[SANDBOX INIT] Checking Isolation Environment...", flush=True)
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        if os.environ.get("SANDBOX_ACTIVE") == "1":
            print("[SANDBOX-L1] Inside Layer 1 Container! Bootstrapping Layers 2 & 3...", flush=True)
            if os.environ.get("SECCOMP_ACTIVE") == "1":
                print("[SANDBOX-L4] [SUCCESS] Verified: Process is wrapped in Seccomp-BPF Kernel Firewall.", flush=True)
            else:
                print("[SANDBOX-L4] [WARNING] Seccomp-BPF is NOT active.", flush=True)
            work_dir = os.path.abspath(os.getcwd())
            cache_dir = os.path.expanduser("~/.cache/MediaMonitor")
            os.makedirs(cache_dir, exist_ok=True)
            cls.enforce_layer2_landlock([work_dir, "/tmp", cache_dir, xdg_runtime])
            print("="*60 + "\n", flush=True)
            return
        if shutil.which("bwrap") is None:
            print("[SANDBOX-L1] [FATAL ERROR] 'bwrap' executable not found. Install via 'sudo pacman -S bubblewrap'.", flush=True)
            sys.exit(1)
        app_dir = os.path.abspath(os.getcwd())

        bwrap_cmd = [
            "bwrap",
            "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
            "--cap-drop", "ALL",
            "--die-with-parent",
            "--new-session",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind-try", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind-try", "/bin", "/bin",
            "--ro-bind-try", "/sbin", "/sbin",
            "--ro-bind", "/etc", "/etc",
            "--ro-bind-try", "/sys", "/sys",

            # Mount a sterile pseudo-dev void, explicitly bypassing all host hardware
            "--dev", "/dev",
            # Explicitly tunnel ONLY the GPU for Wayland/WebGL hardware acceleration
            "--dev-bind-try", "/dev/dri", "/dev/dri",

            "--tmpfs", "/dev/shm",
            "--proc", "/proc",

            # Hide the dangerous X11 backward-compatibility sockets entirely
            "--tmpfs", "/tmp",
            "--tmpfs", "/var",

            "--ro-bind-try", "/var/lib/ca-certificates", "/var/lib/ca-certificates",
            "--ro-bind-try", "/var/cache/fontconfig", "/var/cache/fontconfig",
            "--ro-bind-try", "/usr/share/glvnd", "/usr/share/glvnd",
            "--ro-bind-try", "/usr/share/vulkan", "/usr/share/vulkan",
            "--ro-bind-try", "/etc/xdg", "/etc/xdg",
            "--bind", app_dir, app_dir,
            "--chdir", app_dir,
        ]

        if os.path.exists(xdg_runtime):
            bwrap_cmd.extend(["--bind-try", xdg_runtime, xdg_runtime])

        # D-BUS & UDEV ARE PURPOSELY SEVERED HERE TO PREVENT IPC ESCAPES

        home_path = pathlib.Path.home()
        pki_path = home_path / ".pki"
        if pki_path.exists():
            bwrap_cmd.extend(["--ro-bind-try", str(pki_path), str(pki_path)])

        # --- MACHINE ID BLINDFOLD & HOSTNAME SPOOFING ---
        bwrap_cmd.extend([
            "--hostname", "isolated-monitor",
            "--ro-bind-try", "/dev/null", "/etc/machine-id",
            "--ro-bind-try", "/dev/null", "/var/lib/dbus/machine-id",
            "--tmpfs", "/var/log"
        ])

        # --- TOTAL ENVIRONMENT ANNIHILATION & WAYLAND LOCK ---
        # Sterile environment allowlist with Wayland binding and forced dark-mode injection
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home_path),
            "USER": "sandbox_user",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "XDG_RUNTIME_DIR": xdg_runtime,
            "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY", "wayland-0"),

            # Enforce strict Wayland-only processing. X11 fallback is completely dead.
            "QT_QPA_PLATFORM": "wayland",

            # Force dark mode natively via Qt/Chromium flags without leaking host desktop themes
            "QT_STYLE_OVERRIDE": "fusion",

            "LIBGL_DEBUG": "quiet",
            "SANDBOX_ACTIVE": "1"
        }

        print("[SANDBOX-L4] Compiling Kernel Syscall Firewall...", flush=True)

        print("[SANDBOX-L4] Compiling Kernel Syscall Firewall...", flush=True)
        seccomp_fd = cls.generate_seccomp_bpf()
        if seccomp_fd is not None:
            print(f"[SANDBOX-L4] [SUCCESS] Seccomp-BPF attached to bwrap execution (FD: {seccomp_fd}).", flush=True)
            bwrap_cmd.extend(["--seccomp", str(seccomp_fd)])
            env["SECCOMP_ACTIVE"] = "1"
        else:
            print("[SANDBOX-L4] [FAILED] Could not compile Seccomp-BPF.", flush=True)
        print("\n[SANDBOX-L1] Firing bwrap Execution Command:", flush=True)
        print(" ".join(bwrap_cmd), flush=True)
        bwrap_cmd.extend([sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:])
        try:
            os.execvpe("bwrap", bwrap_cmd, env)
        except Exception as e:
            print(f"[SANDBOX-L1] [FATAL ERROR] Failed to start container process: {e}", flush=True)
            sys.exit(1)

def apply_oom_protection():
    try:
        with open(f"/proc/{os.getpid()}/oom_score_adj", "w") as f:
            f.write("300")
    except Exception:
        pass

apply_oom_protection()

try:
    os.system("pkill -9 -f QtWebEngineProcess >/dev/null 2>&1")
    os.system("killall -9 QtWebEngineProcess >/dev/null 2>&1")

    my_pid = os.getpid()
    pids = subprocess.check_output(["pgrep", "-f", "web.py"]).decode().split()
    for p in pids:
        pid = int(p)
        if pid != my_pid:
            os.kill(pid, signal.SIGKILL)
except Exception:
    pass

if "QT_QPA_PLATFORM" in os.environ:
    del os.environ["QT_QPA_PLATFORM"]

CDP_DEBUG_PORT = 9222
os.environ["QTWEBENGINE_REMOTE_DEBUGGING"] = str(CDP_DEBUG_PORT)
os.environ["OLLAMA_CUDA"] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    # --- CDP & AUTOMATION EVASION ---
    f"--remote-debugging-port={CDP_DEBUG_PORT} "
    "--remote-allow-origins=* "
    "--disable-quic "

    # --- CONTAINER / SANDBOX STABILITY ---
    "--no-sandbox "
    "--disable-dev-shm-usage "
    "--no-proxy-server "

    # --- MEDIA & DESKTOP INTEGRATION ---
    "--autoplay-policy=no-user-gesture-required "
    "--disable-features=HardwareMediaKeyHandling "
    "--enable-features=WebUIDarkMode "
    "--force-dark-mode "

    # --- SAFE GPU & WEBGL SETTINGS ---
    # Intentionally leaving out draft-extensions and blocklist-bypass
    # to allow the Linux driver to safely handle Canvas Fingerprinting.
    "--enable-gpu "
    "--enable-gpu-compositing "
    "--enable-webgl "

    # --- PRIVACY & WEBRTC LEAK PROTECTION ---
    "--webrtc-ip-handling-policy=disable_non_proxied_udp "
    "--disable-webrtc-hw-decoding "
    "--disable-webrtc-hw-encoding "

    # --- STRICT BACKGROUND PROCESSING ---
    "--disable-background-timer-throttling "
    "--disable-renderer-backgrounding "
    "--disable-backgrounding-occluded-windows "
    "--disable-features=CalculateNativeWinOcclusion "

    # --- RESOURCE MANAGEMENT ---
    "--disk-cache-size=33554432 "
    "--media-cache-size=67108864 "
    "--log-level=3 "
)

if "QTWEBENGINE_FORCE_USE_GBM" in os.environ:
    del os.environ["QTWEBENGINE_FORCE_USE_GBM"]

faulthandler.enable()
os.environ["LC_ALL"] = "C.UTF-8"
os.environ["LANG"] = "C.UTF-8"
os.environ["PYTHONUNBUFFERED"] = "1"

AI_PROCESSING_LOCK = threading.RLock()
TARGETS_CONFIG_FILE = "targets_config.json"
APP_SETTINGS_FILE = "app_settings.json"

DEFAULT_TARGETS = [
    {
        "name": "Kayleigh Mcenany",
        "profile_url": "https://www.foxnews.com/person/m/kayleigh-mcenany",
        "x_user": "kayleighmcenany",
        "facebook_user": "KayleighMcEnany7",
        "tiktok_user": "kayleighmcenany",
        "instagram_user": "kayleighmcenany",
        "youtube": True, "fox_api": True, "google_rss": True, "profile_scrape": True,
        "x": True, "facebook": True, "tiktok": True, "instagram": True
    }
]

DEFAULT_APP_SETTINGS = {
    "enable_background_scans": True,
    "enable_background_social_scans": False
}


SHIELD_ALLOWED_DOMAINS = [
    # Adult / Streaming Platforms & CDNs
    "stripchat.com", "chapturist.com", "strpst.com",
    "doppiocdn.net", "doppiocdn.com", "edge-hls.doppiocdn.net", "edge-hls.doppiocdn.media",

    # TikTok
    "tiktok.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
    "tiktokv.com", "byteoversea.com", "ibyteimg.com", "ttwstatic.com",
    "tiktokv.us", "tiktokw.us",

    # Social / Media
    "x.com", "twitter.com", "twimg.com",
    "facebook.com", "fbcdn.net",
    "instagram.com", "cdninstagram.com",

    # Fox Network & Infrastructure
    "foxnews.com", "foxbusiness.com", "moxie.foxnews.com", "foxtv.com",
    "www.foxtv.com", "livenowfox.com", "fox.com", "atp.fox", "fncstatic.com",
    "h-cdn.com", "akamaihd.net", "akamaized.net", "boltdns.net",
    "kts.fox", "dt.fox", "ketchcdn.com", "knotch-cdn.com", "imrworldwide.com",

    # Google & General CDNs
    "google.com", "youtube.com", "googlevideo.com", "ytimg.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com",
    "googleusercontent.com", "storage.googleapis.com",

    # Local
    "127.0.0.1", "localhost"
]

SHIELD_BLOCKED_DOMAINS = [
    "doubleclick.net", "googleadservices.com", "google-analytics.com", "adsystem.com",
    "adsafeprotected.com", "scorecardresearch.com", "moatads.com", "criteo.com",
    "taboola.com", "outbrain.com", "adnxs.com", "rubiconproject.com",
    "amazon-adsystem.com", "chartbeat.net", "quantserve.com", "demdex.net",
    "advertising.com", "ads-twitter.com", "pixel.facebook.com", "analytics.twitter.com",
    "googlesyndication.com", "adform.net", "casalemedia.com", "pubmatic.com",
    "bidswitch.net", "rlcdn.com", "openx.net", "crwdcntrl.net", "smartadserver.com",
    "yieldmanager.com", "lijit.com", "turn.com", "mathtag.com", "adtechus.com"
]

class AIFirewall:
    _cache = {}
    _pending = {}
    _lock = threading.Lock()

    @classmethod
    def check_domain(cls, host):
        full_url = str(host)
        if "://" not in full_url:
            full_url = f"https://{full_url}/"
        parsed = urllib.parse.urlparse(full_url)
        host = (parsed.hostname or parsed.netloc or full_url).strip().lower()

        if not host or " " in host or ".." in host: return False

        if any(host == d or host.endswith("." + d) for d in SHIELD_ALLOWED_DOMAINS): return True
        if any(host == d or host.endswith("." + d) for d in SHIELD_BLOCKED_DOMAINS): return False

        with cls._lock:
            if full_url in cls._cache:
                return cls._cache[full_url]
            if full_url not in cls._pending:
                cls._pending[full_url] = threading.Event()
                is_leader = True
            else:
                is_leader = False

        if not is_leader:
            cls._pending[full_url].wait()
            with cls._lock:
                return cls._cache.get(full_url, False)

        is_safe = False
        try:
            qwen_payload = {"model": "qwen2.5:1.5b", "prompt": f"Is the URL '{full_url}' safe? Reply strictly 'SAFE' or 'ODD'.", "stream": False, "options": {"temperature": 0.0, "num_predict": 2}}
            resp_qwen = requests.post("http://127.0.0.1:11434/api/generate", json=qwen_payload, timeout=1.0)

            if resp_qwen.status_code == 200:
                ans = resp_qwen.json().get("response", "").strip().upper()
                if "SAFE" in ans or "YES" in ans:
                    is_safe = True
                else:
                    if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                        GUI_EMITTER.log_signal.emit(f"[AI Logs] <span style='color: #F59E0B;'>[AI]</span> Qwen flagged URL <span style='color: #F87171;'>'{full_url}'</span> as ODD. Escalating to Llama 3.2...")
                    llama_payload = {
                        "model": "llama3.2",
                        "system": "You are a strict binary classifier. Output ONLY the word SAFE or BLOCK. No conversational filler.",
                        "prompt": f"URL: {full_url}",
                        "stream": False,
                        "options": {"temperature": 0.0, "num_predict": 5}
                    }
                    resp_llama = requests.post("http://127.0.0.1:11434/api/generate", json=llama_payload, timeout=5.0)
                    if resp_llama.status_code == 200:
                        ans_l = resp_llama.json().get("response", "").strip().upper()
                        is_safe = "BLOCK" not in ans_l and "MALICIOUS" not in ans_l
                        if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                            color = "#10B981" if is_safe else "#EF4444"
                            GUI_EMITTER.log_signal.emit(f"[AI Logs] <span style='color: {color};'>[AI]</span> Llama 3.2 response: <b>{ans_l}</b>")
        except Exception:
            is_safe = False

        if not is_safe:
            if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                GUI_EMITTER.log_signal.emit(f"[EMBEDDED] [SHIELD_ALERT] 🤖 LOCAL AI-GATED SHIELD | Domain actively rejected by Llama/Qwen: {host} | URL: {full_url}")

        with cls._lock:
            cls._cache[full_url] = is_safe
            if full_url in cls._pending:
                cls._pending[full_url].set()
                del cls._pending[full_url]
        return is_safe

def clean_handle(raw_str, platform_type="x"):
    if not raw_str: return ""
    raw = str(raw_str).strip()
    if "/search" in raw or "search?q=" in raw or "search-results" in raw or "duckduckgo" in raw: return raw
    raw = re.sub(r'^https?://(?:www\.)?(?:x\.com|twitter\.com|facebook\.com|tiktok\.com|instagram\.com|livenowfox\.com|foxnews\.com|foxbusiness\.com)/@?', '', raw, flags=re.IGNORECASE)
    if platform_type == "facebook":
        raw = re.sub(r'^(?:people|pages|public|groups)/[^/]+/', '', raw, flags=re.IGNORECASE)
        raw = re.sub(r'^profile\.php\?id=', '', raw, flags=re.IGNORECASE)
    raw = raw.strip("/@ ").split("?")[0].split("#")[0]
    invalid = {"home", "explore", "notifications", "messages", "settings", "login", "signup", "search", "top", "groups", "watch", "people", "pages", "public", "hashtag"}
    if raw.lower() in invalid or len(raw) < 2: return ""
    return raw

def get_targets_data():
    if os.path.exists(TARGETS_CONFIG_FILE):
        try:
            with open(TARGETS_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    for item in data:
                        item["x_user"] = clean_handle(item.get("x_user", item.get("x_url", "")), "x")
                        item["facebook_user"] = clean_handle(item.get("facebook_user", item.get("facebook_url", "")), "facebook")
                        item["tiktok_user"] = clean_handle(item.get("tiktok_user", item.get("tiktok_url", "")), "tiktok")
                        item["instagram_user"] = clean_handle(item.get("instagram_user", item.get("instagram_url", "")), "instagram")
                    return data
        except Exception: pass
    return DEFAULT_TARGETS

def save_targets_data(targets_data):
    try:
        with open(TARGETS_CONFIG_FILE, "w", encoding="utf-8") as f: json.dump(targets_data, f, indent=4)
    except Exception as e:
        print(f"[!] Error saving targets configuration: {e}", flush=True)

def get_app_settings():
    if os.path.exists(APP_SETTINGS_FILE):
        try:
            with open(APP_SETTINGS_FILE, "r", encoding="utf-8") as f:
                return {**DEFAULT_APP_SETTINGS, **json.load(f)}
        except Exception: pass
    return DEFAULT_APP_SETTINGS

def save_app_settings(settings_data):
    try:
        with open(APP_SETTINGS_FILE, "w", encoding="utf-8") as f: json.dump(settings_data, f, indent=4)
    except Exception: pass

PRE_GUI_LOGS = []
GUI_EMITTER = None

def pre_gui_log(msg):
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")

    # Strip HTML tags for clean plain-text terminal output
    import re
    clean_terminal_msg = re.sub(r'<[^>]+>', '', msg)
    terminal_formatted = f"[{timestamp}] [PRE-GUI] {clean_terminal_msg}"

    # Wrap the prefix in blue HTML for the app's graphical UI log window
    app_formatted = f"[{timestamp}] <span style='color: #60A5FA;'>[PRE-GUI]</span> {msg}"

    PRE_GUI_LOGS.append(app_formatted)
    sys.__stdout__.write(terminal_formatted + "\n")
    sys.__stdout__.flush()
    try:
        with open(os.path.abspath("mm_boot.log"), "a", encoding="utf-8") as f:
            f.write(app_formatted + "\n")
    except Exception: pass

DOMAINS_CACHE_FILE = "top_1000_domains.txt"

def load_or_download_domains(force_refresh=False):
    domains = []
    is_valid = False

    if not force_refresh and os.path.exists(DOMAINS_CACHE_FILE):
        try:
            with open(DOMAINS_CACHE_FILE, "r", encoding="utf-8") as f:
                domains = [l.strip().lower() for l in f.readlines() if l.strip()]

            # Validation check: Ensure the file contains a robust list (at least 500 valid domains)
            if len(domains) >= 500:
                is_valid = True
                timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
                clean_msg = f"Verified and loaded {len(domains)} top domains from local cache file."
                app_msg = f"[{timestamp}] [SYS_LOG] <span style='color: #10B981;'>{clean_msg}</span>"
                PRE_GUI_LOGS.append(app_msg)
                sys.__stdout__.write(f"[{timestamp}] {clean_msg}\n")
                sys.__stdout__.flush()
            else:
                pre_gui_log(f"[WARNING] Local domains cache file appears incomplete or invalid ({len(domains)} entries). Re-downloading...")
        except Exception as e:
            pre_gui_log(f"[WARNING] Failed to verify local domains cache: {e}")

    if force_refresh or not is_valid:
        try:
            pre_gui_log("[*] Downloading top domains whitelist from remote source...")
            with urllib.request.urlopen("https://raw.githubusercontent.com/bensooter/URLchecker/master/top-1000-websites.txt", timeout=5) as r:
                if r.status == 200:
                    content = r.read().decode('utf-8')
                    with open(DOMAINS_CACHE_FILE, "w", encoding="utf-8") as f:
                        f.write(content)
                    domains = [l.strip().lower() for l in content.splitlines() if l.strip()]
                    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    clean_msg = f"Successfully downloaded and cached {len(domains)} top domains."
                    app_msg = f"[{timestamp}] [SYS_LOG] <span style='color: #10B981;'>{clean_msg}</span>"
                    PRE_GUI_LOGS.append(app_msg)
                    if GUI_EMITTER:
                        GUI_EMITTER.log_signal.emit(app_msg)
                    sys.__stdout__.write(f"[{timestamp}] {clean_msg}\n")
                    sys.__stdout__.flush()
        except Exception as e:
            pre_gui_log(f"[WARNING] Top-domains download failed: {e}")

    if domains:
        for d in domains:
            if d not in SHIELD_ALLOWED_DOMAINS:
                SHIELD_ALLOWED_DOMAINS.append(d)

def configure_ollama_systemd():
    pre_gui_log("[*] Checking Ollama systemd service configuration...")
    override_dir = "/etc/systemd/system/ollama.service.d"
    override_file = os.path.join(override_dir, "override.conf")
    target_config = '[Service]\nEnvironment="OLLAMA_NUM_PARALLEL=1"\nEnvironment="OLLAMA_MAX_QUEUE=512"\n'

    try:
        need_reload = False
        current_config = ""
        if os.path.exists(override_file):
            with open(override_file, "r") as f: current_config = f.read()
        if current_config.strip() != target_config.strip():
            pre_gui_log("[+] Applying systemd override to restrict Ollama to 1 queue process (CPU fix)...")
            if not os.path.exists(override_dir): subprocess.check_call(["sudo", "mkdir", "-p", override_dir], timeout=10)
            subprocess.check_call(f"echo '{target_config}' | sudo tee {override_file} > /dev/null", shell=True, timeout=10)
            need_reload = True
        if need_reload:
            pre_gui_log("[+] Reloading systemd daemon and restarting Ollama service...")
            subprocess.check_call(["sudo", "systemctl", "daemon-reload"], timeout=10)
            subprocess.check_call(["sudo", "systemctl", "restart", "ollama"], timeout=10)
            pre_gui_log("[✅] Ollama systemd override applied and service restarted successfully.")
        else:
            pre_gui_log("[*] Ollama systemd single-queue override is already active.")
    except Exception as e:
        pre_gui_log(f"[!] Warning: Failed to auto-configure Ollama systemd: {e}")

def fix_venv_system_packages():
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        venv_cfg = os.path.join(sys.prefix, "pyvenv.cfg")
        if os.path.exists(venv_cfg):
            with open(venv_cfg, "r") as f: content = f.read()
            if "include-system-site-packages = false" in content.lower():
                pre_gui_log("[*] Modifying venv to allow access to system packages...")
                content = re.sub(r'include-system-site-packages\s*=\s*false', 'include-system-site-packages = true', content, flags=re.IGNORECASE)
                with open(venv_cfg, "w") as f: f.write(content)
                pre_gui_log("[✅] Venv updated. Restarting Python interpreter to load new system paths...")
                os.execv(sys.executable, [sys.executable] + sys.argv)

def bootstrap_dependencies():
    if os.environ.get("SANDBOX_ACTIVE") == "1":
        return

    pre_gui_log("[*] Checking runtime dependencies and system architecture...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "PyQt6", "PyQt6-WebEngine", "PyQt6-Qt6"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

    fix_venv_system_packages()
    for p in glob.glob("/usr/lib/python3.*/site-packages"):
        if p not in sys.path:
            sys.path.insert(1, p)
            site.addsitedir(p)

    # ARCH / ENDEAVOUROS FULL AUTO-INSTALL
    if os.path.exists("/etc/arch-release"):
        arch_pkgs = [
            "python-pyqt6", "python-pyqt6-webengine", "curl",
            "qt6-multimedia", "qt6-multimedia-gstreamer",
            "gst-plugins-good", "gst-plugins-bad", "gst-plugins-ugly", "gst-libav",
            "bubblewrap", "nss", "base-devel"
        ]

        missing_arch = []
        for pkg in arch_pkgs:
            if subprocess.call(["pacman", "-Qs", f"^{pkg}$"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                missing_arch.append(pkg)

        if missing_arch:
            pre_gui_log(f"[*] Installing missing system packages via Pacman: {', '.join(missing_arch)}")
            try:
                subprocess.check_call(["sudo", "pacman", "-Sy", "--noconfirm", "--needed"] + missing_arch, timeout=300)
                pre_gui_log("[✅] System packages installed successfully.")
            except Exception as e:
                pre_gui_log(f"[!] Warning: Pacman install failed: {e}")

        if subprocess.call(["which", "ollama"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            try:
                pre_gui_log("[*] Installing Ollama automatically...")
                subprocess.check_call("curl -fsSL https://ollama.com/install.sh | sh", shell=True, timeout=120)
                subprocess.check_call(["sudo", "systemctl", "enable", "--now", "ollama"], timeout=10)
            except Exception: pass
        else:
            if subprocess.call(["systemctl", "is-active", "--quiet", "ollama"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                try: subprocess.check_call(["sudo", "systemctl", "start", "ollama"], timeout=10)
                except Exception: pass
        configure_ollama_systemd()

    REQUIRED_PACKAGES = {
        "browser_cookie3": "browser-cookie3",
        "requests": "requests",
        "bs4": "beautifulsoup4",
        "dateutil": "python-dateutil",
        "curl_cffi": "curl_cffi",
        "psutil": "psutil",
        "blackboxprotobuf": "blackboxprotobuf",
        "websockets": "websockets",
        "yt_dlp": "yt-dlp",
        "lz4.block": "lz4"
    }

    missing_pip = []
    for module_name, pip_name in REQUIRED_PACKAGES.items():
        if subprocess.call([sys.executable, "-c", f"import {module_name}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing_pip.append(pip_name)

    if missing_pip:
        pre_gui_log(f"[*] Installing missing PIP packages: {', '.join(missing_pip)}")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + missing_pip
            subprocess.check_call(cmd, env=os.environ.copy(), timeout=120)
            pre_gui_log("[✅] PIP packages installed successfully.")
        except Exception as e:
            pre_gui_log(f"[!] Warning: PIP install failed: {e}")

bootstrap_dependencies()

import logging
import warnings
import psutil
import websockets
import blackboxprotobuf
from bs4 import BeautifulSoup
import browser_cookie3
import platform
import requests
from curl_cffi import requests as cffi_requests
import yt_dlp
from PyQt6.QtGui import QPixmap, QPainter, QColor, QLinearGradient, QPen, QIcon, QFont, QPalette
from PyQt6.QtCore import Qt, QRectF, QUrl, QByteArray, QSettings, QTimer, QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTreeWidget, QTreeWidgetItem, QProgressBar, QStackedWidget, QGridLayout,
                             QLabel, QSplitter, QTabWidget, QPlainTextEdit, QLineEdit, QTreeWidgetItemIterator,
                             QTableWidget, QTableWidgetItem, QCheckBox, QGroupBox, QMessageBox)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (QWebEngineProfile, QWebEngineSettings, QWebEnginePage, QWebEngineScript, QWebEngineUrlRequestInterceptor)
from PyQt6.QtNetwork import QNetworkCookie, QNetworkProxy
from PyQt6.QtCore import qInstallMessageHandler, QtMsgType

warnings.filterwarnings("ignore", category=DeprecationWarning)
HISTORY_FILE = "media_history.json"
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
TIME_OFFSET = timedelta(0)

def calibrate_atomic_time():
    global TIME_OFFSET
    try:
        res = requests.head("https://www.google.com", headers={"User-Agent": "Mozilla/5.0"}, timeout=5, allow_redirects=True)
        if 'Date' in res.headers:
            real_time = email.utils.parsedate_to_datetime(res.headers['Date'])
            if real_time.tzinfo is None: real_time = real_time.replace(tzinfo=timezone.utc)
            TIME_OFFSET = real_time - datetime.now(timezone.utc)
    except Exception: pass
calibrate_atomic_time()

def get_real_now() -> datetime: return datetime.now(timezone.utc) + TIME_OFFSET

class LogSignalEmitter(QObject):
    log_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger("MediaMonitor")

def console_log(msg: str): print(msg, flush=True)

class QtLogHandler(logging.Handler):
    def __init__(self, emitter):
        super().__init__()
        self.emitter = emitter
    def emit(self, record):
        msg = self.format(record)
        timestamp = get_real_now().strftime("%H:%M:%S")
        self.emitter.log_signal.emit(f"[{timestamp}] {msg}")

class GlobalStreamRedirector:
    def __init__(self, is_stderr=False):
        self.is_flushing = False
        self.is_stderr = is_stderr
        self.original_stream = sys.__stderr__ if is_stderr else sys.__stdout__

    def write(self, text):
        if not text.strip(): return

        # --- THE FIX: Filter spam BEFORE writing to the terminal ---
        ignore_spam = [
            "--> starting at object", "property 'pluginInstances'", "closes the circle",
            "object with constructor", "stun_port.cc", "Binding request timed out",
            "glGetProgramiv" # Added the WebGL spam here just in case!
        ]
        if any(spam in text for spam in ignore_spam):
            return  # Drop the log completely

        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        clean_text = text.strip()
        prefix = "[STDERR]" if self.is_stderr else "[STDOUT]"
        formatted_console_msg = f"[{timestamp}] {prefix} {clean_text}"

        self.original_stream.write(formatted_console_msg + "\n")
        self.original_stream.flush()

        if self.is_flushing: return
        self.is_flushing = True

        for line in clean_text.splitlines():
            line = line.strip()
            if line:
                msg = f"[System/Deps] [ERROR] {line}" if self.is_stderr else f"[System/Deps] {line}"
                if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                    GUI_EMITTER.log_signal.emit(f"[{timestamp}] {msg}")
                else:
                    pre_gui_log(msg)

        self.is_flushing = False

    def flush(self):
        self.original_stream.flush()

sys.stderr = GlobalStreamRedirector(is_stderr=True)
sys.stdout = GlobalStreamRedirector(is_stderr=False)

# --- C-LEVEL NATIVE STDERR INTERCEPTOR ---
# Chromium C++ bypasses Python's sys.stderr. We must intercept OS File Descriptor 2 directly to block native spam.
try:
    _original_stderr_fd = os.dup(2)
    _pipe_r, _pipe_w = os.pipe()
    os.dup2(_pipe_w, 2)
    os.close(_pipe_w)

    def _native_stderr_pump():
        with os.fdopen(_pipe_r, 'r', errors='replace') as f:
            for line in f:
                # TikTok's WebMSSDK intentionally triggers these WebGL errors for fingerprinting
                if any(spam in line for spam in ["gl_utils.cc", "glGetProgramiv", "WebGL-", "Program object expected"]):
                    continue
                # Write approved lines back to the actual terminal
                os.write(_original_stderr_fd, line.encode('utf-8', errors='replace'))

    _pump_thread = threading.Thread(target=_native_stderr_pump, daemon=True)
    _pump_thread.start()
except Exception:
    pass

class UnifiedNetworkFetcher:
    _sessions = {}
    _domain_locks = {}
    _last_request_time = {}
    _GLOBAL_LOCK = threading.Lock()

    @classmethod
    def _get_session(cls, use_proxy=False):
        key = "direct"
        if key not in cls._sessions:
            cls._sessions[key] = cffi_requests.Session(impersonate="chrome", proxies=None)
        return cls._sessions[key]

    @classmethod
    def _pace_domain(cls, domain):
        with cls._GLOBAL_LOCK:
            if domain not in cls._domain_locks:
                cls._domain_locks[domain] = threading.Lock()

        with cls._domain_locks[domain]:
            now = time.time()
            last = cls._last_request_time.get(domain, 0)
            delay = 0.18 - (now - last)
            if delay > 0:
                time.sleep(delay)
            cls._last_request_time[domain] = time.time()

    @staticmethod
    def fetch(url, service_target, log_callback, method="GET", timeout=12):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower() if parsed.hostname else parsed.netloc.lower()
        port = parsed.port
        if not port:
            port = 443 if scheme == "https" else (80 if scheme == "http" else "N/A")

        if scheme not in ["http", "https"]:
            msg = f"[SHIELD_ALERT] 🛑 NETWORK FIREWALL BLOCK | Service: {scheme.upper()} | Target: LOCAL/UNKNOWN | Port: {port} | Details: Hard-Blocked dangerous protocol in background fetcher | URL: {url}"
            if log_callback: log_callback(msg)
            elif 'GUI_EMITTER' in globals() and GUI_EMITTER: GUI_EMITTER.log_signal.emit(msg)
            return None

        is_safe = AIFirewall.check_domain(host)

        if not is_safe:
            msg = f"[SHIELD_ALERT] 🤖 NETWORK AI-GATED SHIELD | Service: {scheme.upper()} | Target: {host} | Port: {port} | Details: Background fetch rejected by AI | URL: {url}"
            if log_callback: log_callback(msg)
            elif 'GUI_EMITTER' in globals() and GUI_EMITTER: GUI_EMITTER.log_signal.emit(msg)
            return None

        domain = urllib.parse.urlsplit(url).netloc.lower()
        UnifiedNetworkFetcher._pace_domain(domain)
        session = UnifiedNetworkFetcher._get_session(use_proxy=False)
        start_time = time.time()
        req_headers = {"User-Agent": USER_AGENT, "x-background-scanner": "1", "Accept-Encoding": "gzip, deflate, br"}

        for attempt in range(2):
            try:
                if method == "HEAD":
                    response = session.head(url, headers=req_headers, timeout=timeout, allow_redirects=True, verify=False)
                    if response.status_code in [403, 404, 405, 999]:
                        response = session.get(url, headers=req_headers, timeout=timeout, allow_redirects=True, verify=False)
                else:
                    response = session.get(url, headers=req_headers, timeout=timeout, allow_redirects=True, verify=False)

                elapsed = time.time() - start_time
                if log_callback: log_callback(f"[{service_target}] ✅ curl_cffi Success: HTTP {response.status_code} | Size: {len(response.content)}b | Time: {elapsed:.2f}s")
                return response
            except Exception as e:
                if attempt == 0:
                    time.sleep(0.5)
                    continue
                elapsed = time.time() - start_time
                err_msg = str(e)
                if log_callback: log_callback(f"[{service_target}] ❌ [ERROR] curl_cffi Failed ({elapsed:.2f}s): {err_msg[:60]}")
                return None

    @staticmethod
    def pre_validate_link(url, service_target, log_callback=None):
        res = UnifiedNetworkFetcher.fetch(url, service_target, log_callback, method="GET", timeout=6)
        if res and res.status_code < 400: return True
        if log_callback: log_callback(f"[{service_target}] [PRE-VAL] Dropping dead/invalid link: {url}")
        return False

class YTDLP_InternalLogger:
    def debug(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg):
        if any(skip in msg for skip in ["Unsupported URL", "does not have any videos", "Unable to extract secondary user ID"]):
            return
        console_log(f"[YouTube ERR] [ERROR] YT-DLP Backend: {msg}")

class LlamaAIAnalyzer:
    TITLE_STRIP_STRINGS = [' | Fox News Video', ' - Fox News', ' | Fox Business', ' - LiveNOW from FOX']
    @classmethod
    def clean_title(cls, title: str) -> str:
        for s in cls.TITLE_STRIP_STRINGS: title = title.replace(s, '')
        return title.strip()
    @classmethod
    def evaluate_clip(cls, clip: dict, log_callback=None) -> tuple[bool, str]:
        url_lower = clip.get('url', '').lower()
        if "/person/" in url_lower or "/category/" in url_lower or "/author/" in url_lower:
            return False, "Failed fast-check: Profile/Category page detected."
        return True, "Auto-Approved: Native Logic Verification"

class AIDynamicScraper:
    _seen_extracted_urls = set()

    @staticmethod
    def extract_and_repair(raw_payload: str, source_url: str, log_callback=None):
        with AI_PROCESSING_LOCK:
            if log_callback: log_callback(f"[AI Logs] Running Heavy Extraction (Llama) on {source_url[:50]}...")
            prompt = f"""
            Extract the primary video stream, media post, or specific news article from this raw payload.
            Respond ONLY with a valid JSON object containing these keys: 'title', 'url', 'author', 'description'.

            CRITICAL STRICT RULES:
            1. DO NOT extract generalized text articles, author profiles, or category landing pages.
            2. DO NOT extract social media user profile homepages.
            3. ALWAYS extract the FULL complete path. Ensure endpoints match direct video streams (.mp4, .m3u8), players, or active watch structures.
            4. If it is a generic page or dead link, return an empty JSON object {{}}.

            Payload:
            {raw_payload[:2500]}
            """
            payload = {"model": "llama3.2", "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": 0.0, "num_predict": 200}}
            try:
                resp = requests.post("http://127.0.0.1:11434/api/generate", json=payload, timeout=90)
                if resp.status_code == 200:
                    json_match = re.search(r'\{.*\}', resp.json().get("response", "").strip(), re.DOTALL)
                    if json_match:
                        extracted_data = json.loads(json_match.group(0))
                        if extracted_data.get('url'):
                            ext_url = urllib.parse.urljoin(source_url, extracted_data['url'])
                            extracted_data['url'] = ext_url
                            title = extracted_data.get('title', '')

                            if ext_url in AIDynamicScraper._seen_extracted_urls or not title or len(title) < 5 or any(bad in ext_url.lower() for bad in ['/login', '/signup', '/search', 'auth', 'help', 'settings']):
                                return None

                            AIDynamicScraper._seen_extracted_urls.add(ext_url)

                            # --- DOUBLE VERIFICATION PHASE ---
                            if log_callback: log_callback(f"[AI Logs] 🔍 Link extracted. Running Phase 2 Double-Verification on {ext_url[:40]}...")

                            val_res = UnifiedNetworkFetcher.fetch(ext_url, "AI Validate", log_callback, method="GET", timeout=7)
                            if not val_res or val_res.status_code >= 400:
                                if log_callback: log_callback(f"[❌] [AI Logs] Verification failed: Link returned HTTP {val_res.status_code if val_res else 'Timeout'}. Discarding.")
                                return None

                            soup = BeautifulSoup(val_res.content, "html.parser")
                            for script in soup(["script", "style", "nav", "footer"]):
                                script.decompose()
                            page_text = soup.get_text(separator=" ", strip=True)[:1500]

                            val_prompt = f"""
                            You previously extracted a URL. I visited it and here is the text on the page:
                            "{page_text}"

                            Does this page look like a SPECIFIC news article, social media post, or video? Or does it look like a dead link, a "Something went wrong" error, a login wall, or a generic user profile page?
                            Reply strictly with the word "VALID" or "INVALID".
                            """
                            val_payload = {"model": "llama3.2", "prompt": val_prompt, "stream": False, "options": {"temperature": 0.0, "num_predict": 5}}
                            val_resp = requests.post("http://127.0.0.1:11434/api/generate", json=val_payload, timeout=20)

                            if val_resp.status_code == 200:
                                val_answer = val_resp.json().get("response", "").strip().upper()
                                if "INVALID" in val_answer:
                                    if log_callback: log_callback(f"[❌] [AI Logs] Phase 2 failed: AI determined the destination page is dead/generic. Discarding.")
                                    return None
                            # --- END DOUBLE VERIFICATION ---

                            if log_callback: log_callback(f"[✅] [AI Logs] Phase 2 Passed! Verified Live Video/Article: {ext_url}")
                            return extracted_data
            except Exception as e:
                if log_callback: log_callback(f"[❌] [AI Logs] [ERROR] Llama extraction/validation failed: {e}")
            return None

class FoxNewsSearchEngine:
    _captured_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*", "Referer": "https://www.foxnews.com/"}
    @classmethod
    def update_headers(cls, new_headers: dict):
        if new_headers: cls._captured_headers.update(new_headers)
    @staticmethod
    def fetch_search_results(target_name: str, log_callback=None) -> list:
        clips_found = []
        encoded_query = urllib.parse.quote(target_name)
        moxie_url = f"https://moxie.foxnews.com/search/aggregate/web?q={encoded_query}&fields=web"
        resp = UnifiedNetworkFetcher.fetch(moxie_url, "FoxAPI", log_callback)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                items = []
                for tab in data.get('tabs', []):
                    if isinstance(tab, dict) and isinstance(tab.get('data', []), list): items.extend(tab.get('data', []))
                for idx, item in enumerate(items):
                    if not isinstance(item, dict): continue
                    attrs = item.get('attributes', {})
                    title = attrs.get('title') or item.get('title') or attrs.get('headline') or ''
                    url = attrs.get('canonical_url') or item.get('url') or attrs.get('link') or ''
                    if url and not url.startswith('http'): url = 'https://www.foxnews.com' + url
                    pub_date = attrs.get('publication_date') or item.get('pdate') or ''
                    description = attrs.get('description') or item.get('snippet') or ''

                    if not title or not url: continue

                    dt_obj = None
                    if pub_date:
                        try:
                            from dateutil import parser as date_parser
                            dt_obj = date_parser.parse(str(pub_date))
                            if dt_obj.tzinfo is None: dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                        except: pass
                    if not dt_obj: dt_obj = get_real_now() - timedelta(seconds=idx)

                    clips_found.append({
                        "title": LlamaAIAnalyzer.clean_title(title), "url": url,
                        "datetime": dt_obj, "date_str": dt_obj.strftime('%Y-%m-%d'),
                        "target": target_name, "author": "Fox News",
                        "description": description, "source": "FoxAPI", "original_order": idx
                    })
            except Exception as e:
                if log_callback: log_callback(f"[FoxAPI ERR] [ERROR] Parse Failed: {e}")
        return clips_found

class GlobalMediaScanner:
    @staticmethod
    def _fetch_youtube(name, use_proxy, log_cb):
        clips = []
        ydl_opts = {
            'extract_flat': 'in_playlist', 'quiet': True, 'logger': YTDLP_InternalLogger(),
            'skip_download': True, 'ignoreerrors': True, 'no_warnings': True, 'nocheckcertificate': True,
            'http_headers': {'x-background-scanner': '1', 'User-Agent': USER_AGENT}
        }

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(f"ytsearch50:{name} Fox News", download=False)
                for entry in (info.get('entries', []) if info else []):
                    if not entry: continue
                    dt_obj = None
                    if entry.get('upload_date') and len(entry.get('upload_date')) == 8:
                        try: dt_obj = datetime.strptime(entry.get('upload_date'), '%Y%m%d').replace(tzinfo=timezone.utc) + timedelta(hours=12)
                        except: pass
                    if not dt_obj and entry.get('timestamp'): dt_obj = datetime.fromtimestamp(entry['timestamp'], tz=timezone.utc)
                    elif not dt_obj and entry.get('release_timestamp'): dt_obj = datetime.fromtimestamp(entry['release_timestamp'], tz=timezone.utc)
                    if not dt_obj: dt_obj = get_real_now()

                    clip = {
                        'title': LlamaAIAnalyzer.clean_title(entry.get('title', '')),
                        'url': entry.get('url') or f"https://www.youtube.com/watch?v={entry.get('id')}",
                        'target': name, 'author': entry.get('uploader') or entry.get('channel', 'YouTube'),
                        'description': entry.get('description', ''), 'source': 'YouTube',
                        'datetime': dt_obj, 'date_str': dt_obj.strftime('%Y-%m-%d')
                    }
                    is_valid, reason = LlamaAIAnalyzer.evaluate_clip(clip, log_cb)
                    if is_valid:
                        icon = "✅"
                        log_cb(f"[{icon}] [{clip.get('source')}] ({clip.get('target')}) {clip.get('title', '')[:50]}... | {reason}")
                        clip['title'] = f"[{clip['date_str']}] {clip['title']}"
                        clips.append(clip)
        except Exception as e: log_cb(f"[YouTube ERR] [ERROR] {name}: {e}")
        return clips

    @staticmethod
    def _fetch_google_rss(search_query, target_name, log_cb, source_override="GoogleRSS"):
        clips_found = []
        encoded_query = urllib.parse.quote(f'"{search_query}" Fox News' if source_override == "GoogleRSS" else search_query)
        rss_url = f"https://news.google.com/rss/search?q={encoded_query}&hl=en-US&gl=US&ceid=US:en"
        response = UnifiedNetworkFetcher.fetch(rss_url, source_override, log_cb)
        if response and response.status_code == 200:
            try:
                root = ET.fromstring(response.content)
                for idx, item in enumerate(root.findall('.//item')):
                    title = LlamaAIAnalyzer.clean_title(item.find('title').text or "")
                    url = item.find('link').text or ""
                    if not url: continue

                    desc = BeautifulSoup(item.find('description').text or "", "html.parser").get_text(strip=True)
                    dt_obj = None
                    pub_date = item.find('pubDate')
                    if pub_date is not None and pub_date.text:
                        try:
                            dt_obj = email.utils.parsedate_to_datetime(pub_date.text)
                            if dt_obj.tzinfo is None: dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                        except: pass
                    if not dt_obj: dt_obj = get_real_now() - timedelta(seconds=idx)

                    clip = {
                        'title': title, 'url': url,
                        'datetime': dt_obj, 'date_str': dt_obj.strftime('%Y-%m-%d'),
                        'target': target_name, 'author': source_override,
                        'description': desc, 'source': source_override, 'original_order': idx
                    }
                    is_valid, reason = LlamaAIAnalyzer.evaluate_clip(clip, log_cb)
                    if is_valid:
                        icon = "✅"
                        log_cb(f"[{icon}] [{clip.get('source')}] ({clip.get('target')}) {clip.get('title', '')[:50]}... | {reason}")
                        clip['title'] = f"[{clip['date_str']}] {clip['title']}"
                        clips_found.append(clip)
            except Exception as e:
                log_cb(f"[{source_override} ERR] [ERROR] XML Error: {e}")
        return clips_found

    @staticmethod
    def _fetch_web_scrape_fallback(url, target_name, log_cb):
        clips_found = []
        if not url: return clips_found
        response = UnifiedNetworkFetcher.fetch(url, "ProfileScrape", log_cb)
        if response and response.status_code == 200:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                for junk in soup.find_all(['nav', 'footer']): junk.decompose()
                valid_containers = soup.find_all('article') or soup.find_all('div', class_=re.compile(r'\barticle\b|post|item', re.IGNORECASE))
                for idx, container in enumerate(valid_containers[:150]):
                    title_tag = container.find(['h2', 'h3', 'h4', 'h5', 'h1']) or container.find(['a', 'span', 'div'], class_=re.compile(r'title|headline', re.IGNORECASE))
                    if not title_tag: continue
                    a_tag = title_tag if title_tag.name == 'a' else title_tag.find('a') or title_tag.find_parent('a') or container.find('a')
                    if not a_tag or not a_tag.has_attr('href'): continue
                    title = a_tag.get_text(strip=True) or title_tag.get_text(strip=True)
                    if len(title) < 10: continue
                    href = a_tag['href']
                    if "/person/" in href or "/category/" in href or href == "#": continue
                    full_url = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url)) + href if href.startswith('/') else href

                    raw_datetime = container.find('time')['datetime'] if container.find('time') and container.find('time').has_attr('datetime') else (re.search(r'datetime="([^"]+)"', str(container)).group(1) if re.search(r'datetime="([^"]+)"', str(container)) else "")
                    date_str = re.search(r'(\d{4}-\d{2}-\d{2})', raw_datetime).group(1) if re.search(r'(\d{4}-\d{2}-\d{2})', raw_datetime) else ((get_real_now() - timedelta(days=int(re.search(r'(\d+)\s*days?', container.get_text(separator=" ").lower()).group(1)))).strftime('%Y-%m-%d') if re.search(r'(\d+)\s*days?', container.get_text(separator=" ").lower()) else get_real_now().strftime('%Y-%m-%d'))
                    try: dt_obj = datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc) - timedelta(seconds=idx)
                    except: dt_obj = get_real_now() - timedelta(seconds=idx)
                    desc_tag = container.find(['p', 'div', 'span'], class_=re.compile(r'dek|description|snippet|summary', re.IGNORECASE))

                    clip = {
                        "title": LlamaAIAnalyzer.clean_title(title), "url": full_url, "datetime": dt_obj, "date_str": date_str,
                        "target": target_name, "author": "Fox Profile Scrape",
                        "description": f"RAW HTML DATETIME: {raw_datetime} | {desc_tag.get_text(strip=True) if desc_tag else 'Scraped from Fox Profile page.'}",
                        "source": "ProfileScrape", "original_order": idx
                    }
                    is_valid, reason = LlamaAIAnalyzer.evaluate_clip(clip, log_cb)
                    if is_valid:
                        icon = "✅"
                        log_cb(f"[{icon}] [{clip.get('source')}] ({clip.get('target')}) {clip.get('title', '')[:50]}... | {reason}")
                        clip['title'] = f"[{clip['date_str']}] {clip['title']}"
                        clips_found.append(clip)
            except Exception as e:
                log_cb(f"[ProfileScrape ERR] [ERROR] Failed: {e}")
        return clips_found

    @staticmethod
    def _fetch_social(name, target_cfg, platform_tag, url_prefix, log_cb):
        clips = []
        user_key = f"{platform_tag.lower().replace('.com', '')}_user"
        if platform_tag == "X.com": user_key = "x_user"
        user = target_cfg.get(user_key)
        if not user: return clips

        url = f"{url_prefix}{user}"

        if platform_tag == "Facebook" and " " in user:
            log_cb(f"[{platform_tag}] [*] Search query detected. Running Google Dork bypass for: {user}")
            return GlobalMediaScanner._fetch_google_rss(f'"{user}" site:facebook.com', name, log_cb, source_override="Facebook Feed")

        if platform_tag in ["TikTok", "Facebook"]:
            log_cb(f"[{platform_tag}] [*] Background syncing latest posts for {url}...")
            time.sleep(random.uniform(1.5, 3.0))
            ydl_opts = {
                'extract_flat': 'in_playlist', 'lazy_playlist': True, 'quiet': True,
                'skip_download': True, 'nocheckcertificate': True, 'ignoreerrors': True,
                'no_warnings': True, 'logger': YTDLP_InternalLogger(), 'playlist_end': 10,
                'socket_timeout': 8, 'http_headers': {'x-background-scanner': '1', 'User-Agent': USER_AGENT}
            }
            try:
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    info = ydl.extract_info(url, download=False)
                    if info and 'entries' in info:
                        for entry in info['entries']:
                            if not entry: continue
                            ts = entry.get('timestamp') or time.time()
                            dt_obj = datetime.fromtimestamp(ts, tz=timezone.utc)
                            thumbnails = entry.get('thumbnails', [])
                            cover_url = thumbnails[0]['url'] if thumbnails else ""
                            stats = {'playCount': entry.get('view_count', 0), 'diggCount': entry.get('like_count', 0)}

                            source_name = f"{platform_tag} Feed"
                            clip = {
                                "id": entry.get('id', ''),
                                "title": LlamaAIAnalyzer.clean_title(entry.get('title', entry.get('description', f'{platform_tag} Video'))),
                                "url": entry.get('url') or url,
                                "datetime": dt_obj, "date_str": dt_obj.strftime('%Y-%m-%d'),
                                "target": name, "author": entry.get('channel', platform_tag),
                                "description": entry.get('description', ''),
                                "source": source_name, "original_order": 0,
                                "video": {"cover": cover_url}, "stats": stats
                            }
                            icon = "✅"
                            log_cb(f"[{icon}] [{clip.get('source')}] ({clip.get('target')}) {clip.get('title', '')[:50]}... | Pulled cleanly via yt-dlp")
                            clip['title'] = f"[{clip['date_str']}] {clip['title']}"
                            clips.append(clip)
            except Exception as e: log_cb(f"[{platform_tag} ERR] [ERROR] {e}")
            return clips

        if platform_tag == "X.com":
            target_url = f"https://x.com/search?q={urllib.parse.quote(user)}" if " " in user else url
            resp = UnifiedNetworkFetcher.fetch(target_url, platform_tag, log_cb)
            if resp and resp.status_code == 200:
                try:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    articles = soup.find_all('article', attrs={'data-tweet-id': True}) or soup.find_all('article')
                    for idx, art in enumerate(articles[:15]):
                        tweet_url_tag = art.find('meta', attrs={'itemProp': 'url'})
                        tweet_url = tweet_url_tag.get('content') if tweet_url_tag else ""
                        if not tweet_url:
                            for a in art.find_all('a', href=True):
                                if '/status/' in a['href']:
                                    tweet_url = a['href'] if a['href'].startswith('http') else f"https://x.com{a['href']}"
                                    break
                        if not tweet_url: continue

                        text_tag = art.find('meta', attrs={'itemProp': 'text'})
                        tweet_text = text_tag.get('content', '') if text_tag else art.get_text(" ", strip=True)

                        date_tag = art.find('meta', attrs={'itemProp': 'datePublished'}) or art.find('meta', attrs={'itemProp': 'dateCreated'})
                        date_str = date_tag.get('content', '') if date_tag else ""
                        dt_obj = None
                        if date_str:
                            try:
                                from dateutil import parser as date_parser
                                dt_obj = date_parser.parse(date_str)
                                if dt_obj.tzinfo is None: dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                            except Exception: pass
                        if not dt_obj: dt_obj = get_real_now() - timedelta(seconds=idx)

                        clip = {
                            "title": LlamaAIAnalyzer.clean_title(tweet_text[:120]),
                            "url": tweet_url,
                            "datetime": dt_obj, "date_str": dt_obj.strftime('%Y-%m-%d'),
                            "target": name, "author": f"@{user}",
                            "description": tweet_text,
                            "source": "X.com Feed", "original_order": idx
                        }
                        icon = "✅"
                        log_cb(f"[{icon}] [{clip.get('source')}] ({clip.get('target')}) {clip.get('title', '')[:50]}... | Parsed X.com Timeline")
                        clip['title'] = f"[{clip['date_str']}] {clip['title']}"
                        clips.append(clip)
                except Exception as e: log_cb(f"[X.com ERR] [ERROR] Parsing failed: {e}")
            return clips

        if platform_tag == "Instagram":
            resp = UnifiedNetworkFetcher.fetch(url, platform_tag, log_cb)
            if resp and resp.status_code == 200:
                try:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for idx, link in enumerate(soup.find_all('a', href=True)):
                        href = link['href']
                        if '/videos/' in href or '/posts/' in href or '/reel/' in href or '/p/' in href:
                            full_post_url = href if href.startswith('http') else f"{url_prefix.rstrip('/')}{href}"
                            title_text = link.get_text(strip=True) or f"Instagram Post by {name}"
                            dt_obj = get_real_now() - timedelta(minutes=idx * 10)
                            clip = {
                                "title": LlamaAIAnalyzer.clean_title(title_text[:120]),
                                "url": full_post_url,
                                "datetime": dt_obj, "date_str": dt_obj.strftime('%Y-%m-%d'),
                                "target": name, "author": name,
                                "description": f"Extracted from Instagram profile feed.",
                                "source": "Instagram Feed", "original_order": idx
                            }
                            icon = "✅"
                            log_cb(f"[{icon}] [{clip.get('source')}] ({clip.get('target')}) {clip.get('title', '')[:50]}... | Found IG Media")
                            clip['title'] = f"[{clip['date_str']}] {clip['title']}"
                            clips.append(clip)
                            if len(clips) >= 10: break
                except Exception as e: log_cb(f"[Instagram ERR] [ERROR] {e}")
        return clips

def run_scan_task(args):
    task_type, name, target_cfg, use_proxy, platform_tag, url_prefix = args
    logs = []
    clips = []
    def log_cb(msg):
        logs.append(msg)
    try:
        if task_type == 'youtube':
            clips = GlobalMediaScanner._fetch_youtube(name, use_proxy, log_cb)
        elif task_type == 'fox_api':
            for c in FoxNewsSearchEngine.fetch_search_results(name, log_cb):
                is_valid, reason = LlamaAIAnalyzer.evaluate_clip(c, log_cb)
                if is_valid:
                    log_cb(f"[✅] [{c.get('source')}] ({c.get('target')}) {c.get('title', '')[:50]}... | {reason}")
                    c['title'] = f"[{c['date_str']}] {c['title']}"
                    clips.append(c)
        elif task_type == 'google_rss':
            clips = GlobalMediaScanner._fetch_google_rss(name, name, log_cb)
        elif task_type == 'profile_scrape':
            clips = GlobalMediaScanner._fetch_web_scrape_fallback(target_cfg.get("profile_url"), name, log_cb)
        elif task_type == 'social':
            clips = GlobalMediaScanner._fetch_social(name, target_cfg, platform_tag, url_prefix, log_cb)
    except Exception as e:
        logs.append(f"[SYS_LOG] [ERROR] Task {task_type} for {name} failed: {e}")
    return task_type, clips, logs

class StreamResolverThread(QThread):
    resolved = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, url):
        super().__init__()
        self.url = url
    def run(self):
        try:
            target_url = self.url
            parsed = urllib.parse.urlparse(target_url)
            if parsed.scheme.lower() not in ["http", "https"]:
                if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                    GUI_EMITTER.log_signal.emit(f"[SHIELD_ALERT] 🛑 Blocked Video Player from executing dangerous protocol: {target_url}")
                self.error.emit("Shield Blocked: Invalid Protocol")
                return

            host = parsed.netloc.lower()

            is_safe = AIFirewall.check_domain(host)
            if not is_safe:
                if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                    GUI_EMITTER.log_signal.emit(f"[SHIELD_ALERT] 🤖 Blocked Video Player from resolving AI-rejected domain: {host}")
                self.error.emit("AI Shield: Domain Rejected")
                return

            if "news.google.com" in target_url:
                res = UnifiedNetworkFetcher.fetch(target_url, "Resolver", None, timeout=6)
                if res and res.url: target_url = res.url
            ydl_opts = {
                'quiet': True,
                'nocheckcertificate': True,
                'ignoreerrors': True,
                'format': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
            }
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(target_url, download=False)
                stream_url = info.get('url') if info else None
                if not stream_url and info and 'formats' in info and len(info['formats']) > 0: stream_url = info['formats'][-1].get('url')
                if stream_url: self.resolved.emit(stream_url)
                else: self.error.emit("No media stream extracted by yt-dlp.")
        except Exception as e: self.error.emit(str(e))

class AIErrorDiagnosticWorker(QThread):
    diagnostic_ready = pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.error_queue = []
        self.running = True
        self.analyzed_session_cache = set()
        self.last_ai_call_time = 0

    def add_error(self, error_msg):
        if any(tag in error_msg for tag in ["[AI Logs]", "[AI Auto-Diag]", "[Qwen", "LLAMA ONLINE", "Analyzing Unique Error"]): return
        clean_error = re.sub(r'<[^>]+>', '', error_msg)
        clean_error = re.sub(r'\[\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\]', '', clean_error)
        clean_error = re.sub(r'\b1\d{12}\b', '', clean_error).strip()
        signature_hash = hashlib.md5(clean_error.encode()).hexdigest()
        lower_err = clean_error.lower()
        if "timeout" in lower_err and "socket" in lower_err: return
        if "404" in lower_err or "410" in lower_err: return
        if "js info" in lower_err or "js warn" in lower_err: return

        if signature_hash not in self.analyzed_session_cache:
            self.analyzed_session_cache.add(signature_hash)
            self.error_queue.append(clean_error)

    def run(self):
        while self.running:
            current_time = time.time()
            if self.error_queue and (current_time - self.last_ai_call_time) > 12.0:
                error_to_analyze = self.error_queue.pop(0)
                self.last_ai_call_time = current_time

                prompt = f"""
                Analyze this error from the Media Monitor app: '{error_to_analyze}'.
                Determine if this is a fixable local application error or an external/proprietary anti-bot block (like TikTok WebMSSDK or CORS server restrictions).

                You MUST start your response with EXACTLY one of these two tags:
                1. '[HEAL SUCCESS]' followed by the actual corrective code or config fix.
                2. '[HEAL FAILED]' followed by why it cannot be patched programmatically (e.g., closed-source proprietary block or external server rate limit).
                """

                self.diagnostic_ready.emit(f"<span style='color: #8B5CF6;'>[AI Logs] <b>[Llama 3.2 Healer]</b> Evaluating error healability...</span>")
                payload = {"model": "llama3.2", "prompt": prompt, "stream": False, "options": {"temperature": 0.0}}
                try:
                    resp = requests.post("http://127.0.0.1:11434/api/generate", json=payload, timeout=25)
                    if resp.status_code == 200:
                        diagnosis = resp.json().get("response", "").strip()
                        color = "#10B981" if "[HEAL SUCCESS]" in diagnosis else "#EF4444"
                        self.diagnostic_ready.emit(f"<span style='color: {color};'><b>[AI Healer Audit]</b> {diagnosis}</span><br>")
                except Exception as e:
                    self.diagnostic_ready.emit(f"<span style='color: #EF4444;'>[AI Logs] [ERROR] Llama Healer Worker failed: {e}</span><br>")
            time.sleep(2.0)

class MediaScannerWorker(QThread):
    scan_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(int, str)
    log_msg = pyqtSignal(str)

    def __init__(self, target_list=None, parent=None):
        super().__init__(parent)
        self.target_data = get_targets_data()
        self.target_map = {t["name"]: t for t in self.target_data}
        self.target_list = target_list if target_list else [t["name"] for t in self.target_data]

    def run(self):
        results = {'network_clips': [], 'youtube_clips': []}
        settings = get_app_settings()
        use_proxy = False  # Disabled proxy dependency for CDP intercept
        enable_social = settings.get("enable_background_social_scans", False)

        tasks = []
        for name in self.target_list:
            target_cfg = self.target_map.get(name, {})
            if target_cfg.get("youtube", True):
                tasks.append(('youtube', name, target_cfg, use_proxy, None, None))
            if target_cfg.get("fox_api", True):
                tasks.append(('fox_api', name, target_cfg, use_proxy, None, None))
            if target_cfg.get("google_rss", True):
                tasks.append(('google_rss', name, target_cfg, use_proxy, None, None))
            if target_cfg.get("profile_scrape", True):
                tasks.append(('profile_scrape', name, target_cfg, use_proxy, None, None))

            if enable_social:
                if target_cfg.get("x", True):
                    tasks.append(('social', name, target_cfg, use_proxy, "X.com", "https://x.com/"))
                if target_cfg.get("tiktok", True):
                    tasks.append(('social', name, target_cfg, use_proxy, "TikTok", "https://www.tiktok.com/@"))
                if target_cfg.get("facebook", True):
                    tasks.append(('social', name, target_cfg, use_proxy, "Facebook", "https://www.facebook.com/"))
                if target_cfg.get("instagram", True):
                    tasks.append(('social', name, target_cfg, use_proxy, "Instagram", "https://www.instagram.com/"))

        cpu_cores = os.cpu_count() or 4
        optimal_workers = min(4, cpu_cores)

        self.progress_update.emit(10, f"Spawning {optimal_workers} Balanced Background Workers...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=optimal_workers) as executor:
            futures = []
            for t in tasks:
                futures.append(executor.submit(run_scan_task, t))
                time.sleep(0.05)

            total_tasks = len(futures)
            for idx, future in enumerate(concurrent.futures.as_completed(futures)):
                try:
                    task_type, clips, logs = future.result()
                    for log in logs:
                        self.log_msg.emit(log)
                    if task_type == 'youtube':
                        results['youtube_clips'].extend(clips)
                    else:
                        results['network_clips'].extend(clips)
                except Exception as e:
                    self.log_msg.emit(f"[SYS_LOG] [ERROR] Worker thread exception: {e}")

                prog = int(10 + ((idx + 1) / max(1, total_tasks)) * 85)
                self.progress_update.emit(prog, f"Scanning Background Profiles... ({idx+1}/{total_tasks} jobs)")

        filtered, seen = [], set()
        for clip in results['network_clips']:
            if clip['url'] not in seen:
                filtered.append(clip)
                seen.add(clip['url'])
        results['network_clips'] = filtered

        self.progress_update.emit(100, "Multi-Threaded Scan Complete.")
        self.scan_complete.emit(results)

class OllamaModelManager(QThread):
    progress_update = pyqtSignal(int, str)
    download_complete = pyqtSignal()
    log_msg = pyqtSignal(str)
    def run(self):
        self.progress_update.emit(10, "Verifying Dual-Tier Models (Llama & Qwen)...")
        try:
            resp = requests.get("http://127.0.0.1:11434/api/tags", timeout=5)
            models = [m.get("name", "") for m in resp.json().get("models", [])] if resp.status_code == 200 else []

            if "llama3.2:latest" not in models and "llama3.2" not in models:
                self.progress_update.emit(30, "Pulling Heavy Model (Llama 3.2)...")
                subprocess.run(["ollama", "pull", "llama3.2"], check=True, timeout=120)

            if "qwen2.5:1.5b" not in models:
                self.progress_update.emit(70, "Pulling Micro Model (Qwen 1.5B)...")
                subprocess.run(["ollama", "pull", "qwen2.5:1.5b"], check=True, timeout=120)

            self.log_msg.emit("[SYS_LOG] [✅] Dual-Tier AI (Llama 3.2 & Qwen 2.5) successfully verified & loaded.")
            self.progress_update.emit(100, "AI Engine Ready.")
        except Exception as e:
            self.progress_update.emit(0, f"AI Init failed: {e}")
            self.log_msg.emit(f"[SYS_LOG] [ERROR] Failed to init Ollama: {e}")
        finally: self.download_complete.emit()

def unpack_protobuf(raw_bytes, depth=0):
    """
    Natively decompresses and decodes Protobuf payloads using pure bytes.
    Avoids string-escape recursion loops entirely.
    """
    if depth > 10:
        return None

    # 1. Unroll Compression (Gzip / Zlib)
    for _ in range(3):
        if raw_bytes.startswith(b'\x1f\x8b') or (len(raw_bytes) > 1 and raw_bytes[0] == 0x1f and raw_bytes[1] == 0x8b):
            try:
                raw_bytes = gzip.decompress(raw_bytes)
                continue
            except Exception: pass
        if len(raw_bytes) > 2 and raw_bytes[0] == 0x78:
            try:
                raw_bytes = zlib.decompress(raw_bytes)
                continue
            except Exception: pass
        break

    # 2. Native Protobuf Byte Decoding
    try:
        parsed, _ = blackboxprotobuf.decode_message(raw_bytes)
        if isinstance(parsed, dict) and len(parsed) > 0:
            new_dict = {}
            for k, v in parsed.items():
                new_dict[k] = process_field(v, depth + 1)
            return new_dict
    except Exception:
        pass

    # 3. Ultimate Fallback: Extract human-readable text from raw binary media chunks
    try:
        cleaned = "".join([chr(b) if 32 <= b < 127 else " " for b in raw_bytes])
        cleaned = " ".join(cleaned.split())
        if len(cleaned) > 5 and any(c.isalpha() for c in cleaned):
            return {"_extracted_text": cleaned}
    except Exception:
        pass

    return None

def process_field(v, depth):
    if isinstance(v, dict):
        return {k: process_field(val, depth) for k, val in v.items()}
    elif isinstance(v, list):
        return [process_field(val, depth) for val in v]
    elif isinstance(v, (bytes, bytearray)):
        unpacked = unpack_protobuf(v, depth)
        if unpacked is not None:
            return unpacked
        # If it's a pure binary media chunk, Base64 encode it so JSON doesn't crash
        return {"_raw_b64": base64.b64encode(v).decode('utf-8')}
    elif isinstance(v, str):
        # Catch strings that are accidentally decompressed binary payloads
        if v.startswith('\x1f') or 'H4sI' in v:
            try:
                b = v.encode('latin1')
                unpacked = unpack_protobuf(b, depth)
                if unpacked: return unpacked
            except Exception: pass
    return v

def decode_tiktok_websocket_frame(payload):
    if not payload: return None
    try:
        raw_bytes = None
        if isinstance(payload, bytes):
            raw_bytes = payload
        elif isinstance(payload, str):
            try:
                # Intercept pre-parsed JSON dicts
                parsed_json = json.loads(payload)
                if isinstance(parsed_json, dict):
                    if parsed_json.get("1") == "1" and parsed_json.get("7") != "msg":
                        return {"_sys_info": "Server Keep-Alive Ping (Skipped)"}
                    return process_field(parsed_json, 0)
                elif isinstance(parsed_json, list):
                    return process_field(parsed_json, 0)
            except Exception: pass

            try:
                # Check for Base64 encapsulation
                padding = 4 - (len(payload) % 4)
                padded = payload + ("=" * padding) if padding < 4 else payload
                raw_bytes = base64.b64decode(padded, validate=True)
            except Exception:
                raw_bytes = payload.encode('latin1', errors='ignore')

        if raw_bytes:
            unpacked = unpack_protobuf(raw_bytes, 0)
            if unpacked and isinstance(unpacked, dict):
                # Filter spam pings
                if unpacked.get("1") == "1" and unpacked.get("7") != "msg":
                    return {"_sys_info": "Server Keep-Alive Ping (Skipped)"}
                return unpacked
    except Exception:
        pass
    return payload


class CDPInterceptorWorker(QThread):
    log_signal = pyqtSignal(str, bool)

    def __init__(self, port=9222, parent=None):
        super().__init__(parent)
        self.port = port
        self.running = True
        self.attached_targets = set()

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.main_loop())
        finally:
            loop.close()

    async def main_loop(self):
        # Fetch the underlying DevTools websocket URL and push it to the GUI System Logs
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{self.port}/json/version")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    v_data = json.loads(resp.read().decode("utf-8"))
                    ws_url = v_data.get("webSocketDebuggerUrl")
                    if ws_url:
                        console_log(f"[System/Deps] DevTools listening on {ws_url}")
        except Exception:
            pass

        while self.running:
            try:
                targets = self._get_debug_targets()
                for target in targets:
                    target_id = target.get("id")
                    ws_url = target.get("webSocketDebuggerUrl")

                    # Broaden target filter to capture iframes, workers, and pages where TikTok Live operates
                    if ws_url and target_id not in self.attached_targets:
                        self.attached_targets.add(target_id)
                        asyncio.create_task(self.listen_to_target(target_id, ws_url))
            except Exception:
                pass
            await asyncio.sleep(1.0)

    def _get_debug_targets(self):
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{self.port}/json")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return []
        return []

    async def listen_to_target(self, target_id: str, ws_url: str):
        msg_id = 0
        try:
            async with websockets.connect(ws_url, max_size=20 * 1024 * 1024) as ws:
                msg_id += 1
                await ws.send(json.dumps({"id": msg_id, "method": "Network.enable", "params": {"maxPostDataSize": 65536}}))
                request_map = {}

                async for raw_msg in ws:
                    if not self.running:
                        break

                    data = json.loads(raw_msg)
                    method = data.get("method", "")
                    params = data.get("params", {})

                    # --- NATIVE TIKTOK LIVE WEBSOCKET SNIFFING VIA CDP ---
                    if method == "Network.webSocketCreated":
                        url = params.get("url", "")
                        self._log_websocket_event(url, "🔌 WebSocket Created / Connected")

                    elif method == "Network.webSocketWillSendHandshakeRequest":
                        req = params.get("request", {})
                        url = req.get("url", "")
                        headers = req.get("headers", {})
                        self._log_websocket_handshake(url, "OUTBOUND WS HANDSHAKE REQUEST", headers)

                    elif method == "Network.webSocketHandshakeResponseReceived":
                        resp = params.get("response", {})
                        status = resp.get("status", 0)
                        headers = resp.get("headers", {})
                        self._log_websocket_handshake("", "INBOUND WS HANDSHAKE RESPONSE", headers, status)

                    elif method == "Network.webSocketFrameReceived":
                        response = params.get("response", {})
                        payload = response.get("payloadData", "")
                        self._log_websocket_frame("⬅️ INBOUND WS FRAME (Decrypted)", payload)

                    elif method == "Network.webSocketFrameSent":
                        response = params.get("response", {})
                        payload = response.get("payloadData", "")
                        self._log_websocket_frame("➔ OUTBOUND WS FRAME", payload)
                    # ---------------------------------------------------

                    elif method == "Network.requestWillBeSent":
                        req = params.get("request", {})
                        req_id = params.get("requestId")
                        url = req.get("url", "")
                        headers = req.get("headers", {})
                        http_method = req.get("method", "GET")
                        post_data = req.get("postData", "")

                        if not post_data and req.get("hasPostData", False):
                            try:
                                msg_id += 1
                                await ws.send(json.dumps({"id": msg_id, "method": "Network.getRequestPostData", "params": {"requestId": req_id}}))
                            except Exception:
                                pass

                        request_map[req_id] = {"url": url, "headers": headers, "method": http_method}
                        self._log_request(url, headers, http_method, post_data)

                    elif method == "Network.responseReceived":
                        req_id = params.get("requestId")
                        resp = params.get("response", {})
                        url = resp.get("url", "")
                        mime = resp.get("mimeType", "").lower()
                        status = resp.get("status", 0)
                        req_meta = request_map.get(req_id, {})

                        if any(t in mime for t in ["json", "text", "javascript", "xml"]) or "/api/" in url:
                            msg_id += 1
                            get_body_cmd = json.dumps({"id": msg_id, "method": "Network.getResponseBody", "params": {"requestId": req_id}})
                            await ws.send(get_body_cmd)

                            async for body_resp_raw in ws:
                                body_data = json.loads(body_resp_raw)
                                if body_data.get("id") == msg_id:
                                    result = body_data.get("result", {})
                                    body_text = result.get("body", "")
                                    self._log_response_body(url, status, mime, body_text, req_meta.get("headers", {}))
                                    break

        except Exception:
            pass
        finally:
            self.attached_targets.discard(target_id)

    def _determine_tag(self, url: str) -> str:
        u = url.lower()
        if "webmssdk" in u or "byteoversea" in u or "ttwstatic" in u: return "[WEBMSSDK]"
        if "tiktok.com" in u or "tiktokv" in u: return "[TIKTOK_LOG]"
        if "x.com" in u or "twitter.com" in u: return "[X_LOG]"
        if "facebook.com" in u: return "[FB_LOG]"
        if "instagram.com" in u: return "[INSTAGRAM_LOG]"
        if "foxnews.com" in u or "foxbusiness.com" in u: return "[FOXWEB_LOG]"
        if "news.google.com" in u: return "[GoogleRSS]"
        if "youtube.com" in u: return "[YouTube]"
        return "[WEB_LOG]"

    def _log_websocket_event(self, url: str, event_title: str):
        tag = self._determine_tag(url)
        log_html = (
            f"<div style='margin-bottom: 8px;'>"
            f"<span style='color: #10B981; font-weight: bold;'>{tag}</span> "
            f"<span style='color: #F59E0B; font-weight: bold;'>[{event_title}]</span><br>"
            f"<a href='{url}' style='color: #38BDF8; text-decoration: none;'>{url}</a><br>"
            f"<span style='color: #4B5563;'>{'-'*50}</span>"
            f"</div>"
        )
        self.log_signal.emit(log_html, True)

    def _log_websocket_handshake(self, url: str, title: str, headers: dict, status: int = None):
        tag = self._determine_tag(url if url else "https://www.tiktok.com")
        headers_html = "<br>".join([f"&nbsp;&nbsp;<span style='color: #93C5FD;'>{k}:</span> <span style='color: #D1D5DB;'>{v}</span>" for k, v in headers.items()])
        status_html = f" <span style='color: #34D399; font-weight: bold;'>(HTTP {status})</span>" if status else ""
        url_html = f"<a href='{url}' style='color: #38BDF8; text-decoration: none;'>{url}</a><br>" if url else ""

        log_html = (
            f"<div style='margin-bottom: 8px;'>"
            f"<span style='color: #10B981; font-weight: bold;'>{tag}</span> "
            f"<span style='color: #F59E0B; font-weight: bold;'>[{title}]{status_html}</span><br>"
            f"{url_html}"
            f"{headers_html}<br>"
            f"<span style='color: #4B5563;'>{'-'*50}</span>"
            f"</div>"
        )
        self.log_signal.emit(log_html, True)

    def _log_websocket_frame(self, direction: str, payload_str: str):
        if not payload_str.strip(): return

        try:
            # Decode Base64, unpack gzip, and unpack binary Protobuf frames
            decoded_json = decode_tiktok_websocket_frame(payload_str)

            if decoded_json:
                formatted_body = json.dumps(decoded_json, indent=2)
                body_color = "#34D399" # Bright green for successfully decoded live protobuf streams
            else:
                formatted_body = payload_str
                body_color = "#A78BFA" # Purple fallback for raw string/text frames
        except Exception:
            formatted_body = payload_str
            body_color = "#FCA5A5"

        try:
            settings = get_app_settings()
            tab_wrap_states = settings.get("tab_wrap_states", {})
            is_truncated = tab_wrap_states.get("TikTok", True)

            if is_truncated and len(formatted_body) > 2000:
                formatted_body = (
                    formatted_body[:2000] +
                    "\n\n... [✂️ TRUNCATED - Uncheck 'Truncate Lines (Wrap)' to view full payload] ..."
                )
        except Exception:
            if len(formatted_body) > 2000:
                formatted_body = formatted_body[:2000] + "\n\n... [✂️ TRUNCATED] ..."

        formatted_body = formatted_body.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>').replace('  ', '&nbsp;&nbsp;')

        log_html = (
            f"<div style='margin-bottom: 8px;'>"
            f"<span style='color: #10B981; font-weight: bold;'>[TIKTOK_LOG]</span> "
            f"<span style='color: #38BDF8; font-weight: bold;'>[{direction}]</span><br>"
            f"<span style='color: {body_color};'>{formatted_body}</span><br>"
            f"<span style='color: #4B5563;'>{'-'*50}</span>"
            f"</div>"
        )
        self.log_signal.emit(log_html, True)

    def _log_request(self, url: str, headers: dict, method: str, body: str = ""):
        if not url.startswith("http"): return
        tag = self._determine_tag(url)
        headers_html = "<br>".join([f"&nbsp;&nbsp;<span style='color: #93C5FD;'>{k}:</span> <span style='color: #D1D5DB;'>{v}</span>" for k, v in headers.items()])

        body_html = ""
        if body and body.strip():
            try:
                formatted_body = json.dumps(json.loads(body), indent=2)
                body_color = "#38BDF8"
            except Exception:
                formatted_body = body
                body_color = "#93C5FD"

            try:
                settings = get_app_settings()
                tab_wrap_states = settings.get("tab_wrap_states", {})
                key_map = {"[X_LOG]": "X.com", "[TIKTOK_LOG]": "TikTok", "[FB_LOG]": "Facebook", "[INSTAGRAM_LOG]": "Instagram", "[FOXWEB_LOG]": "Fox Web"}
                tab_key = key_map.get(tag, "Web")
                is_truncated = tab_wrap_states.get(tab_key, True)

                if is_truncated and len(formatted_body) > 2000:
                    formatted_body = (
                        formatted_body[:2000] +
                        "\n\n... [✂️ TRUNCATED - Uncheck 'Truncate Lines (Wrap)' to view full payload] ..."
                    )
            except Exception:
                if len(formatted_body) > 2000:
                    formatted_body = formatted_body[:2000] + "\n\n... [✂️ TRUNCATED] ..."

            formatted_body = formatted_body.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>').replace('  ', '&nbsp;&nbsp;')
            body_html = f"<br><span style='color: #F472B6; font-weight: bold;'>[OUTBOUND REQUEST BODY]</span><br><span style='color: {body_color};'>{formatted_body}</span><br>"

        log_html = (
            f"<div style='margin-bottom: 8px;'>"
            f"<span style='color: #10B981; font-weight: bold;'>{tag}</span> "
            f"<span style='color: #EC4899; font-weight: bold;'>[HTTP OUTBOUND REQUEST ➔] ({method})</span><br>"
            f"<a href='{url}' style='color: #38BDF8; text-decoration: none;'>{url}</a><br>"
            f"{headers_html}<br>"
            f"{body_html}"
            f"<span style='color: #4B5563;'>{'-'*50}</span>"
            f"</div>"
        )
        self.log_signal.emit(log_html, True)

    def _log_response_body(self, url: str, status: int, mime: str, body: str, headers: dict):
        if not body.strip(): return
        tag = self._determine_tag(url)

        try:
            formatted_body = json.dumps(json.loads(body), indent=2)
            body_color = "#A78BFA"
        except Exception:
            formatted_body = body
            body_color = "#FCA5A5"

        try:
            settings = get_app_settings()
            tab_wrap_states = settings.get("tab_wrap_states", {})
            key_map = {"[X_LOG]": "X.com", "[TIKTOK_LOG]": "TikTok", "[FB_LOG]": "Facebook", "[INSTAGRAM_LOG]": "Instagram", "[FOXWEB_LOG]": "Fox Web"}
            tab_key = key_map.get(tag, "Web")
            is_truncated = tab_wrap_states.get(tab_key, True)

            if is_truncated and len(formatted_body) > 2000:
                formatted_body = (
                    formatted_body[:2000] +
                    "\n\n... [✂️ TRUNCATED - Uncheck 'Truncate Lines (Wrap)' to view full payload] ..."
                )
        except Exception:
            if len(formatted_body) > 2000:
                formatted_body = formatted_body[:2000] + "\n\n... [✂️ TRUNCATED] ..."

        formatted_body = formatted_body.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>').replace('  ', '&nbsp;&nbsp;')

        log_html = (
            f"<div style='margin-bottom: 8px;'>"
            f"<span style='color: #10B981; font-weight: bold;'>{tag}</span> "
            f"<span style='color: #3B82F6; font-weight: bold;'>[⬅️ HTTP INBOUND RESPONSE: HTTP {status}]</span> "
            f"<span style='color: #9CA3AF;'>({mime})</span><br>"
            f"<a href='{url}' style='color: #38BDF8; text-decoration: none;'>{url}</a><br><br>"
            f"<span style='color: {body_color};'>{formatted_body}</span><br>"
            f"<span style='color: #4B5563;'>{'-'*60}</span>"
            f"</div>"
        )
        self.log_signal.emit(log_html, True)

class TikTokCommentWorker(QThread):
    comments_ready = pyqtSignal(str)

    def __init__(self, video_url):
        super().__init__()
        self.video_url = video_url

    def run(self):
        ydl_opts = {
            'getcomments': True,
            'skip_download': True,
            'quiet': True,
            'no_warnings': True,
            'extract_flat': False,
            'socket_timeout': 8,
            'http_headers': {'x-background-scanner': '1', 'User-Agent': USER_AGENT},
            'extractor_args': {'tiktok': ['api_hostname=api16-normal-c-useast1a.tiktokv.com']}
        }

        def extract():
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(self.video_url, download=False)
                raw_comments = info.get('comments', []) if info else []
                parsed = []
                for c in raw_comments[:50]:
                    ts_str = ""
                    if c.get('timestamp'):
                        try: ts_str = datetime.fromtimestamp(c['timestamp'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M')
                        except: pass

                    avatar_url = c.get('author_thumbnail') or c.get('avatar') or c.get('author_thumb') or ''
                    if isinstance(avatar_url, list) and avatar_url:
                        avatar_url = avatar_url[0].get('url', '') if isinstance(avatar_url[0], dict) else str(avatar_url[0])

                    parsed.append({
                        "author": c.get('author') or c.get('author_id') or "Anonymous",
                        "author_thumbnail": avatar_url,
                        "text": c.get('text') or "",
                        "like_count": c.get('like_count', 0),
                        "timestamp_str": ts_str
                    })
                return json.dumps(parsed)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(extract)
                result_json = future.result(timeout=10.0)
                parsed_check = json.loads(result_json)
                if not parsed_check:
                    raise Exception("Rate limited or empty response")
                self.comments_ready.emit(result_json)
        except Exception as e:
            err_str = str(e).lower()
            notice_text = (
                "⚠️ TikTok Rate-Limit / Captcha Triggered.\n"
                "TikTok has temporarily flagged rapid requests from this session. "
                "Please wait 30-60 seconds or click '🗑️ Clear Cache' to reset session fingerprints."
            )
            fallback_error = [{
                "author": "System Security Notice",
                "author_thumbnail": "",
                "text": notice_text,
                "like_count": 0,
                "timestamp_str": ""
            }]
            self.comments_ready.emit(json.dumps(fallback_error))

class TikTokProfileWorker(QThread):
    log_signal = pyqtSignal(str, bool)
    grid_signal = pyqtSignal(str, bool)
    progress_signal = pyqtSignal(int, str)

    def __init__(self, username, profile_url, offset=0, is_append=False, cookie_db=None):
        super().__init__()
        self.username = username
        self.profile_url = profile_url
        self.offset = offset
        self.is_append = is_append
        self.cookie_db = cookie_db

    def run(self):
        import random
        action_word = "Fetching more videos" if self.is_append else "Initiating real-time bypass"
        self.log_signal.emit(f"[TikTok] [*] {action_word} for @{self.username} (Offset: {self.offset})...", False)

        time.sleep(random.uniform(1.5, 3.0))
        cmd = [
            sys.executable, "-m", "yt_dlp",
            "--dump-json",
            "--flat-playlist",
            "--no-warnings",
            "--playlist-start", str(self.offset + 1),
            "--playlist-end", str(self.offset + 40),
            "--socket-timeout", "12",
            "--extractor-args", "tiktok:api_hostname=api16-normal-c-useast1a.tiktokv.com;app_info=1233"
        ]
        cmd.append(self.profile_url)

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )

            grid_payload = []
            count = 0

            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if 'id' in entry or 'url' in entry:
                        count += 1
                        prog_percent = min(95, 5 + int((count / 40) * 90))
                        self.progress_signal.emit(prog_percent, f"Extracting video {self.offset + count} for @{self.username}...")

                        vid_id = entry.get('id', '') or (entry.get('url', '').split('/')[-1] if entry.get('url') else f"vid_{self.offset + count}")
                        title = entry.get('title', 'TikTok Video')
                        description = entry.get('description', title)
                        url = entry.get('url') or f"https://www.tiktok.com/@{self.username}/video/{vid_id}"

                        thumbnails = entry.get('thumbnails', [])
                        cover_url = ""
                        anim_url = ""
                        for t in thumbnails:
                            t_url = t.get('url', '')
                            if '.webp' in t_url or 'animated' in t_url.lower():
                                anim_url = t_url
                            if '.jpeg' in t_url or '.jpg' in t_url:
                                cover_url = t_url
                        if not cover_url and thumbnails:
                            cover_url = thumbnails[0].get('url', '')
                        if not anim_url:
                            anim_url = cover_url

                        views = entry.get('view_count', 0)
                        likes = entry.get('like_count', 0)

                        grid_payload.append({
                            "id": vid_id,
                            "desc": description,
                            "url": url,
                            "author": self.username,
                            "video": {"cover": cover_url, "anim": anim_url},
                            "stats": {"playCount": views, "diggCount": likes}
                        })

                        log_item = f"<b>[{self.offset + count}] ID:</b> {vid_id} | <b>Desc:</b> {description[:40]}... | <a href='{url}' style='color:#60A5FA;'>{url}</a>"
                        self.log_signal.emit(log_item, True)
                except Exception:
                    pass

            process.stdout.close()
            process.wait()

            if grid_payload:
                self.progress_signal.emit(100, f"Mounting {len(grid_payload)} videos into grid...")
                self.grid_signal.emit(json.dumps(grid_payload), self.is_append)
            else:
                self.progress_signal.emit(100, "Bypass returned 0 videos. End of feed.")
                self.grid_signal.emit(json.dumps([]), self.is_append)
        except Exception as e:
            err_str = str(e).lower()
            is_ratelimit = "429" in err_str or "too many requests" in err_str or "captcha" in err_str or "timeout" in err_str
            if is_ratelimit:
                QTimer.singleShot(0, lambda: setattr(self, '_tiktok_rate_limited', True))
                QTimer.singleShot(60000, lambda: setattr(self, '_tiktok_rate_limited', False))
                self.log_signal.emit(f"[TikTok] [⚠️] Rate-limit/Timeout triggered. Entering 60s cooldown...", True)
            self.log_signal.emit(f"[TikTok] [ERROR] yt-dlp fetch failed: {e}", False)
            time.sleep(5.0)
            self.grid_signal.emit(json.dumps([]), self.is_append)

class ColorTabWidget(QTabWidget):
    def set_tab_text_color(self, index, color_hex): self.tabBar().setTabTextColor(index, QColor(color_hex))

class LoggingWebEnginePage(QWebEnginePage):
    def __init__(self, profile, view, log_prefix, app_instance=None):
        super().__init__(profile, view)
        self.log_prefix = log_prefix
        self.app_instance = app_instance
        self._last_msg = ""
        self._msg_count = 0

        if hasattr(self, 'certificateError') and hasattr(self.certificateError, 'connect'):
            self.certificateError.connect(self.handle_cert_error)

    def handle_cert_error(self, cert_error):
        if hasattr(cert_error, 'acceptCertificate'):
            cert_error.acceptCertificate()
        elif hasattr(cert_error, 'ignoreCertificateError'):
            cert_error.ignoreCertificateError()
        elif hasattr(cert_error, 'accept'):
            cert_error.accept()

    def acceptNavigationRequest(self, url, _type, isMainFrame):
        scheme = url.scheme().lower()
        host = url.host().lower()

        if scheme not in ["http", "https", "ws", "wss", "blob", "data", "about"]:
            if self.app_instance:
                self.app_instance.append_log_message(f"[WEB_SEC] [SHIELD_ALERT] 🛑 FIREWALL BLOCK | Service: {scheme.upper()} | Target: {host or 'UNTRUSTED_PROTOCOL'} | Details: Hard-Blocked non-standard web protocol | URL: {url.toString()}", is_embedded=True)
            return False

        if scheme in ["http", "https", "ws", "wss"]:
            is_safe = AIFirewall.check_domain(host)
            if not is_safe:
                if self.app_instance:
                    self.app_instance.append_log_message(f"[WEB_SEC] [SHIELD_ALERT] 🤖 AI-GATED SHIELD | Service: {scheme.upper()} | Target: {host} | Details: Blocked unauthorized redirect to AI-rejected domain | URL: {url.toString()}", is_embedded=True)
                return False

        return super().acceptNavigationRequest(url, _type, isMainFrame)

    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        ignore_phrases = [
            "Content Security Policy", "Refused to execute inline script", "third-party cookie",
            "Reflect is already polyfilled", "AppContext will be overwritten", "loadableReady",
            "set global cache", "[slardar]", "sibyl_sdk_collector_init_result", "a.init is not a function",
            "deprecatedStyle", "ttap_vmok_load", "detect canceled", "missing key en",
            "[PlayerStart]", "[VideoPrefetch]", "Failed to load resource", "ERR_BLOCKED_BY_CLIENT"
        ]
        if any(phrase in message for phrase in ignore_phrases):
            return

        if message == self._last_msg:
            self._msg_count += 1
            if self._msg_count > 3: return
        else:
            self._last_msg = message
            self._msg_count = 0

        clean_source = sourceID.split('/')[-1].split('?')[0] if '/' in sourceID else sourceID
        if not clean_source: clean_source = "Inline"

        level_name = "INFO"
        if level == QWebEnginePage.JavaScriptConsoleMessageLevel.WarningMessageLevel: level_name = "WARNING"
        elif level == QWebEnginePage.JavaScriptConsoleMessageLevel.ErrorMessageLevel: level_name = "ERROR"

        lower_msg = message.lower()

        if "webmssdk.js" in sourceID and message == "Error":
            return

        if any(sig in lower_msg for sig in ['cloudflare', 'turnstile', 'datadome', 'perimeterx', 'captcha', 'challenge-error', 'recaptcha']):
            log_msg = f"[SHIELD_ALERT] [ERROR] Anti-Bot Challenge Triggered: {clean_source}:{lineNumber} -> {message}"
        elif "[web_sec]" in lower_msg:
            log_msg = f"[SHIELD_ALERT] {message.replace('[WEB_SEC] ', '').replace('[web_sec] ', '')}"
        elif "cors policy" in lower_msg:
            log_msg = f"{self.log_prefix} [WARNING] Blocked cross-origin request in {clean_source} (CORS)"
        else:
            log_msg = f"{self.log_prefix} [{level_name}] [{clean_source}:{lineNumber}] {message}"

        if 'GUI_EMITTER' in globals() and GUI_EMITTER:
            GUI_EMITTER.log_signal.emit(f"[EMBEDDED] {log_msg}")
        else:
            console_log(f"[EMBEDDED] {log_msg}")

class WebEngineHeaderInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self):
        super().__init__()
        self._cached_settings = get_app_settings()
        self._last_settings_update = time.time()

    def _get_settings(self):
        # Refresh settings from disk every 5 seconds to catch UI toggles without freezing the browser
        if time.time() - self._last_settings_update > 5.0:
            self._cached_settings = get_app_settings()
            self._last_settings_update = time.time()
        return self._cached_settings

    def interceptRequest(self, info):
        url = info.requestUrl()
        scheme = url.scheme().encode('utf-8').lower()
        host = url.host().encode('utf-8').lower()

        port = url.port()
        if port == -1:
            port = 443 if scheme in [b"https", b"wss"] else (80 if scheme in [b"http", b"ws"] else "N/A")

        if scheme not in [b"http", b"https", b"ws", b"wss", b"blob", b"data"]:
            info.block(True)
            if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                scheme_str = scheme.decode('utf-8', errors='ignore').upper()
                GUI_EMITTER.log_signal.emit(f"[EMBEDDED] [SHIELD_ALERT] 🛑 FIREWALL BLOCK | Service: {scheme_str} | Target: UNTRUSTED_PROTOCOL | Port: {port} | Details: Hard-Blocked non-standard web protocol | URL: {url.toString()}")
            return

        if scheme in [b"http", b"https", b"ws", b"wss"]:
            host_str = host.decode('utf-8', errors='ignore')
            if host_str:
                is_safe = AIFirewall.check_domain(host_str)
                if not is_safe:
                    info.block(True)
                    if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                        scheme_str = scheme.decode('utf-8', errors='ignore').upper()
                        GUI_EMITTER.log_signal.emit(f"[EMBEDDED] [SHIELD_ALERT] 🤖 AI-GATED SHIELD | Service: {scheme_str} | Target: {host_str} | Port: {port} | Details: Blocked by AI Gatekeeper | URL: {url.toString()}")
                    return

                # --- PASSIVE TELEMETRY LOGGING (UNDETECTED) ---
                if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                    settings = self._get_settings()

                    is_tiktok = any(d in host_str for d in ["tiktok", "byteoversea", "ttwstatic", "tiktokv", "tiktokcdn"])
                    is_x = any(d in host_str for d in ["x.com", "twitter", "twimg"])
                    is_fb = any(d in host_str for d in ["facebook.com", "fbcdn"])
                    is_ig = any(d in host_str for d in ["instagram.com", "cdninstagram"])
                    is_fox = any(d in host_str for d in ["foxnews.com", "foxbusiness.com"])

                    # Always log passively via CDP
                    if True:
                        method = info.requestMethod().data().decode('utf-8')
                        url_str = url.toString()

                        # Filter out static assets so UI logs aren't spammed with images/js
                        if method != "GET" or not any(ext in url_str.lower() for ext in ['.png', '.jpg', '.jpeg', '.webp', '.css', '.woff', '.woff2', '.js', '.chunk']):
                            log_tag = "[PASSIVE_TELEMETRY]"
                            if is_tiktok: log_tag = "[TIKTOK_LOG]"
                            elif is_x: log_tag = "[X_LOG]"
                            elif is_fb: log_tag = "[FB_LOG]"
                            elif is_ig: log_tag = "[INSTAGRAM_LOG]"
                            elif is_fox: log_tag = "[FOXWEB_LOG]"

                            desc = "👁️ <b>Passive Browser Telemetry:</b> Captured locally via DevTools Protocol."
                            log_html = f"<div style='margin-bottom: 8px;'><span style='color: #9CA3AF; font-weight: bold;'>{log_tag}</span> <span style='color: #A78BFA; font-weight: bold;'>[BROWSER REQUEST]</span><br><span style='color: #E2E8F0; font-size: 14px;'><i>{desc}</i></span><br><a href='{url_str}' style='color: #10B981; text-decoration: none;'>{url_str}</a><br>&nbsp;&nbsp;<span style='color: #93C5FD;'>Method:</span> <span style='color: #D1D5DB;'>{method}</span><br><span style='color: #4B5563;'>{'-'*50}</span></div>"
                            GUI_EMITTER.log_signal.emit(f"[EMBEDDED] {log_html}")

class EmbeddedPlayerApp(QMainWindow):

    def __init__(self, log_emitter):
        super().__init__()
        global GUI_EMITTER
        GUI_EMITTER = log_emitter
        # Force NoProxy so QWebEngineView connects natively directly to the web
        no_proxy = QNetworkProxy(QNetworkProxy.ProxyType.NoProxy)
        QNetworkProxy.setApplicationProxy(no_proxy)

        self.targets_data = get_targets_data()
        self.app_settings = get_app_settings()
        self.clips = []
        self.setWindowTitle("Multi-Target Media Monitor (curl_cffi & Dual-AI)")
        self.loaded_tabs = {1: False, 2: False, 3: False, 4: False, 5: False, 6: False}
        self.settings = QSettings("MediaMonitor", "AppConfig")

        if saved := self.settings.value("geometry"): self.restoreGeometry(saved)
        else: self.resize(1600, 900)

        self.load_history()
        log_emitter.log_signal.connect(self.append_log_message)
        self.init_ui()

        if hasattr(self, '_early_logs'):
            for msg, is_html, is_embed in self._early_logs: self.append_log_message(msg, is_html, is_embed)
            self._early_logs.clear()

        loaded_from_file = set()
        boot_log_path = os.path.abspath("mm_boot.log")
        if os.path.exists(boot_log_path):
            try:
                with open(boot_log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        clean_line = line.strip()
                        if clean_line:
                            self.append_log_message(clean_line)
                            loaded_from_file.add(clean_line)
            except Exception: pass

        for early_msg in PRE_GUI_LOGS:
            if early_msg not in loaded_from_file:
                self.append_log_message(early_msg)
        PRE_GUI_LOGS.clear()

        self._tiktok_fallback_timer = None
        self._tiktok_fetching_active = False
        self._current_tk_target_user = None
        self.tk_offset = 0
        self.comment_worker = None

        self.ai_diagnostics = AIErrorDiagnosticWorker(self)
        self.ai_diagnostics.diagnostic_ready.connect(lambda msg: self.append_log_message(msg, is_html=True))
        log_emitter.error_signal.connect(self.ai_diagnostics.add_error)

        self.cdp_worker = CDPInterceptorWorker(port=CDP_DEBUG_PORT, parent=self)
        self.cdp_worker.log_signal.connect(lambda msg, is_embed: self.append_log_message(msg, is_html=True, is_embedded=is_embed))

        self.scanner_thread = None
        self.downloader_thread = None

        self.memory_watchdog = QTimer(self)
        self.memory_watchdog.timeout.connect(self.check_memory_pressure)
        self.memory_watchdog.start(60000)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.trigger_background_scan)

        QTimer.singleShot(500, self.ai_diagnostics.start)
        QTimer.singleShot(800, self.cdp_worker.start)
        QTimer.singleShot(1500, self.check_and_download_model)

    def init_ui(self):
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(self.main_splitter)

        base_cache_dir = os.path.expanduser("~/.cache/MediaMonitor")
        main_cache_dir = os.path.join(base_cache_dir, "mm_main_persistent")
        os.makedirs(main_cache_dir, exist_ok=True)

        self.main_profile = QWebEngineProfile("Main_Persistent", self)
        self.main_profile.setCachePath(main_cache_dir)
        self.main_profile.setPersistentStoragePath(main_cache_dir)
        self.main_profile.setHttpUserAgent(USER_AGENT)
        self.main_profile.setHttpAcceptLanguage("en-US,en;q=0.9")
        self.main_profile.setHttpCacheMaximumSize(100 * 1024 * 1024)

        self.header_interceptor = WebEngineHeaderInterceptor()

        default_profile = QWebEngineProfile.defaultProfile()
        default_profile.setUrlRequestInterceptor(self.header_interceptor)
        default_profile.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        default_profile.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)

        self.main_profile.setUrlRequestInterceptor(self.header_interceptor)
        self.main_profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)

        settings = self.main_profile.settings()
        for attr in [QWebEngineSettings.WebAttribute.LocalStorageEnabled, QWebEngineSettings.WebAttribute.PluginsEnabled, QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows]:
            settings.setAttribute(attr, True)

        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)

        self.left_widget = QWidget()
        left_layout = QVBoxLayout(self.left_widget)
        left_layout.setContentsMargins(5, 5, 5, 5)

        header_layout = QHBoxLayout()
        self.network_header = QLabel("<b><span style='color: #22C55E;'>⬤</span> Network & YT Clips:</b>")
        header_layout.addWidget(self.network_header)

        self.clear_cache_btn = QPushButton("🗑️ Clear Cache")
        self.clear_cache_btn.setStyleSheet("QPushButton { background-color: #EF4444; color: #FFFFFF; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; } QPushButton:hover { background-color: #DC2626; }")
        self.clear_cache_btn.clicked.connect(self.clear_cache_history)
        header_layout.addWidget(self.clear_cache_btn)

        header_layout.addStretch()
        left_layout.addLayout(header_layout)

        search_layout = QHBoxLayout()
        self.network_search_input = QLineEdit()
        self.network_search_input.setPlaceholderText("🔍 Search/Filter Network Videos...")
        self.network_search_input.setStyleSheet("QLineEdit { background-color: #1F2937; color: #FFFFFF; border: 1px solid #374151; border-radius: 4px; padding: 6px; font-size: 13px; }")
        self.network_search_input.textChanged.connect(self.filter_network_list)

        self.network_search_btn = QPushButton("Deep Scan Web")
        self.network_search_btn.setStyleSheet("QPushButton { background-color: #2563EB; color: #FFFFFF; padding: 6px 12px; border-radius: 4px; font-weight: bold; font-size: 11px; } QPushButton:hover { background-color: #1D4ED8; }")
        self.network_search_btn.clicked.connect(self.run_deep_search)

        search_layout.addWidget(self.network_search_input)
        search_layout.addWidget(self.network_search_btn)
        left_layout.addLayout(search_layout)

        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setRange(0, 100)
        self.scan_progress_bar.setValue(0)
        self.scan_progress_bar.setTextVisible(True)
        self.scan_progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_progress_bar.setFixedHeight(18)

        self.scan_status_label = QLabel("Status: Idle")
        self.scan_status_label.setStyleSheet("color: #9CA3AF; font-size: 11px; font-weight: bold;")

        left_layout.addWidget(self.scan_progress_bar)
        left_layout.addWidget(self.scan_status_label)

        self.network_tabs = ColorTabWidget()
        self.network_lists = {}
        self.rebuild_network_tabs()
        left_layout.addWidget(self.network_tabs)

        self.center_container = QWidget()
        center_container_layout = QVBoxLayout(self.center_container)
        center_container_layout.setContentsMargins(0, 0, 0, 0)

        nav_bar_layout = QHBoxLayout()
        self.url_label = QLabel("🌐 <b>Target URL:</b>")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Paste URL here...")
        self.url_input.setStyleSheet("QLineEdit { background-color: #1F2937; color: #FFFFFF; border: 1px solid #374151; border-radius: 4px; padding: 6px; font-size: 13px; }")
        self.url_input.returnPressed.connect(self.navigate_url_bar)

        self.url_go_btn = QPushButton("Go")
        self.url_go_btn.setStyleSheet("QPushButton { background-color: #2563EB; color: #FFFFFF; font-weight: bold; padding: 6px 12px; border-radius: 4px; } QPushButton:hover { background-color: #1D4ED8; }")
        self.url_go_btn.clicked.connect(self.navigate_url_bar)

        nav_bar_layout.addWidget(self.url_label)
        nav_bar_layout.addWidget(self.url_input)
        nav_bar_layout.addWidget(self.url_go_btn)

        center_container_layout.addLayout(nav_bar_layout)
        self.center_tabs = ColorTabWidget()

        self.native_video_widget = QWidget()
        nv_layout = QVBoxLayout(self.native_video_widget)
        nv_layout.setContentsMargins(0, 0, 0, 0)
        nv_layout.setSpacing(0)

        self.web_nav_layout = QHBoxLayout()
        nv_layout.addLayout(self.web_nav_layout)

        self.video_output = self.create_logging_webview(self.main_profile, "[WEB_LOG]")
        self.video_output.settings().setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)

        def enforce_autoplay(ok):
            if ok:
                js_autoplay = """
                let ap_attempts = 0;
                const ap_interval = setInterval(() => {
                    ap_attempts++;
                    if (ap_attempts > 5) {
                        clearInterval(ap_interval);
                        return;
                    }
                    const playBtns = document.querySelectorAll('.vjs-big-play-button, .play-button, [aria-label="Play"], .playBtn');
                    playBtns.forEach(btn => {
                        if (btn && btn.click) btn.click();
                    });
                    const vids = document.querySelectorAll('video');
                    vids.forEach(v => {
                        if (v.paused) v.play().catch(e => {});
                    });
                }, 1500);
                """
                self.video_output.page().runJavaScript(js_autoplay)

        self.video_output.loadFinished.connect(enforce_autoplay)
        nv_layout.addWidget(self.video_output, stretch=1)

        self.center_tabs.addTab(self.native_video_widget, "🌐 Web")

        x_tab = QWidget()
        x_layout = QVBoxLayout(x_tab)
        self.x_nav_layout = QHBoxLayout()
        self.x_web_view = self.create_logging_webview(self.main_profile, "[X_LOG]")
        x_layout.addLayout(self.x_nav_layout)
        x_layout.addWidget(self.x_web_view)
        self.center_tabs.addTab(x_tab, "🐦 X (Twitter)")

        fb_tab = QWidget()
        fb_layout = QVBoxLayout(fb_tab)
        self.fb_nav_layout = QHBoxLayout()
        self.fb_web_view = self.create_logging_webview(self.main_profile, "[FB_LOG]")
        fb_layout.addLayout(self.fb_nav_layout)
        fb_layout.addWidget(self.fb_web_view)
        self.center_tabs.addTab(fb_tab, "📘 Facebook")

        fox_tab = QWidget()
        fox_layout = QVBoxLayout(fox_tab)
        self.fox_nav_layout = QHBoxLayout()
        self.fox_web_view = self.create_logging_webview(self.main_profile, "[FOXWEB_LOG]")
        fox_layout.addLayout(self.fox_nav_layout)
        fox_layout.addWidget(self.fox_web_view)
        self.center_tabs.addTab(fox_tab, "🦊 Fox Profiles")

        tiktok_cache_dir = os.path.join(base_cache_dir, "mm_tk_persistent")
        os.makedirs(tiktok_cache_dir, exist_ok=True)
        self.tiktok_profile = QWebEngineProfile("TikTok_Persistent", self.center_tabs)
        self.tiktok_profile.setCachePath(tiktok_cache_dir)
        self.tiktok_profile.setPersistentStoragePath(tiktok_cache_dir)
        self.tiktok_profile.setHttpUserAgent(USER_AGENT)
        self.tiktok_profile.setHttpAcceptLanguage("en-US,en;q=0.9,es;q=0.8")
        self.tiktok_profile.setHttpCacheMaximumSize(50 * 1024 * 1024)

        self.tiktok_profile.setUrlRequestInterceptor(self.header_interceptor)

        settings = self.tiktok_profile.settings()
        for attr in [QWebEngineSettings.WebAttribute.LocalStorageEnabled, QWebEngineSettings.WebAttribute.JavascriptEnabled, QWebEngineSettings.WebAttribute.PluginsEnabled]:
            settings.setAttribute(attr, True)

        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
        self.tiktok_profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)

        tiktok_tab = QWidget()
        tiktok_layout = QVBoxLayout(tiktok_tab)
        self.tiktok_nav_layout = QHBoxLayout()
        self.tiktok_web_view = self.create_logging_webview(self.tiktok_profile, "[TIKTOK_LOG]")

        tiktok_layout.addLayout(self.tiktok_nav_layout)
        tiktok_layout.addWidget(self.tiktok_web_view)
        self.center_tabs.addTab(tiktok_tab, "📱 TikTok")

        ig_tab = QWidget()
        ig_layout = QVBoxLayout(ig_tab)
        self.ig_nav_layout = QHBoxLayout()
        self.ig_web_view = self.create_logging_webview(self.main_profile, "[INSTAGRAM_LOG]")
        ig_layout.addLayout(self.ig_nav_layout)
        ig_layout.addWidget(self.ig_web_view)
        self.center_tabs.addTab(ig_tab, "📷 Instagram")

        self.rebuild_all_platform_bars()

        self.settings_tab = QWidget()
        self.build_settings_tab()
        self.center_tabs.addTab(self.settings_tab, "⚙️ Settings")

        self.center_tabs.currentChanged.connect(self.on_center_tab_changed)
        center_container_layout.addWidget(self.center_tabs)

        self.right_pane = QWidget()
        right_layout = QVBoxLayout(self.right_pane)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        copy_logs_btn = QPushButton("📋 Copy All Logs")
        copy_logs_btn.setStyleSheet("QPushButton { background-color: #2563EB; color: white; font-weight: bold; border-radius: 4px; padding: 10px; font-size: 13px; margin: 4px; } QPushButton:hover { background-color: #1D4ED8; }")
        copy_logs_btn.clicked.connect(self.copy_all_logs)
        right_layout.addWidget(copy_logs_btn)

        log_controls_layout = QHBoxLayout()
        log_controls_layout.setContentsMargins(4, 0, 4, 4)

        self.clear_log_btn = QPushButton("🗑️ Clear Tab")
        self.clear_log_btn.setStyleSheet("QPushButton { background-color: #2563EB; color: white; font-weight: bold; border-radius: 4px; padding: 6px; } QPushButton:hover { background-color: #DC2626; }")
        self.clear_log_btn.clicked.connect(self.clear_current_log)

        self.wrap_log_cb = QCheckBox("Truncate Lines (Wrap)")
        self.wrap_log_cb.setStyleSheet("color: white; font-weight: bold;")
        self.wrap_log_cb.stateChanged.connect(self.toggle_log_wrap)

        self.disable_biometrics_cb = QCheckBox("Disable Biometrics JS")
        self.disable_biometrics_cb.setStyleSheet("color: #F87171; font-weight: bold;")
        self.disable_biometrics_cb.setChecked(self.app_settings.get("disable_biometrics", False))
        self.disable_biometrics_cb.stateChanged.connect(self.toggle_biometrics)
        self.disable_biometrics_cb.hide()

        log_controls_layout.addWidget(self.clear_log_btn)
        log_controls_layout.addWidget(self.wrap_log_cb)
        log_controls_layout.addWidget(self.disable_biometrics_cb)
        right_layout.addLayout(log_controls_layout)

        self.log_tab_grid = QGridLayout()
        self.log_tab_grid.setSpacing(3)
        self.log_tab_grid.setContentsMargins(4, 4, 4, 4)
        grid_container = QWidget()
        grid_container.setLayout(self.log_tab_grid)
        grid_container.setStyleSheet("background-color: #111827;")
        right_layout.addWidget(grid_container)

        self.subnav_container = QWidget()
        self.subnav_container.setStyleSheet("background-color: #1F2937; border-top: 1px solid #374151; border-bottom: 2px solid #374151;")
        subnav_layout = QHBoxLayout(self.subnav_container)
        subnav_layout.setContentsMargins(4, 4, 4, 4)
        subnav_layout.setSpacing(4)

        self.btn_view_embedded = QPushButton("🌐 Primary")
        self.btn_view_embedded.setCheckable(True)
        self.btn_view_embedded.setChecked(True)
        self.btn_view_embedded.setStyleSheet("QPushButton { background-color: #8B5CF6; color: white; font-weight: bold; padding: 6px; border-radius: 4px; }")
        self.btn_view_embedded.clicked.connect(self.toggle_log_view_mode)

        self.btn_view_main = QPushButton("📄 Secondary")
        self.btn_view_main.setCheckable(True)
        self.btn_view_main.setStyleSheet("QPushButton { background-color: #374151; color: #9CA3AF; font-weight: bold; padding: 6px; border-radius: 4px; border: none; } QPushButton:hover { background-color: #4B5563; color: white; }")
        self.btn_view_main.clicked.connect(self.toggle_log_view_mode)

        self.btn_embed_refresh = QPushButton("🔄")
        self.btn_embed_refresh.setToolTip("Refresh Embedded View")
        self.btn_embed_refresh.setStyleSheet("QPushButton { background-color: #374151; color: white; padding: 6px; border-radius: 4px; } QPushButton:hover { background-color: #2563EB; }")
        self.btn_embed_refresh.clicked.connect(lambda: self.trigger_embedded_browser_action("refresh"))

        self.btn_embed_clear = QPushButton("🧹")
        self.btn_embed_clear.setToolTip("Clear Cache & Reload Embedded View")
        self.btn_embed_clear.setStyleSheet("QPushButton { background-color: #374151; color: white; padding: 6px; border-radius: 4px; } QPushButton:hover { background-color: #EF4444; }")
        self.btn_embed_clear.clicked.connect(lambda: self.trigger_embedded_browser_action("clear"))

        self.btn_embed_stop = QPushButton("🛑")
        self.btn_embed_stop.setToolTip("Stop Loading Embedded View")
        self.btn_embed_stop.setStyleSheet("QPushButton { background-color: #374151; color: white; padding: 6px; border-radius: 4px; } QPushButton:hover { background-color: #DC2626; }")
        self.btn_embed_stop.clicked.connect(lambda: self.trigger_embedded_browser_action("stop"))

        subnav_layout.addWidget(self.btn_view_embedded)
        subnav_layout.addWidget(self.btn_view_main)
        subnav_layout.addStretch()
        subnav_layout.addWidget(self.btn_embed_refresh)
        subnav_layout.addWidget(self.btn_embed_clear)
        subnav_layout.addWidget(self.btn_embed_stop)

        right_layout.addWidget(self.subnav_container)

        self.master_log_stack = QStackedWidget()
        self.log_stack = QStackedWidget()
        self.embedded_log_stack = QStackedWidget()

        self.log_consoles = {}
        self.embedded_consoles = {}
        self.log_buttons = []
        self.log_tab_keys = []

        log_tabs_data = [
            ("Web", "Web"),
            ("Unsorted", "Unsorted Traffic"),
            ("System", "General"),
            ("X.com", "X.com"),
            ("Facebook", "Facebook"),
            ("Fox Web", "Fox Web"),
            ("TikTok", "TikTok"),
            ("Instagram", "Instagram"),
            ("WebMSSDK", "WebMSSDK"),
            ("Shield", "Web_Security"),
            ("AI Found", "AI Found"),
            ("AI Logs", "AI Logs")
        ]

        for idx, (tab_name, key) in enumerate(log_tabs_data):
            self.log_tab_keys.append(key)

            btn = QPushButton(tab_name)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=idx: self.switch_log_tab(i))
            self.log_buttons.append(btn)

            row = idx // 8
            col = idx % 8
            self.log_tab_grid.addWidget(btn, row, col)

            te_main = QPlainTextEdit()
            te_main.setReadOnly(True)
            te_main.setStyleSheet("QPlainTextEdit { background-color: #0D1117; color: #FFFFFF; font-family: monospace; font-size: 14px; border: none; padding: 8px; }")

            te_embed = QPlainTextEdit()
            te_embed.setReadOnly(True)
            te_embed.setStyleSheet("QPlainTextEdit { background-color: #000000; color: #E0E7FF; font-family: monospace; font-size: 14px; border: none; padding: 8px; border-top: 2px solid #8B5CF6; }")

            tab_wrap_states = self.app_settings.get("tab_wrap_states", {})
            is_wrap = tab_wrap_states.get(key, True)

            te_main.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if is_wrap else QPlainTextEdit.LineWrapMode.NoWrap)
            te_main.setMaximumBlockCount(2000)

            te_embed.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if is_wrap else QPlainTextEdit.LineWrapMode.NoWrap)
            te_embed.setMaximumBlockCount(2000)

            self.log_consoles[key] = te_main
            self.embedded_consoles[key] = te_embed

            self.log_stack.addWidget(te_main)
            self.embedded_log_stack.addWidget(te_embed)

        self.master_log_stack.addWidget(self.log_stack)
        self.master_log_stack.addWidget(self.embedded_log_stack)
        right_layout.addWidget(self.master_log_stack)

        self.switch_log_tab(2)  # Index 2 is the System log window

        self.main_splitter.addWidget(self.left_widget)
        self.main_splitter.addWidget(self.center_container)
        self.main_splitter.addWidget(self.right_pane)
        self.main_splitter.setSizes([300, 700, 400])

        self._populate_network_list()

    def clear_login_cache(self):
        reply = QMessageBox.question(
            self, "Confirm Login Cache Clear",
            "Are you sure you want to clear all login caches and cookies? You will need to log back into your accounts (TikTok, X, Facebook, etc.).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                for p in [getattr(self, 'main_profile', None), getattr(self, 'tiktok_profile', None)]:
                    if p:
                        if p.cookieStore():
                            p.cookieStore().deleteAllCookies()
                        p.clearHttpCache()
                        p.clearAllVisitedLinks()

                base_cache_dir = os.path.expanduser("~/.cache/MediaMonitor")
                for d_name in ["mm_main_persistent", "mm_tk_persistent"]:
                    d_path = os.path.join(base_cache_dir, d_name)
                    if os.path.exists(d_path):
                        shutil.rmtree(d_path, ignore_errors=True)
                        os.makedirs(d_path, exist_ok=True)

                for v in [getattr(self, 'video_output', None), getattr(self, 'x_web_view', None),
                          getattr(self, 'fb_web_view', None), getattr(self, 'fox_web_view', None),
                          getattr(self, 'tiktok_web_view', None), getattr(self, 'ig_web_view', None)]:
                    if v: v.reload()

                self.append_log_message("[SYS_LOG] <span style='color: #EF4444;'>[✅] All login caches, persistent storage directories, and cookies have been wiped. Relogin required.</span>", is_html=True, is_embedded=False)
                QMessageBox.information(self, "Login Cache Cleared", "Login caches successfully cleared. Please re-authenticate your accounts.")
            except Exception as e:
                self.append_log_message(f"[SYS_LOG] [ERROR] Failed to clear login cache: {e}", is_embedded=False)

    def refresh_domains_whitelist(self):
        load_or_download_domains(force_refresh=True)
        self.append_log_message("[SYS_LOG] [✅] Top domains whitelist re-downloaded and cache file updated successfully.", is_embedded=False)

    def rebuild_network_tabs(self):
        self.network_tabs.clear()
        self.network_lists = {}
        for t in self.targets_data:
            name = t["name"]
            tree_widget = QTreeWidget()
            tree_widget.setHeaderHidden(True)
            tree_widget.setStyleSheet("QTreeWidget { background-color: #121212; border: none; outline: none; } QTreeWidget::item { border-bottom: 1px solid #333333; } QTreeWidget::item:selected { background-color: #374151; }")
            tree_widget.itemClicked.connect(self.on_tree_item_clicked)
            self.network_lists[name] = tree_widget
            self.network_tabs.addTab(tree_widget, name.split()[0])
        self._populate_network_list()

    def build_nav_bar_for_platform(self, nav_layout, web_view, key_user):
        while nav_layout.count() > 0:
            item = nav_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        btn_style = "QPushButton { background-color: #333333; color: #FFFFFF; padding: 6px 10px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #444444; }"
        target_btn_style = "QPushButton { background-color: #2563EB; color: #FFFFFF; padding: 6px 12px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #1D4ED8; }"

        back_btn = QPushButton("◀ Back")
        fwd_btn = QPushButton("Forward ▶")
        refresh_btn = QPushButton("🔄 Refresh")
        back_btn.setStyleSheet(btn_style)
        fwd_btn.setStyleSheet(btn_style)
        refresh_btn.setStyleSheet(btn_style)
        back_btn.clicked.connect(web_view.back)
        fwd_btn.clicked.connect(web_view.forward)
        refresh_btn.clicked.connect(web_view.reload)

        nav_layout.addWidget(back_btn)
        nav_layout.addWidget(fwd_btn)
        nav_layout.addWidget(refresh_btn)

        for t in self.targets_data:
            name = t["name"]
            url = ""
            if key_user == "profile_url":
                p_url = t.get("profile_url", "").strip()
                if p_url: url = p_url
            else:
                user_handle = clean_handle(t.get(key_user, ""), key_user.split("_")[0])
                if user_handle:
                    if key_user == "x_user": url = f"https://x.com/{user_handle}"
                    elif key_user == "facebook_user": url = f"https://www.facebook.com/{user_handle}"
                    elif key_user == "tiktok_user": url = f"https://www.tiktok.com/@{user_handle}"
                    elif key_user == "instagram_user": url = f"https://www.instagram.com/{user_handle}"

            if not url: continue

            btn = QPushButton(name)
            btn.setStyleSheet(target_btn_style)
            btn.clicked.connect(lambda checked, u=url, wv=web_view: self.load_platform_url(wv, u))
            nav_layout.addWidget(btn)

        nav_layout.addStretch()

    def load_platform_url(self, web_view, url):
        self.url_input.setText(url)
        platform_tag = "Network"
        url_lower = url.lower()
        if "x.com" in url_lower or "twitter.com" in url_lower: platform_tag = "X.com"
        elif "facebook.com" in url_lower: platform_tag = "Facebook"
        elif "tiktok.com" in url_lower: platform_tag = "TikTok"
        elif "instagram.com" in url_lower: platform_tag = "Instagram"
        elif "foxnews.com" in url_lower or "foxbusiness.com" in url_lower: platform_tag = "Fox Web"

        if GUI_EMITTER:
            GUI_EMITTER.log_signal.emit(f"[{platform_tag}] 🚀 Loading URL in Native WebEngine: {url}")

        web_view.load(QUrl(url))

    def rebuild_all_platform_bars(self):
        self.build_nav_bar_for_platform(self.web_nav_layout, self.video_output, "profile_url")
        self.build_nav_bar_for_platform(self.x_nav_layout, self.x_web_view, "x_user")
        self.build_nav_bar_for_platform(self.fb_nav_layout, self.fb_web_view, "facebook_user")
        self.build_nav_bar_for_platform(self.tiktok_nav_layout, self.tiktok_web_view, "tiktok_user")
        self.build_nav_bar_for_platform(self.ig_nav_layout, self.ig_web_view, "instagram_user")
        self.build_nav_bar_for_platform(self.fox_nav_layout, self.fox_web_view, "profile_url")

    def fetch_tiktok_comments(self, video_url):
        if self.comment_worker and self.comment_worker.isRunning():
            self.comment_worker.quit()
        self.comment_worker = TikTokCommentWorker(video_url)
        self.comment_worker.comments_ready.connect(self.on_tiktok_comments_ready)
        self.comment_worker.start()

    def on_tiktok_comments_ready(self, json_str):
        script = f"if (typeof window.renderTikTokComments === 'function') {{ window.renderTikTokComments({json_str}); }}"
        self.tiktok_web_view.page().runJavaScript(script)

    def load_more_tiktok_videos(self):
        if not self._current_tk_target_user: return
        self.tk_offset += 40
        self.run_tiktok_ytdlp_worker(self._current_tk_target_user, f"https://www.tiktok.com/@{self._current_tk_target_user}", is_append=True)

    def switch_log_tab(self, index):
        for i, btn in enumerate(self.log_buttons):
            if i == index:
                btn.setChecked(True)
                btn.setStyleSheet("QPushButton { background-color: #2563EB; color: #FFFFFF; font-weight: bold; border: 2px solid #60A5FA; border-radius: 4px; padding: 6px; font-size: 12px; }")
            else:
                btn.setChecked(False)
                btn.setStyleSheet("QPushButton { background-color: #374151; color: #F3F4F6; font-weight: bold; border: 1px solid #4B5563; border-radius: 4px; padding: 6px; font-size: 12px; } QPushButton:hover { background-color: #4B5563; color: #FFFFFF; }")

        self.master_log_stack.setCurrentIndex(0 if self.btn_view_main.isChecked() else 1)
        self.log_stack.setCurrentIndex(index)
        self.embedded_log_stack.setCurrentIndex(index)

        if hasattr(self, 'log_tab_keys') and index < len(self.log_tab_keys):
            current_key = self.log_tab_keys[index]
            tab_wrap_states = self.app_settings.get("tab_wrap_states", {})
            is_wrap = tab_wrap_states.get(current_key, True)

            if hasattr(self, 'wrap_log_cb'):
                self.wrap_log_cb.blockSignals(True)
                self.wrap_log_cb.setChecked(is_wrap)
                self.wrap_log_cb.blockSignals(False)

            if hasattr(self, 'disable_biometrics_cb'):
                if current_key == "Web_Security":
                    self.disable_biometrics_cb.show()
                else:
                    self.disable_biometrics_cb.hide()

    def set_log_view_mode(self, is_embedded: bool):
        if is_embedded:
            self.btn_view_embedded.setChecked(True)
            self.btn_view_main.setChecked(False)
            self.btn_view_embedded.setStyleSheet("QPushButton { background-color: #8B5CF6; color: white; font-weight: bold; padding: 6px; border-radius: 4px; }")
            self.btn_view_main.setStyleSheet("QPushButton { background-color: #374151; color: #9CA3AF; font-weight: bold; padding: 6px; border-radius: 4px; border: none; } QPushButton:hover { background-color: #4B5563; color: white; }")
            self.master_log_stack.setCurrentIndex(1)
        else:
            self.btn_view_main.setChecked(True)
            self.btn_view_embedded.setChecked(False)
            self.btn_view_main.setStyleSheet("QPushButton { background-color: #2563EB; color: white; font-weight: bold; padding: 6px; border-radius: 4px; border: 1px solid #60A5FA; }")
            self.btn_view_embedded.setStyleSheet("QPushButton { background-color: #374151; color: #9CA3AF; font-weight: bold; padding: 6px; border-radius: 4px; border: none; } QPushButton:hover { background-color: #4B5563; color: white; }")
            self.master_log_stack.setCurrentIndex(0)

    def toggle_log_view_mode(self):
        if self.sender() == self.btn_view_main:
            self.set_log_view_mode(False)
        else:
            self.set_log_view_mode(True)

    def clear_current_log(self):
        current_idx = self.log_stack.currentIndex()
        if self.master_log_stack.currentIndex() == 0:
            current_widget = self.log_stack.widget(current_idx)
        else:
            current_widget = self.embedded_log_stack.widget(current_idx)

        if isinstance(current_widget, QPlainTextEdit):
            current_widget.clear()

    def toggle_log_wrap(self, state):
        current_idx = self.log_stack.currentIndex()
        if current_idx < 0 or not hasattr(self, 'log_tab_keys'): return

        current_key = self.log_tab_keys[current_idx]
        is_wrap = bool(state)

        tab_wrap_states = self.app_settings.get("tab_wrap_states", {})
        tab_wrap_states[current_key] = is_wrap
        self.app_settings["tab_wrap_states"] = tab_wrap_states
        save_app_settings(self.app_settings)

        for stack in [self.log_stack, self.embedded_log_stack]:
            current_widget = stack.widget(current_idx)
            if isinstance(current_widget, QPlainTextEdit):
                current_widget.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if is_wrap else QPlainTextEdit.LineWrapMode.NoWrap)

    def toggle_biometrics(self, state):
        self.app_settings["disable_biometrics"] = bool(state)
        save_app_settings(self.app_settings)
        self.append_log_message("[SYS_LOG] <span style='color: #F87171;'>Biometrics setting saved. Takes effect on next app restart or new tab load.</span>", is_html=True)

    def trigger_embedded_browser_action(self, action):
        current_idx = self.center_tabs.currentIndex()
        views = {0: self.video_output, 1: self.x_web_view, 2: self.fb_web_view, 3: self.fox_web_view, 4: self.tiktok_web_view, 5: self.ig_web_view}
        view = views.get(current_idx)

        if not view:
            self.append_log_message("[EMBEDDED] [SYS_LOG] Open a social or news tab to use browser actions.")
            return

        if action == "refresh":
            view.reload()
            self.append_log_message(f"[EMBEDDED] [SYS_LOG] Refreshing embedded view {view.url().toString()}...")
        elif action == "clear":
            view.page().profile().clearHttpCache()
            view.reload()
            self.append_log_message(f"[EMBEDDED] [SYS_LOG] Cleared cache and hard-reloading embedded view...")
        elif action == "source":
            view.page().toHtml(lambda html: self.append_log_message(
                f"[EMBEDDED] <span style='color:#60A5FA;'><b>[Page Source Snippet]</b> Length: {len(html)} chars.</span><br>"
                f"<span style='color:#9CA3AF;'>{html[:1000].replace('<','&lt;').replace('>','&gt;')}...</span>", True
            ))
        elif action == "stop":
            view.stop()
            self.append_log_message(f"[EMBEDDED] [SYS_LOG] Stopped loading on embedded view.")

    def check_memory_pressure(self):
        try:
            process = psutil.Process(os.getpid())
            mem_mb = process.memory_info().rss / (1024 * 1024)
            if mem_mb > 4000:
                self.append_log_message(f"<span style='color: #EF4444; font-weight:bold;'>[WATCHDOG] Memory high ({mem_mb:.0f}MB)! Clearing cache without unloading tabs to preserve feed state.</span>", is_html=True)
                for p in [getattr(self, 'main_profile', None), getattr(self, 'tiktok_profile', None)]:
                    if p: p.clearHttpCache()
        except Exception as e: console_log(f"[WATCHDOG] Failed to check memory: {e}")

    def test_llama_manually(self):
        url = "http://127.0.0.1:11434/api/generate"
        payload = {"model": "llama3.2", "prompt": "This is a brief system check. Reply 'LLAMA ONLINE' and nothing else.", "stream": False, "options": {"temperature": 0.0}}
        try:
            self.append_log_message("[AI Logs] Checking Llama engine status...")
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                self.append_log_message(f"<span style='color: #10B981; font-size: 15px;'>[✅] Llama Response Received:</span><br>{response.json().get('response', '')}", is_html=True)
            elif response.status_code == 404:
                self.append_log_message(f"<span style='color: #EF4444; font-size: 15px;'>[❌] [ERROR] Llama HTTP Error: 404. Re-pulling...</span>", is_html=True)
                subprocess.Popen(["ollama", "pull", "llama3.2"])
            else:
                self.append_log_message(f"<span style='color: #EF4444; font-size: 15px;'>[❌] [ERROR] Llama HTTP Error: {response.status_code}</span>", is_html=True)
        except Exception as e:
            self.append_log_message(f"<span style='color: #EF4444; font-size: 15px;'>[❌] [ERROR] Llama Connection Failed: {e}</span>", is_html=True)

    def check_and_download_model(self):
        self.scan_progress_bar.setStyleSheet("QProgressBar { border: 1px solid #374151; border-radius: 4px; background-color: #1F2937; color: white; font-weight: bold; } QProgressBar::chunk { background-color: #F59E0B; border-radius: 3px; }")
        self.downloader_thread = OllamaModelManager()
        self.downloader_thread.progress_update.connect(self.update_progress_ui)
        self.downloader_thread.download_complete.connect(self.on_download_complete)
        self.downloader_thread.log_msg.connect(self.append_log_message)
        self.downloader_thread.start()

    def on_download_complete(self):
        self.scan_progress_bar.setStyleSheet("QProgressBar { border: 1px solid #374151; border-radius: 4px; background-color: #1F2937; color: white; font-weight: bold; } QProgressBar::chunk { background-color: #3B82F6; border-radius: 3px; }")
        self.test_llama_manually()
        self.refresh_timer.start(1800000)
        self.trigger_background_scan()

    def update_progress_ui(self, value, text):
        self.scan_progress_bar.setValue(value)
        self.scan_status_label.setText(f"Status: {text}")

    def clear_cache_history(self):
        self.clips = []
        if os.path.exists(HISTORY_FILE):
            try: os.remove(HISTORY_FILE)
            except Exception: pass
        self._populate_network_list()
        self.network_header.setText("<b><span style='color: #EF4444;'>❌</span> Network & YT Clips: (Cache Cleared)</b>")
        self.append_log_message("[SYS_LOG] <span style='color: #10B981;'>[✅] Media history and network clips cache cleared. Login sessions preserved.</span>", is_html=True, is_embedded=False)

    def reset_tiktok_session(self):
        """Rotates TikTok device fingerprint and clears session cookies to instantly bypass rate limits."""
        if hasattr(self, 'tiktok_profile') and self.tiktok_profile:
            self.tiktok_profile.cookieStore().deleteAllCookies()
            self.tiktok_profile.clearHttpCache()
            self.append_log_message("[TikTok] [SYS_LOG] 🔄 Rotating TikTok device session & cookies to bypass rate limit...", is_embedded=True)
            self.tiktok_web_view.reload()

        for tree_widget in self.network_lists.values():
            tree_widget.clear()
        self.network_header.setText("<b><span style='color: #EF4444;'>❌</span> Network & YT Clips: (Cache Cleared)</b>")

        if hasattr(self, 'main_profile') and self.main_profile.cookieStore():
            self.main_profile.cookieStore().deleteAllCookies()
        if hasattr(self, 'tiktok_profile') and self.tiktok_profile.cookieStore():
            self.tiktok_profile.cookieStore().deleteAllCookies()

        clear_script = """
        (function() {
            try {
                localStorage.clear();
                sessionStorage.clear();
                if (window.indexedDB && window.indexedDB.databases) {
                    window.indexedDB.databases().then(r => {
                        r.forEach(db => window.indexedDB.deleteDatabase(db.name));
                    });
                }
                console.log('[WEB_SEC] Full storage wipe completed.');
            } catch(e) {}
        })();
        """
        views = [getattr(self, 'x_web_view', None), getattr(self, 'fb_web_view', None),
                 getattr(self, 'fox_web_view', None), getattr(self, 'tiktok_web_view', None),
                 getattr(self, 'ig_web_view', None)]
        for v in views:
            if v and v.page(): v.page().runJavaScript(clear_script)
        for p in [getattr(self, 'main_profile', None), getattr(self, 'tiktok_profile', None)]:
            if p:
                p.clearHttpCache()
                p.clearAllVisitedLinks()
        self.append_log_message("[SYS_LOG] <span style='color: #10B981;'>[✅] Storage wiped and caches cleared.</span>", is_html=True, is_embedded=False)

    def copy_all_logs(self):
        clipboard = QApplication.clipboard()

        all_logs_text = "=== MULTI-TARGET MEDIA MONITOR FULL LOG DUMP ===\n"
        all_logs_text += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        all_logs_text += "="*60 + "\n"
        all_logs_text += ">>> MAIN APP LOGS <<<\n"
        all_logs_text += "="*60 + "\n\n"

        for name, text_edit in self.log_consoles.items():
            content = text_edit.toPlainText().strip()
            if content:
                all_logs_text += f"--- [MAIN - {name.upper()}] ---\n{content}\n\n"

        all_logs_text += "="*60 + "\n"
        all_logs_text += ">>> Primary <<<\n"
        all_logs_text += "="*60 + "\n\n"

        for name, text_edit in self.embedded_consoles.items():
            content = text_edit.toPlainText().strip()
            if content:
                all_logs_text += f"--- [EMBEDDED - {name.upper()}] ---\n{content}\n\n"

        clipboard.setText(all_logs_text)
        self.append_log_message("<span style='color: #10B981;'>[✅] All active logs successfully copied to clipboard!</span>", is_html=True, is_embedded=False)

    def smart_append(self, text_edit: QPlainTextEdit, message: str, is_html: bool = False):
        v_scrollbar = text_edit.verticalScrollBar()
        was_at_bottom = (v_scrollbar.value() >= v_scrollbar.maximum() - 20)

        if is_html:
            text_edit.appendHtml(message)
        else:
            text_edit.appendPlainText(message)

        if was_at_bottom:
            v_scrollbar.setValue(v_scrollbar.maximum())

    def append_log_message(self, message: str, is_html: bool = False, is_embedded: bool = False):
        if "[EMBEDDED]" in message:
            is_embedded = True
            message = message.replace("[EMBEDDED] ", "").replace("[EMBEDDED]", "")
            message = message.replace("[System/Deps] ", "")

        if "<span" in message or "<div" in message: is_html = True

        if not hasattr(self, 'log_consoles') or not self.log_consoles:
            if not hasattr(self, '_early_logs'): self._early_logs = []
            self._early_logs.append((message, is_html, is_embedded))
            return

        lower_msg = message.lower()

        if "deploying environment masking framework" in lower_msg:
            return

        error_tags = ["[error]", "exception:", "[!]"]
        is_error = any(tag in lower_msg for tag in error_tags) and "[ai auto-diag]" not in lower_msg and "[ai page diagnosis]" not in lower_msg and "🧠" not in lower_msg

        if is_error and hasattr(GUI_EMITTER, 'error_signal'):
            GUI_EMITTER.error_signal.emit(message)

        is_firewall_block = "FIREWALL BLOCK" in message or "AI-GATED SHIELD" in message or "[SHIELD_ALERT]" in message
        is_stealth_fallback = "intercepted network fetch failure, returning fallback mock" in lower_msg
        is_redirect_block = "blocked unauthorized redirect to:" in lower_msg

        if not is_html:
            safe_msg = message.replace('<', '&lt;').replace('>', '&gt;')

            if is_redirect_block:
                safe_msg = safe_msg.replace("[WEB_SEC]", "<span style='background-color: #B45309; color: #FEF3C7; padding: 2px 6px; border-radius: 4px;'><b>⚠️ REDIRECT SHIELD</b></span>")
                safe_msg = safe_msg.replace("[SHIELD_ALERT]", "")
                safe_msg = safe_msg.replace("Blocked unauthorized redirect to:", "<span style='color: #F87171; font-weight: bold;'>Blocked unauthorized navigation redirect to:</span>")
                safe_msg = f"<span style='color: #FCA5A5; line-height: 1.4;'>{safe_msg}</span>"

            elif is_stealth_fallback:
                safe_msg = safe_msg.replace("[SHIELD_ALERT]", "<span style='background-color: #1E3A8A; color: #BFDBFE; padding: 2px 6px; border-radius: 4px;'><b>🛡️ STEALTH SHIELD</b></span>")
                safe_msg = safe_msg.replace("Intercepted network fetch failure, returning fallback mock", "<span style='color: #60A5FA; font-weight: bold;'>Network fetch interception handled via stealth mock fallback</span>")
                safe_msg = f"<span style='color: #93C5FD; line-height: 1.4;'>{safe_msg}</span>"

            elif is_firewall_block:
                safe_msg = safe_msg.replace("| Service:", "| <span style='color: #FBBF24; font-weight: bold;'>Service:</span>")
                safe_msg = safe_msg.replace("| Target:", "| <span style='color: #60A5FA; font-weight: bold;'>Target:</span>")
                safe_msg = safe_msg.replace("| Port:", "| <span style='color: #A78BFA; font-weight: bold;'>Port:</span>")
                safe_msg = safe_msg.replace("| Details:", "| <span style='color: #F87171; font-weight: bold;'>Details:</span>")
                safe_msg = safe_msg.replace("| Method:", "| <span style='color: #34D399; font-weight: bold;'>Method:</span>")
                safe_msg = safe_msg.replace("| Client IP:", "| <span style='color: #2DD4BF; font-weight: bold;'>Client IP:</span>")

                if "| URL:" in safe_msg:
                    parts = safe_msg.split("| URL:")
                    header_part = parts[0].strip()
                    raw_u = parts[1].strip()

                    try:
                        p = urllib.parse.urlparse(raw_u)
                        display_url = raw_u

                        if p.path:
                            path_segments = [s for s in p.path.split('/') if s]
                            if path_segments:
                                filename = path_segments[-1]
                                if any(filename.endswith(ext) for ext in ['.js', '.json', '.png', '.jpg', '.ico', '.m3u8', '.ts', '.xml', '.css', '.html']):
                                    colored_filename = f"<span style='color: #22D3EE; font-weight: bold;'>{filename}</span>"
                                    url_without_query = f"{p.scheme}://{p.netloc}{p.path}"
                                    colored_url_without_query = colored_filename.join(url_without_query.rsplit(filename, 1))

                                    rest = ""
                                    if p.params: rest += f";{p.params}"
                                    if p.query: rest += f"?{p.query}"
                                    if p.fragment: rest += f"#{p.fragment}"

                                    display_url = colored_url_without_query + rest
                    except Exception:
                        display_url = raw_u

                    safe_msg = f"{header_part}<br>&nbsp;&nbsp;&nbsp;&nbsp;<span style='color: #9CA3AF;'>↳ <b>URL:</b></span> <span style='color: #38BDF8; text-decoration: underline;' title='{raw_u}'>{display_url}</span><br>"

                safe_msg = safe_msg.replace("[SHIELD_ALERT]", "<span style='background-color: #7F1D1D; color: #FECACA; padding: 2px 6px; border-radius: 4px;'><b>🛡️ SHIELD</b></span>")
                safe_msg = safe_msg.replace("🛡️ FIREWALL BLOCK", "<span style='color: #EF4444; font-weight: bold;'>FIREWALL BLOCK</span>")
                safe_msg = safe_msg.replace("🛑 FIREWALL BLOCK", "<span style='color: #EF4444; font-weight: bold;'>FIREWALL BLOCK</span>")

                safe_msg = f"<span style='color: #E5E7EB; line-height: 1.4;'>{safe_msg}</span>"
            elif "[shield_alert]" in lower_msg or "[web_sec]" in lower_msg: safe_msg = f"<span style='color: #EF4444; font-weight: bold;'>{safe_msg}</span>"
            elif "[✅]" in safe_msg or "Success" in safe_msg: safe_msg = f"<span style='color: #10B981;'>{safe_msg}</span>"
            elif is_error: safe_msg = f"<span style='color: #EF4444; font-weight: bold;'>{safe_msg}</span>"
            elif "[warning]" in lower_msg or "warning:" in lower_msg: safe_msg = f"<span style='color: #FBBF24; font-weight: bold;'>{safe_msg}</span>"
            elif "[webmssdk]" in lower_msg: safe_msg = f"<span style='color: #38BDF8;'>{safe_msg}</span>"
            elif "Llama Verification Engine" in safe_msg: safe_msg = f"<span style='color: #34D399;'>{safe_msg}</span>"
            elif "[sys_log]" in lower_msg or "[system/deps]" in lower_msg or "[pre-gui]" in lower_msg or "[qt " in lower_msg: safe_msg = f"<span style='color: #60A5FA;'>{safe_msg}</span>"
            elif "[cdp" in lower_msg or "[ai logs]" in lower_msg: safe_msg = f"<span style='color: #A78BFA;'>{safe_msg}</span>"
            else: safe_msg = f"<span style='color: #D1D5DB;'>{safe_msg}</span>"

            message, is_html = safe_msg, True

        target_key = "General"

        if is_firewall_block or is_stealth_fallback or is_redirect_block or "[shield_alert]" in lower_msg or "shield_alert" in lower_msg or "[web_sec]" in lower_msg or "suppressed fatal" in lower_msg:
            target_key = "Web_Security"

        elif "[x_log]" in lower_msg:
            target_key = "X.com"
        elif "[fb_log]" in lower_msg:
            target_key = "Facebook"
        elif "[tiktok_log]" in lower_msg:
            target_key = "TikTok"
        elif "[instagram_log]" in lower_msg:
            target_key = "Instagram"
        elif "[foxweb_log]" in lower_msg:
            target_key = "Fox Web"
        elif "[intercepted headers]" in lower_msg or "[http inbound response]" in lower_msg or "[http outbound request]" in lower_msg:
            if "x.com" in lower_msg or "twitter.com" in lower_msg: target_key = "X.com"
            elif "facebook.com" in lower_msg: target_key = "Facebook"
            elif "tiktok.com" in lower_msg or "tiktokv" in lower_msg: target_key = "TikTok"
            elif "instagram.com" in lower_msg: target_key = "Instagram"
            elif "foxnews.com" in lower_msg: target_key = "Fox Web"
            else: target_key = "Web"

        elif "[webmssdk]" in lower_msg or "webmssdk" in lower_msg or "byteoversea" in lower_msg or "_signature" in lower_msg or "x-bogus" in lower_msg:
            target_key = "WebMSSDK"
            if not is_html:
                message = f"<span style='color: #38BDF8;'>{message}</span>"
                is_html = True
        elif "ai scrape" in lower_msg or "[ai discovered]" in lower_msg or "added new ai clip" in lower_msg or "[ai found" in lower_msg:
            target_key = "AI Found"
        elif ("llama" in lower_msg and "auto-approved" not in lower_msg) or "[ai logs]" in lower_msg or "[ai auto-diag]" in lower_msg or "[ai page diagnosis]" in lower_msg or "🧠" in lower_msg or "[ai extract]" in lower_msg:
            target_key = "AI Logs"
        elif "[youtube" in lower_msg or "[foxapi" in lower_msg or "[googlerss" in lower_msg or "[profilescrape" in lower_msg:
            target_key = "Web"
        elif "[unsorted_traffic]" in lower_msg:
            target_key = "Unsorted Traffic"
        elif "[x.com" in lower_msg or "[x_log]" in lower_msg:
            target_key = "X.com"
        elif "[facebook" in lower_msg or "[fb_log]" in lower_msg:
            target_key = "Facebook"
        elif "[fox web]" in lower_msg or "[foxweb_log]" in lower_msg:
            target_key = "Fox Web"
        elif "[tiktok" in lower_msg or "[tiktok_log]" in lower_msg or "pulled cleanly via yt-dlp" in lower_msg:
            target_key = "TikTok"
        elif "[instagram" in lower_msg or "[instagram_log]" in lower_msg:
            target_key = "Instagram"
        elif "[web_log]" in lower_msg or "[web] " in lower_msg or "[web]" in lower_msg:
            if "twimg.com" in lower_msg or "twitter.com" in lower_msg or "x.com" in lower_msg:
                target_key = "X.com"
            elif "fbcdn.net" in lower_msg or "facebook.com" in lower_msg:
                target_key = "Facebook"
            elif "tiktok" in lower_msg:
                target_key = "TikTok"
            elif "instagram" in lower_msg or "cdninstagram" in lower_msg:
                target_key = "Instagram"
            elif "foxnews.com" in lower_msg or "foxbusiness.com" in lower_msg:
                target_key = "Fox Web"
            else:
                target_key = "Web"
        elif "[sys_log]" in lower_msg or "[system/deps]" in lower_msg or "[pre-gui]" in lower_msg or "[qt " in lower_msg or "sandbox" in lower_msg:
            target_key = "General"
            is_embedded = True
        else:
            target_key = "Web"

        if target_key in ["General", "AI Logs"]:
            is_embedded = True

        # Strip the technical [SYS_LOG] prefix before display without breaking routing
        display_message = message.replace("[SYS_LOG] ", "").replace("[SYS_LOG]", "")

        if is_embedded:
            if target_key in self.embedded_consoles:
                self.smart_append(self.embedded_consoles[target_key], display_message, is_html)
            else:
                self.smart_append(self.embedded_consoles["General"], message, is_html)
        else:
            if target_key in self.log_consoles:
                self.smart_append(self.log_consoles[target_key], display_message, is_html)
            else:
                self.smart_append(self.log_consoles["General"], display_message, is_html)

            # Route System (General) and AI Logs secondary entries into the primary consoles as well
            if target_key in ["General", "AI Logs"]:
                if target_key in self.embedded_consoles:
                    self.smart_append(self.embedded_consoles[target_key], display_message, is_html)

    def load_history(self):
        if not os.path.exists(HISTORY_FILE): return
        try:
            with open(HISTORY_FILE, 'r') as f: saved_data = json.load(f)
            self.clips = []
            seen_keys = set()
            for item in saved_data:
                dt_val = item.get('datetime')
                if dt_val:
                    try:
                        if isinstance(dt_val, str):
                            dt_obj = datetime.fromisoformat(dt_val)
                            if dt_obj.tzinfo is None: dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                            item['datetime'] = dt_obj
                    except Exception: item['datetime'] = None
                clip_key = (item['url'], item.get('source', ''))
                if clip_key not in seen_keys:
                    self.clips.append(item)
                    seen_keys.add(clip_key)
            self.save_history()
        except Exception: self.clips = []

    def save_history(self):
        try:
            data_to_save = []
            for clip in self.clips:
                clip_copy = clip.copy()
                dt_val = clip_copy.get('datetime')
                if isinstance(dt_val, datetime): clip_copy['datetime'] = dt_val.isoformat()
                elif dt_val is None: clip_copy['datetime'] = None
                data_to_save.append(clip_copy)
            with open(HISTORY_FILE, 'w') as f: json.dump(data_to_save, f, indent=4)
        except Exception: pass

    def trigger_background_scan(self, custom_query=None):
        if self.scanner_thread is not None and self.scanner_thread.isRunning(): return
        if not self.app_settings.get("enable_background_scans", True) and not custom_query:
            self.append_log_message("[SYS_LOG] ⏸ Background Network Scans are disabled in Settings. Skipping background sweep.", is_embedded=False)
            self.update_progress_ui(0, "Idle (Network Scans Disabled in Settings)")
            return

        self.update_progress_ui(5, "Initializing Scanners & AI Engine...")
        active_names = [t["name"] for t in self.targets_data]

        if custom_query and custom_query not in active_names:
            new_target = {
                "name": custom_query, "profile_url": "", "x_user": clean_handle(custom_query, "x"),
                "facebook_user": clean_handle(custom_query, "facebook"), "tiktok_user": clean_handle(custom_query, "tiktok"),
                "instagram_user": clean_handle(custom_query, "instagram"), "youtube": True, "fox_api": True,
                "google_rss": True, "profile_scrape": False, "x": True, "facebook": True, "tiktok": True, "instagram": True
            }
            self.targets_data.append(new_target)
            save_targets_data(self.targets_data)
            self.rebuild_all_platform_bars()

        targets = [custom_query] if custom_query else [t["name"] for t in self.targets_data]
        self.scanner_thread = MediaScannerWorker(targets, self)
        self.scanner_thread.progress_update.connect(self.update_progress_ui)
        self.scanner_thread.scan_complete.connect(self.on_scan_finished)
        self.scanner_thread.log_msg.connect(lambda msg: self.append_log_message(msg, is_embedded=False))
        self.scanner_thread.start()

    def on_scan_finished(self, results):
        all_new_clips = results['youtube_clips'] + results['network_clips']
        existing_keys = {(clip['url'], clip.get('source', '')) for clip in self.clips}
        added_count = 0
        for new_clip in all_new_clips:
            clip_key = (new_clip['url'], new_clip.get('source', ''))
            if clip_key not in existing_keys:
                self.clips.append(new_clip)
                existing_keys.add(clip_key)
                added_count += 1

        if added_count > 0 or not self.clips:
            def get_safe_dt(clip): return clip.get('datetime') if isinstance(clip.get('datetime'), datetime) else datetime.min.replace(tzinfo=timezone.utc)
            self.clips.sort(key=get_safe_dt, reverse=True)
            self.clips = self.clips[:1000]
            self.save_history()
            self._populate_network_list()

        if self.clips: self.network_header.setText("<b><span style='color: #22C55E;'>⬤</span> Network & YT Clips:</b>")
        else: self.network_header.setText("<b><span style='color: #EF4444;'>❌</span> Network & YT Clips:</b>")
        QTimer.singleShot(3000, lambda: self.update_progress_ui(0, "Idle (Waiting for next cycle)"))

    def filter_network_list(self, text):
        text = text.lower()
        for tree in self.network_lists.values():
            iterator = QTreeWidgetItemIterator(tree)
            while iterator.value():
                item = iterator.value()
                if not item.parent():
                    iterator += 1
                    continue
                widget = tree.itemWidget(item, 0)
                if widget:
                    if text in widget.text().lower() or text in item.data(0, 100).lower(): item.setHidden(False)
                    else: item.setHidden(True)
                iterator += 1

    def run_deep_search(self, custom_query=None):
        query = self.network_search_input.text().strip()
        if not query: return
        self.append_log_message(f"[SYS_LOG] Initiating Deep Web Scan for query: '{query}'", is_embedded=False)
        self.trigger_background_scan(custom_query=query)

    def _populate_network_list(self):
        now_local = get_real_now().astimezone()
        local_today_str = now_local.strftime('%Y-%m-%d')
        local_yesterday_str = (now_local - timedelta(days=1)).strftime('%Y-%m-%d')
        min_date = datetime.min.replace(tzinfo=timezone.utc)

        def get_safe_dt(clip): return clip.get('datetime') if isinstance(clip.get('datetime'), datetime) else min_date
        self.clips.sort(key=get_safe_dt, reverse=True)

        for target_name, tree in self.network_lists.items():
            tree.clear()
            cat_data = [
                (QTreeWidgetItem(["🤖 AI Discovered"]), "#4C1D95", "#DDD6FE", "#8B5CF6", "#1E1B4B", "#2E1065"),
                (QTreeWidgetItem(["👤 Author Profile Scrape"]), "#1E3A8A", "#BFDBFE", "#3B82F6", "#0F172A", "#1E293B"),
                (QTreeWidgetItem(["🦊 FoxNews.com Network Search"]), "#581C87", "#F3E8FF", "#A855F7", "#1E1B4B", "#312E81"),
                (QTreeWidgetItem(["▶️ YouTube Searches"]), "#991B1B", "#FEE2E2", "#DC2626", "#450A0A", "#7F1D1D"),
                (QTreeWidgetItem(["🔍 Google RSS Search"]), "#064E3B", "#A7F3D0", "#10B981", "#111C18", "#132E25"),
                (QTreeWidgetItem(["🐦 X.com Feed"]), "#0369A1", "#E0F2FE", "#0EA5E9", "#082F49", "#0C4A6E"),
                (QTreeWidgetItem(["📘 Facebook Feed"]), "#1E40AF", "#DBEAFE", "#3B82F6", "#172554", "#1D4ED8"),
                (QTreeWidgetItem(["📱 TikTok Feed"]), "#701A75", "#FAE8FF", "#D946EF", "#4A044E", "#581C87")
            ]
            cat_ai, cat_profile, cat_fox_api, cat_youtube, cat_google, cat_x_feed, cat_fb_feed, cat_tiktok = [item[0] for item in cat_data]

            for cat, bg_hex, fg_hex, _, _, _ in cat_data:
                cat.setBackground(0, QColor(bg_hex))
                cat.setForeground(0, QColor(fg_hex))
                font = QFont()
                font.setBold(True)
                font.setPointSize(11)
                cat.setFont(0, font)
                tree.addTopLevelItem(cat)

            target_clips = [c for c in self.clips if c.get('target') == target_name or (c.get('target') == 'None' and target_name.lower() in c.get('title', '').lower())]
            ai_clips      = [c for c in target_clips if "AI" in c.get('source', '')][:100]
            profile_clips = [c for c in target_clips if "ProfileScrape" in c.get('source', '') and "AI" not in c.get('source', '')][:100]
            fox_api_clips = [c for c in target_clips if "Fox" in c.get('source', '') and "Profile" not in c.get('source', '') and "AI" not in c.get('source', '')][:100]
            youtube_clips = [c for c in target_clips if "YouTube" in c.get('source', '') and "AI" not in c.get('source', '')][:100]
            google_clips  = [c for c in target_clips if "Google" in c.get('source', '') and "Fox" not in c.get('source', '') and "AI" not in c.get('source', '')][:100]
            x_clips       = [c for c in target_clips if c.get('source') == "X.com Feed"][:100]
            fb_clips      = [c for c in target_clips if c.get('source') == "Facebook Feed"][:100]
            tiktok_clips  = [c for c in target_clips if c.get('source') == "TikTok Feed"][:100]

            def build_tree_items(clip_list, parent_category, accent_color, card_bg, inner_bg):
                for clip in clip_list:
                    item = QTreeWidgetItem()
                    item.setData(0, 100, clip['url'])
                    item.setData(0, 101, clip.get('source', ''))
                    raw_title = clip['title'].replace('<', '&lt;').replace('>', '&gt;')
                    dt_val = clip.get('datetime')
                    if isinstance(dt_val, datetime): clip_date_str = dt_val.astimezone().strftime('%Y-%m-%d')
                    else:
                        match = re.search(r'\[(\d{4}-\d{2}-\d{2})\]', clip['title'])
                        clip_date_str = match.group(1) if match else clip.get('date_str', '')

                    title_no_date = re.sub(r'\[\d{4}-\d{2}-\d{2}\]\s*', '', raw_title)
                    if clip_date_str == local_today_str: text_color, weight = "#4ADE80", "bold"
                    elif clip_date_str == local_yesterday_str: text_color, weight = "#38BDF8", "bold"
                    else: text_color, weight = "#E5E7EB", "normal"

                    pattern = re.compile(re.escape(target_name), re.IGNORECASE)
                    desc_part = re.sub(r'\s+', ' ', pattern.sub("", title_no_date)).replace(' - ', ' ').replace(' | ', ' ').strip()
                    if desc_part.startswith('-') or desc_part.startswith(':'): desc_part = desc_part[1:].strip()

                    log_source = clip.get('source', 'Cached History')
                    desc_text = str(clip.get('description', '')).replace('<', '&lt;').replace('>', '&gt;')

                    formatted_date = f"<span style='color: {text_color}; font-weight: bold;'>[{clip_date_str}]</span>" if clip_date_str else ""
                    formatted_name = f"<span style='color: #FDE047; font-weight: bold;'>{target_name}</span>"

                    html_content = f"""
                    <div style='margin: 4px 0; padding: 8px; background-color: {card_bg}; border-left: 5px solid {accent_color}; border-radius: 4px;'>
                        <div style='color: {text_color}; font-weight: {weight}; font-size: 14px; font-family: sans-serif; white-space: normal; line-height: 1.3;'>
                            {formatted_date} {formatted_name} - {desc_part}
                        </div>
                        <div style='color: #F3F4F6; font-size: 11px; font-family: monospace; margin-top: 6px; padding: 6px; background-color: {inner_bg}; border-left: 2px solid {accent_color}; border-radius: 2px;'>
                            <b style='color: #93C5FD;'>{log_source}</b><br><span style='color: #FDE047;'>{desc_text}</span>
                        </div>
                    </div>
                    """
                    label = QLabel(html_content)
                    label.setWordWrap(True)
                    label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
                    label.setStyleSheet("background: transparent; border: none;")
                    parent_category.addChild(item)
                    tree.setItemWidget(item, 0, label)

            build_tree_items(ai_clips, cat_ai, "#8B5CF6", "#1E1B4B", "#2E1065")
            build_tree_items(profile_clips, cat_profile, "#3B82F6", "#0F172A", "#1E293B")
            build_tree_items(fox_api_clips, cat_fox_api, "#A855F7", "#1E1B4B", "#312E81")
            build_tree_items(youtube_clips, cat_youtube, "#DC2626", "#450A0A", "#7F1D1D")
            build_tree_items(google_clips, cat_google, "#10B981", "#111C18", "#132E25")
            build_tree_items(x_clips, cat_x_feed, "#0EA5E9", "#082F49", "#0C4A6E")
            build_tree_items(fb_clips, cat_fb_feed, "#3B82F6", "#172554", "#1D4ED8")
            build_tree_items(tiktok_clips, cat_tiktok, "#D946EF", "#4A044E", "#581C87")

            for cat in [cat_ai, cat_profile, cat_fox_api, cat_youtube, cat_google, cat_x_feed, cat_fb_feed, cat_tiktok]:
                cat.setExpanded(True)

    def inspect_page_for_errors(self, ok, view, log_prefix):
        if not ok:
            self.append_log_message(f"{log_prefix} [ERROR] Page failed to load natively at {view.url().toString()}", is_embedded=True)
            return
        def handle_html(html):
            if not html: return
            soup = BeautifulSoup(html, "html.parser")
            for script in soup(["script", "style", "noscript"]): script.decompose()
            soup_text = soup.get_text(separator=" ", strip=True)
            lowered_text = soup_text.lower()

            error_signatures = [
                "something went wrong", "couldn't find this account", "this page isn't available",
                "this post is unavailable", "this tweet is unavailable", "verify you are human",
                "security check", "access denied", "you've been blocked"
            ]
            has_valid_profile = "followers" in lowered_text or "following" in lowered_text or "fox news" in lowered_text
            is_error_page = any(sig in lowered_text for sig in error_signatures)

            if is_error_page and not has_valid_profile:
                safe_html = html[:1200].replace('<', '&lt;').replace('>', '&gt;')
                safe_text = soup_text[:800].replace('<', '&lt;').replace('>', '&gt;')

                def trigger_ai_site_healer():
                    try:
                        prompt = f"The social site page at {view.url().toString()} returned a block or error. Page text: {safe_text[:400]}. Provide a 1-sentence recovery strategy or alternative URL structure to heal this broken endpoint."
                        payload = {"model": "qwen2.5:1.5b", "prompt": prompt, "stream": False, "options": {"temperature": 0.0}}
                        resp = requests.post("http://127.0.0.1:11434/api/generate", json=payload, timeout=10)
                        if resp.status_code == 200:
                            fix_suggestion = resp.json().get("response", "").strip()
                            self.append_log_message(f"<span style='color: #F59E0B;'><b>🧠 [AI Site Healer]</b> Recovery suggestion for {log_prefix}: {fix_suggestion}</span>", is_html=True, is_embedded=True)
                    except Exception:
                        pass
                threading.Thread(target=trigger_ai_site_healer, daemon=True).start()

                error_details = (
                    f"{log_prefix} [ERROR] [!] Captcha or Block Page Detected. AI Healer engaged.<br><br>"
                    f"<span style='color: #F87171;'><b>--- VISIBLE PAGE TEXT ---</b><br>{safe_text}</span>"
                )
                self.append_log_message(error_details, is_html=True, is_embedded=True)
        view.page().toHtml(handle_html)

    def create_logging_webview(self, profile, log_prefix="[SYS_LOG]"):
        view = QWebEngineView()
        page = LoggingWebEnginePage(profile, view, log_prefix, app_instance=self)
        view.setPage(page)
        view.page().setBackgroundColor(QColor(18, 18, 18))

        def emit_log(msg):
            if 'GUI_EMITTER' in globals() and GUI_EMITTER:
                GUI_EMITTER.log_signal.emit(f"[EMBEDDED] {msg}")
            else:
                console_log(f"[EMBEDDED] {msg}")

        view.urlChanged.connect(lambda url: emit_log(f"{view.page().log_prefix} [Navigation Request] {url.toString()}"))
        view.loadFinished.connect(lambda ok: emit_log(f"{view.page().log_prefix} [Page Load] Status: {'Success' if ok else 'Failed'}"))
        view.loadFinished.connect(lambda ok, v=view, lp=log_prefix: self.inspect_page_for_errors(ok, v, lp))
        return view

    def play_native_video(self, url, log_prefix="[Web]"):
        if hasattr(self, 'resolver_thread') and self.resolver_thread.isRunning(): self.resolver_thread.quit()
        self.append_log_message(f"{log_prefix} Loading URL directly in Web tab: {url}", is_embedded=False)
        self.load_platform_url(self.video_output, url)
        self.center_tabs.setCurrentIndex(0)

    def navigate_url_bar(self):
        url_str = self.url_input.text().strip()
        if not url_str: return

        if "://" not in url_str:
            url_str = "https://" + url_str

        current_idx = self.center_tabs.currentIndex()
        if current_idx == 0: self.play_native_video(url_str)
        elif current_idx == 1: self.load_platform_url(self.x_web_view, url_str)
        elif current_idx == 2: self.load_platform_url(self.fb_web_view, url_str)
        elif current_idx == 3: self.load_platform_url(self.fox_web_view, url_str)
        elif current_idx == 4: self.load_platform_url(self.tiktok_web_view, url_str)
        elif current_idx == 5: self.load_platform_url(self.ig_web_view, url_str)

    def check_and_fallback_tiktok(self, target_url):
        if "tiktok.com/@" not in target_url.lower():
            return
        if "/video/" in target_url.lower() or "/reposts" in target_url.lower():
            return

        match = re.search(r'tiktok\.com/@([^/?#]+)', target_url)
        if not match:
            return
        username = match.group(1)

        if getattr(self, '_tiktok_rate_limited', False):
            return

        if getattr(self, '_current_tk_target_user', None) != username:
            self._tiktok_fetching_active = False
            self._current_tk_target_user = username
            self.tk_offset = 0

        if self._tiktok_fetching_active:
            return

        if self._tiktok_fallback_timer is not None:
            self._tiktok_fallback_timer.stop()
            self._tiktok_fallback_timer.deleteLater()
            self._tiktok_fallback_timer = None

        def evaluate_dom_status(has_native_posts, has_error_block):
            if has_native_posts:
                self.append_log_message(f"[TikTok] [✅] Native feed verified for @{username}. Custom grid bypassed.", is_embedded=True)
                self._tiktok_fetching_active = False
                return

            if has_error_block and not self._tiktok_fetching_active:
                self._tiktok_fetching_active = True
                self.append_log_message(f"[TikTok] [⚠️] 'Something went wrong' detected for @{username}. Rotating session & engaging yt-dlp profile bypass...", is_embedded=True)

                self.reset_tiktok_session()

                self.tiktok_web_view.page().runJavaScript(f"if (typeof window.showTikTokLoading === 'function') window.showTikTokLoading('{username}');")
                self.run_tiktok_ytdlp_worker(username, target_url, is_append=False)

        js_eval_script = """
        (function() {
            const feedList = document.querySelector('[data-e2e="user-post-item-list"]');
            const hasPosts = feedList && feedList.querySelectorAll('[data-e2e="user-post-item"]').length > 0;
            let hasError = false;
            document.querySelectorAll('p, span, h2, div').forEach(el => {
                if (el.textContent && (el.textContent.includes('Page not available') || el.textContent.includes('Something went wrong') || el.textContent.includes("couldn't find this account"))) {
                    if (!el.closest('[data-e2e="user-header"]')) hasError = true;
                }
            });
            return [hasPosts, hasError];
        })();
        """

        self._tiktok_fallback_timer = QTimer(self)
        self._tiktok_fallback_timer.setSingleShot(True)
        self._tiktok_fallback_timer.timeout.connect(lambda: self.tiktok_web_view.page().runJavaScript(
            js_eval_script,
            lambda res: evaluate_dom_status(res[0], res[1]) if res and isinstance(res, list) else evaluate_dom_status(False, False)
        ))
        self._tiktok_fallback_timer.start(800)

    def run_tiktok_ytdlp_worker(self, username, profile_url, is_append=False):
        if hasattr(self, 'active_tk_worker') and self.active_tk_worker and self.active_tk_worker.isRunning():
            if not is_append:
                return
            try:
                self.active_tk_worker.log_signal.disconnect()
                self.active_tk_worker.grid_signal.disconnect()
                self.active_tk_worker.progress_signal.disconnect()
            except Exception: pass

        cookie_db = getattr(EmbeddedPlayerApp, 'GLOBAL_COOKIE_DB', None)
        if cookie_db and not os.path.exists(cookie_db):
            cookie_db = None
        self.active_tk_worker = TikTokProfileWorker(username, profile_url, offset=self.tk_offset, is_append=is_append, cookie_db=cookie_db)
        self.active_tk_worker.log_signal.connect(lambda msg, html: self.append_log_message(msg, is_html=html, is_embedded=True))

        def update_progress_callback(percent, txt):
            QTimer.singleShot(0, lambda: self.tiktok_web_view.page().runJavaScript(
                f"if (typeof window.updateTikTokLoading === 'function') window.updateTikTokLoading({percent}, '{txt}');"
            ))

        def inject_grid_callback(js_data, append_mode, u=username):
            self._tiktok_fetching_active = False
            script = f"if (typeof window.renderGridWithData === 'function') {{ window.renderGridWithData({js_data}, '{u}', {'true' if append_mode else 'false'}); }}"
            QTimer.singleShot(0, lambda: self.tiktok_web_view.page().runJavaScript(script))

        self.active_tk_worker.progress_signal.connect(update_progress_callback)
        self.active_tk_worker.grid_signal.connect(inject_grid_callback)
        self.active_tk_worker.start()

    def build_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        layout.setContentsMargins(15, 15, 15, 15)

        header = QLabel("⚙️ Target Profiles & Advanced Settings")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #60A5FA; margin-bottom: 10px;")
        layout.addWidget(header)

        scan_group = QGroupBox("🔍 Background Network Scanner Settings")
        scan_group.setStyleSheet("QGroupBox { font-weight: bold; color: #F3F4F6; border: 1px solid #374151; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        scan_layout = QVBoxLayout(scan_group)

        self.cb_enable_scans = QCheckBox("Enable Automatic Background Network Searches (YouTube, RSS, Fox API, Profile Scrapes)")
        self.cb_enable_scans.setChecked(self.app_settings.get("enable_background_scans", True))
        self.cb_enable_scans.setStyleSheet("color: #34D399; font-weight: bold; font-size: 13px; padding: 4px;")

        self.cb_enable_social_scans = QCheckBox("Enable Automatic Background Social Scans on Startup (X, Facebook, TikTok, Instagram)")
        self.cb_enable_social_scans.setChecked(self.app_settings.get("enable_background_social_scans", False))
        self.cb_enable_social_scans.setStyleSheet("color: #60A5FA; font-weight: bold; font-size: 13px; padding: 4px;")

        scan_layout.addWidget(self.cb_enable_scans)
        scan_layout.addWidget(self.cb_enable_social_scans)
        layout.addWidget(scan_group)

        whitelist_group = QGroupBox("🛡️ AI Shield Whitelist Cache")
        whitelist_group.setStyleSheet("QGroupBox { font-weight: bold; color: #F3F4F6; border: 1px solid #374151; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        whitelist_layout = QVBoxLayout(whitelist_group)

        refresh_whitelist_btn = QPushButton("🔄 Re-download Top Domains Whitelist")
        refresh_whitelist_btn.setStyleSheet("QPushButton { background-color: #3B82F6; color: white; font-weight: bold; padding: 8px; border-radius: 4px; } QPushButton:hover { background-color: #2563EB; }")
        refresh_whitelist_btn.clicked.connect(self.refresh_domains_whitelist)
        whitelist_layout.addWidget(refresh_whitelist_btn)
        layout.addWidget(whitelist_group)

        login_cache_group = QGroupBox("🔐 Login Session & Cookie Management")
        login_cache_group.setStyleSheet("QGroupBox { font-weight: bold; color: #F3F4F6; border: 1px solid #374151; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        login_cache_layout = QVBoxLayout(login_cache_group)

        clear_login_btn = QPushButton("🧹 Clear Login Cache & Force Relogin")
        clear_login_btn.setStyleSheet("QPushButton { background-color: #EF4444; color: white; font-weight: bold; padding: 8px; border-radius: 4px; } QPushButton:hover { background-color: #DC2626; }")
        clear_login_btn.clicked.connect(self.clear_login_cache)
        login_cache_layout.addWidget(clear_login_btn)
        layout.addWidget(login_cache_group)

        add_group = QGroupBox("➕ Add New Person / Target to Watch")
        add_group.setStyleSheet("QGroupBox { font-weight: bold; color: #F3F4F6; border: 1px solid #374151; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        add_layout = QVBoxLayout(add_group)

        row1 = QHBoxLayout()
        self.new_name_input = QLineEdit()
        self.new_name_input.setPlaceholderText("Target Full Name (e.g., Kayleigh Mcenany)")
        self.new_name_input.setStyleSheet("QLineEdit { background-color: #1F2937; color: #FFFFFF; border: 1px solid #4B5563; border-radius: 4px; padding: 6px; }")
        row1.addWidget(self.new_name_input)
        add_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.new_fox_url = QLineEdit()
        self.new_fox_url.setPlaceholderText("Fox / Network Profile URL")
        self.new_x_url = QLineEdit()
        self.new_x_url.setPlaceholderText("X Handle")
        self.new_fb_url = QLineEdit()
        self.new_fb_url.setPlaceholderText("Facebook User")
        self.new_tk_url = QLineEdit()
        self.new_tk_url.setPlaceholderText("TikTok Handle")
        self.new_ig_url = QLineEdit()
        self.new_ig_url.setPlaceholderText("Instagram Handle")

        field_style = "QLineEdit { background-color: #1F2937; color: #FFFFFF; border: 1px solid #4B5563; border-radius: 4px; padding: 4px; font-size: 11px; }"
        for inp in [self.new_fox_url, self.new_x_url, self.new_fb_url, self.new_tk_url, self.new_ig_url]:
            inp.setStyleSheet(field_style)
            row2.addWidget(inp)
        add_layout.addLayout(row2)

        cb_layout = QHBoxLayout()
        self.cb_yt = QCheckBox("YouTube")
        self.cb_fox = QCheckBox("Fox API")
        self.cb_rss = QCheckBox("Google RSS")
        self.cb_scrape = QCheckBox("Profile Scrape")
        self.cb_x = QCheckBox("X")
        self.cb_fb = QCheckBox("Facebook")
        self.cb_tk = QCheckBox("TikTok")
        self.cb_ig = QCheckBox("Instagram")

        for cb in [self.cb_yt, self.cb_fox, self.cb_rss, self.cb_scrape, self.cb_x, self.cb_fb, self.cb_tk, self.cb_ig]:
            cb.setChecked(True)
            cb.setStyleSheet("color: #E5E7EB; font-weight: bold;")
            cb_layout.addWidget(cb)
        add_layout.addLayout(cb_layout)

        add_btn = QPushButton("➕ Add Target")
        add_btn.setStyleSheet("QPushButton { background-color: #2563EB; color: white; font-weight: bold; padding: 8px; border-radius: 4px; } QPushButton:hover { background-color: #1D4ED8; }")
        add_btn.clicked.connect(self.add_target_from_form)
        add_layout.addWidget(add_btn)

        layout.addWidget(add_group)

        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(15)
        self.targets_table.setHorizontalHeaderLabels([
            "Target Name", "Network Profile URL", "X Handle", "Facebook User", "TikTok Handle", "Instagram Handle",
            "YT", "API", "RSS", "Author", "X", "FaceBook", "TikTok", "Instagram", "Actions"
        ])
        self.targets_table.setStyleSheet("QTableWidget { background-color: #111827; color: white; gridline-color: #4B5563; border: 1px solid #374151; } QHeaderView::section { background-color: #1F2937; color: #60A5FA; font-weight: bold; border: 1px solid #374151; padding: 4px; }")

        layout.addWidget(self.targets_table)
        self.populate_settings_table()

        save_btn = QPushButton("Save All Settings & Restart Scanners")
        save_btn.setStyleSheet("QPushButton { background-color: #2563EB; color: white; font-weight: bold; font-size: 14px; padding: 12px; border-radius: 6px; } QPushButton:hover { background-color: #1D4ED8; }")
        save_btn.clicked.connect(self.save_and_reload_settings)
        layout.addWidget(save_btn)

    def populate_settings_table(self):
        self.targets_table.setRowCount(0)
        for row, t in enumerate(self.targets_data):
            self.targets_table.insertRow(row)

            def create_item(text):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                return item

            self.targets_table.setItem(row, 0, create_item(t.get("name", "")))
            self.targets_table.setItem(row, 1, create_item(t.get("profile_url", "")))
            self.targets_table.setItem(row, 2, create_item(clean_handle(t.get("x_user", ""), "x")))
            self.targets_table.setItem(row, 3, create_item(clean_handle(t.get("facebook_user", ""), "facebook")))
            self.targets_table.setItem(row, 4, create_item(clean_handle(t.get("tiktok_user", ""), "tiktok")))
            self.targets_table.setItem(row, 5, create_item(clean_handle(t.get("instagram_user", ""), "instagram")))

            keys = ["youtube", "fox_api", "google_rss", "profile_scrape", "x", "facebook", "tiktok", "instagram"]
            for col_idx, key in enumerate(keys, start=6):
                chk_item = QTableWidgetItem()
                chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
                chk_item.setCheckState(Qt.CheckState.Checked if t.get(key, True) else Qt.CheckState.Unchecked)
                self.targets_table.setItem(row, col_idx, chk_item)

            act_widget = QWidget()
            act_layout = QHBoxLayout(act_widget)
            act_layout.setContentsMargins(2, 2, 2, 2)
            del_btn = QPushButton("Delete")
            del_btn.setFixedWidth(65)
            del_btn.setStyleSheet("QPushButton { background-color: #EF4444; color: white; border-radius: 3px; padding: 4px; font-size: 13px; } QPushButton:hover { background-color: #DC2626; }")
            del_btn.clicked.connect(lambda checked, r=row: self.delete_target_row(r))
            act_layout.addWidget(del_btn)
            self.targets_table.setCellWidget(row, 14, act_widget)

    def add_target_from_form(self):
        name = self.new_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Input Error", "Target name cannot be empty!")
            return

        new_target = {
            "name": name,
            "profile_url": self.new_fox_url.text().strip(),
            "x_user": clean_handle(self.new_x_url.text().strip(), "x"),
            "facebook_user": clean_handle(self.new_fb_url.text().strip(), "facebook"),
            "tiktok_user": clean_handle(self.new_tk_url.text().strip(), "tiktok"),
            "instagram_user": clean_handle(self.new_ig_url.text().strip(), "instagram"),
            "youtube": self.cb_yt.isChecked(),
            "fox_api": self.cb_fox.isChecked(),
            "google_rss": self.cb_rss.isChecked(),
            "profile_scrape": self.cb_scrape.isChecked(),
            "x": self.cb_x.isChecked(),
            "facebook": self.cb_fb.isChecked(),
            "tiktok": self.cb_tk.isChecked(),
            "instagram": self.cb_ig.isChecked()
        }

        self.targets_data.append(new_target)
        self.populate_settings_table()

        self.new_name_input.clear()
        self.new_fox_url.clear()
        self.new_x_url.clear()
        self.new_fb_url.clear()
        self.new_tk_url.clear()
        self.new_ig_url.clear()
        self.append_log_message(f"[SYS_LOG] Target '{name}' added to settings list.", is_embedded=False)

    def delete_target_row(self, row):
        if 0 <= row < len(self.targets_data):
            removed = self.targets_data.pop(row)
            self.populate_settings_table()
            self.append_log_message(f"[SYS_LOG] Target '{removed.get('name')}' removed.", is_embedded=False)

    def save_and_reload_settings(self):
        self.app_settings["enable_background_scans"] = self.cb_enable_scans.isChecked()
        self.app_settings["enable_background_social_scans"] = self.cb_enable_social_scans.isChecked()
        save_app_settings(self.app_settings)

        updated_data = []
        keys = ["youtube", "fox_api", "google_rss", "profile_scrape", "x", "facebook", "tiktok", "instagram"]
        for row in range(self.targets_table.rowCount()):
            name_item = self.targets_table.item(row, 0)
            if not name_item or not name_item.text().strip(): continue

            target = {
                "name": name_item.text().strip(),
                "profile_url": self.targets_table.item(row, 1).text().strip() if self.targets_table.item(row, 1) else "",
                "x_user": clean_handle(self.targets_table.item(row, 2).text().strip() if self.targets_table.item(row, 2) else "", "x"),
                "facebook_user": clean_handle(self.targets_table.item(row, 3).text().strip() if self.targets_table.item(row, 3) else "", "facebook"),
                "tiktok_user": clean_handle(self.targets_table.item(row, 4).text().strip() if self.targets_table.item(row, 4) else "", "tiktok"),
                "instagram_user": clean_handle(self.targets_table.item(row, 5).text().strip() if self.targets_table.item(row, 5) else "", "instagram")
            }

            for col_idx, key in enumerate(keys, start=6):
                chk_item = self.targets_table.item(row, col_idx)
                target[key] = (chk_item.checkState() == Qt.CheckState.Checked) if chk_item else True

            updated_data.append(target)

        self.targets_data = updated_data
        save_targets_data(self.targets_data)
        self.rebuild_network_tabs()
        self.rebuild_all_platform_bars()

        self.append_log_message("<span style='color: #10B981;'>[✅] All Settings saved!</span>", is_html=True, is_embedded=False)
        self.trigger_background_scan()

    def on_tree_item_clicked(self, item, column):
        target_url = item.data(0, 100)
        source = item.data(0, 101)

        if target_url and "about:blank" not in target_url:
            # Load clean standalone HTML5 video player by safely extracting the numeric ID
            if "foxnews.com/video/" in target_url:
                vid_match = re.search(r'/video/(\d+)', target_url)
                if vid_match:
                    vid_id = vid_match.group(1)
                    target_url = f"https://video.foxnews.com/v/video-embed.html?video_id={vid_id}"

            prefix_map = {
                "YouTube": "[Web] [YouTube] [Player]",
                "FoxAPI": "[Web] [FoxAPI] [Player]",
                "GoogleRSS": "[Web] [GoogleRSS] [Player]",
                "ProfileScrape": "[Web] [ProfileScrape] [Player]"
            }

            source_to_tab = {
                "ProfileScrape": 0,
                "FoxAPI": 0,
                "YouTube": 0,
                "GoogleRSS": 0,
                "AI Scrape": 0,
                "X.com Feed": 3,
                "Facebook Feed": 4,
                "TikTok Feed": 6,
                "Instagram Feed": 7
            }

            if source in source_to_tab:
                self.switch_log_tab(source_to_tab[source])
            else:
                self.switch_log_tab(2)

            log_prefix = "AI Found / " if source == "AI Scrape" else ""
            self.append_log_message(f"<span style='color: #A78BFA;'><b>[{log_prefix}{source}]</b> Loading item: <a href='{target_url}' style='color:#60A5FA;'>{target_url}</a></span>", is_html=True, is_embedded=False)

            self.url_input.setText(target_url)

            self.center_tabs.setCurrentIndex(0)
            self.play_native_video(target_url, log_prefix=prefix_map.get(source, "[Web]"))

    def on_center_tab_changed(self, index):
        log_tab_mapping = {
            0: 0,  # Web -> Web log
            1: 3,  # X.com -> X.com log
            2: 4,  # Facebook -> Facebook log
            3: 5,  # Fox Profiles -> Fox Web log
            4: 6,  # TikTok -> TikTok log
            5: 7   # Instagram -> Instagram log
        }
        if index in log_tab_mapping:
            self.switch_log_tab(log_tab_mapping[index])

        # Automatically switch to Primary (embedded view) for Web (0), social & Fox web tabs (indices 1 to 5),
        # and keep Main app logs for Settings (6).
        if 0 <= index <= 5:
            self.set_log_view_mode(True)
        else:
            self.set_log_view_mode(False)

        def delayed_load(view, url):
            self.load_platform_url(view, url)

        if index == 1 and not self.loaded_tabs[1]:
            self.loaded_tabs[1] = True
            QTimer.singleShot(150, lambda: delayed_load(self.x_web_view, "https://x.com/home"))
        elif index == 2 and not self.loaded_tabs[2]:
            self.loaded_tabs[2] = True
            QTimer.singleShot(150, lambda: delayed_load(self.fb_web_view, "https://www.facebook.com/"))
        elif index == 3 and not self.loaded_tabs[3]:
            self.loaded_tabs[3] = True
            QTimer.singleShot(150, lambda: delayed_load(self.fox_web_view, "https://www.foxnews.com/"))
        elif index == 4 and not self.loaded_tabs[4]:
            self.loaded_tabs[4] = True
            first_target = self.targets_data[0] if self.targets_data else {}
            tiktok_user = first_target.get("tiktok_user", "kayleighmcenany")
            QTimer.singleShot(150, lambda: delayed_load(self.tiktok_web_view, f"https://www.tiktok.com/@{tiktok_user}"))
        elif index == 5 and not self.loaded_tabs[5]:
            self.loaded_tabs[5] = True
            QTimer.singleShot(150, lambda: delayed_load(self.ig_web_view, "https://www.instagram.com/"))

    def closeEvent(self, event):
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("main_splitter_state", self.main_splitter.saveState())
        self.save_history()

        self.ai_diagnostics.running = False
        if self.ai_diagnostics.isRunning():
            self.ai_diagnostics.quit()
            self.ai_diagnostics.wait(500)

        if hasattr(self, 'cdp_worker') and self.cdp_worker.isRunning():
            self.cdp_worker.running = False
            self.cdp_worker.quit()
            self.cdp_worker.wait(1000)

        if hasattr(self, 'resolver_thread') and self.resolver_thread.isRunning():
            self.resolver_thread.quit()

        if self.comment_worker and self.comment_worker.isRunning():
            self.comment_worker.quit()

        for view in [self.video_output, self.x_web_view, self.fb_web_view, self.fox_web_view, self.tiktok_web_view, self.ig_web_view]:
            try: view.deleteLater()
            except: pass

        event.accept()
        QApplication.quit()
        os._exit(0)

def qt_message_handler(mode, context, message):
    ignore_list = [
        "GPUInfo", "GL_INVALID_VALUE", "glGetProgramiv", "stun.l.google.com",
        "Binding request timed out", "Failed to resolve address",
        "GBM is not supported", "OpenType support missing", "Fallback to Vulkan rendering",
        "Remote debugging server started successfully"
    ]
    if any(ignore in message for ignore in ignore_list): return

    # Intercept graphics fallback notices and note them as normal hardware behavior
    if any(v_msg in message for v_msg in ["Failed to create Vulkan instance", "Failed to create platform Vulkan instance"]):
        return  # Suppress the redundant Vulkan probe failure

    if "Failed to query DRM render node file path" in message or "Fallback to /dev/dri/renderD128" in message:
        html_msg = "<span style='color: #FBBF24; font-weight: bold;'>⚠ GPU Notice:</span> <span style='color: #E5E7EB;'>Vulkan safely bypassed. Hardware acceleration active via OpenGL/EGL on /dev/dri/renderD128 (Normal Behavior).</span>"
        if 'app_log_emitter' in globals():
            app_log_emitter.log_signal.emit(html_msg)
        return

    if "ERROR:" in message or mode in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
        msg = f"[Qt Engine] [ERROR] {message}"
    else:
        msg = f"[Qt Engine] {message}"

    if 'app_log_emitter' in globals():
        app_log_emitter.log_signal.emit(msg)
    else:
        print(msg, flush=True)

    if "ERROR:" in message or mode in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
        msg = f"[Qt Engine] [ERROR] {message}"
    else:
        msg = f"[Qt Engine] {message}"

    if 'app_log_emitter' in globals():
        app_log_emitter.log_signal.emit(msg)
    else:
        print(msg, flush=True)

if __name__ == "__main__":
    MultiLayerSandbox.execute_layer1_containment()

    # Load domains strictly once, after process containment is fully locked in
    load_or_download_domains(force_refresh=False)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    icon_dir = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps")
    os.makedirs(icon_dir, exist_ok=True)
    icon_path = os.path.join(icon_dir, "multi-target-media-monitor.png")
    desktop_dir = os.path.expanduser("~/.local/share/applications")
    os.makedirs(desktop_dir, exist_ok=True)
    desktop_path = os.path.join(desktop_dir, "multi-target-media-monitor.desktop")
    try:
        size = 256
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg_grad = QLinearGradient(0, 0, size, size)
        bg_grad.setColorAt(0.0, QColor(28, 31, 38))
        bg_grad.setColorAt(1.0, QColor(14, 16, 21))
        painter.setBrush(bg_grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(QRectF(0, 0, size, size), 48, 48)
        painter.setPen(QPen(QColor(60, 65, 80), 3))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(QRectF(0, 0, size, size), 48, 48)
        painter.save()
        painter.translate(128, 128)
        painter.save()
        painter.rotate(-30)
        orbit_pen1 = QPen(QColor(234, 120, 31), 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(orbit_pen1)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QRectF(-90, -40, 180, 80))
        painter.restore()
        painter.save()
        painter.rotate(30)
        orbit_pen2 = QPen(QColor(217, 119, 6), 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(orbit_pen2)
        painter.drawEllipse(QRectF(-90, -40, 180, 80))
        painter.restore()
        painter.save()
        painter.rotate(90)
        orbit_pen3 = QPen(QColor(194, 65, 12), 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(orbit_pen3)
        painter.drawEllipse(QRectF(-90, -40, 180, 80))
        painter.restore()

        painter.restore()

        nucleus_rect = QRectF(96, 96, 64, 64)
        r_grad = QLinearGradient(128, 96, 160, 128)
        r_grad.setColorAt(0.0, QColor(220, 70, 65))
        r_grad.setColorAt(1.0, QColor(197, 34, 31))
        painter.setBrush(r_grad)
        painter.setPen(QPen(QColor(40, 40, 40), 1))
        painter.drawPie(nucleus_rect, 0 * 16, 120 * 16)
        g_grad = QLinearGradient(128, 160, 96, 128)
        g_grad.setColorAt(0.0, QColor(40, 160, 80))
        g_grad.setColorAt(1.0, QColor(19, 115, 51))
        painter.setBrush(g_grad)
        painter.drawPie(nucleus_rect, 120 * 16, 120 * 16)
        y_grad = QLinearGradient(96, 128, 128, 96)
        y_grad.setColorAt(0.0, QColor(240, 165, 0))
        y_grad.setColorAt(1.0, QColor(227, 116, 0))
        painter.setBrush(y_grad)
        painter.drawPie(nucleus_rect, 240 * 16, 120 * 16)
        core_hub = QRectF(112, 112, 32, 32)
        b_grad = QLinearGradient(112, 112, 144, 144)
        b_grad.setColorAt(0.0, QColor(80, 150, 255))
        b_grad.setColorAt(1.0, QColor(26, 115, 232))
        painter.setBrush(b_grad)
        painter.setPen(QPen(QColor(255, 255, 255), 1.5))
        painter.drawEllipse(core_hub)

        painter.end()
        pixmap.save(icon_path, "PNG")
    except Exception as e:
        print(f"[!] Warning: Could not generate custom icon: {e}")

    app_icon = QIcon(pixmap)
    app.setWindowIcon(app_icon)

    try:
        desktop_content = f"""[Desktop Entry]
Type=Application
Name=Multi-Target Media Monitor
Exec={sys.executable} {os.path.abspath(sys.argv[0])}
Icon={icon_path}
Comment=Advanced Multi-Target Media Monitor
Terminal=false
Categories=Network;AudioVideo;
StartupNotify=true
StartupWMClass=MultiTargetMediaMonitor
"""
        with open(desktop_path, "w", encoding="utf-8") as f:
            f.write(desktop_content)

        subprocess.run(["update-desktop-database", icon_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] Warning: Could not create local .desktop file: {e}")

    app.setApplicationName("MultiTargetMediaMonitor")
    app.setOrganizationName("MediaMonitor")

    if hasattr(app, "setDesktopFileName"):
        app.setDesktopFileName("multi-target-media-monitor")

    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(26, 26, 26))
    dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(18, 18, 18))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(26, 26, 26))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(35, 35, 35))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(dark_palette)

    global app_log_emitter
    app_log_emitter = LogSignalEmitter()
    qInstallMessageHandler(qt_message_handler)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(QtLogHandler(app_log_emitter))

    window = EmbeddedPlayerApp(app_log_emitter)
    window.setWindowIcon(app_icon)

    window.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowMinMaxButtonsHint | Qt.WindowType.WindowCloseButtonHint)
    window.show()
    window.raise_()
    window.activateWindow()

    sys.exit(app.exec())
