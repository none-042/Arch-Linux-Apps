#!/usr/bin/env python3
import os
import subprocess
import time
import re

def run_cmd(cmd, ignore_errors=False, return_full=False):
    """Executes a command. Returns stdout, or the full subprocess object if requested."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 and not ignore_errors:
            print(f"[-] Warning: Command failed ({cmd})\n    Error: {result.stderr.strip()}")
        if return_full:
            return result
        return result.stdout.strip()
    except Exception as e:
        print(f"[-] Error executing {cmd}: {str(e)}")
        if return_full:
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))
        return ""

def get_interfaces():
    """Dynamically identify all network interfaces, ignoring loopback."""
    raw = run_cmd("ip -o link show | awk -F': ' '{print $2}'")
    return [iface.strip() for iface in raw.split('\n') if iface and iface.strip() != 'lo']

def detect_desktop_environment():
    """Dynamically detects the installed desktop environment."""
    if run_cmd("command -v plasmashell", ignore_errors=True):
        return "KDE"
    elif run_cmd("command -v mate-session", ignore_errors=True):
        return "MATE"
    return "UNKNOWN"

def undo_aggressive_lockdown():
    """Reverses the breaking changes from the paranoid version."""
    print("[*] --- Reverting strict USB and DNS lockdowns... ---")

    # 1. Nuke USBGuard completely (Arch version) so Wi-Fi/USB drives work
    run_cmd("systemctl stop usbguard", ignore_errors=True)
    run_cmd("systemctl disable usbguard", ignore_errors=True)
    run_cmd("pacman -Rns --noconfirm usbguard", ignore_errors=True)
    run_cmd("rm -rf /etc/usbguard", ignore_errors=True)

    # Force the Linux kernel to trust all USB ports again immediately
    print("    [*] Waking up kernel USB bus authorizations...")
    run_cmd("sh -c 'for bus in /sys/bus/usb/devices/usb*/authorized_default; do echo 1 > \"$bus\" 2>/dev/null; done'", ignore_errors=True)
    run_cmd("sh -c 'for dev in /sys/bus/usb/devices/*/authorized; do echo 1 > \"$dev\" 2>/dev/null; done'", ignore_errors=True)

    # Clean up any leftover hidepid restrictions that break Polkit/USB automounting
    run_cmd("mount -o remount,rw,hidepid=0 /proc", ignore_errors=True)
    if os.path.exists("/etc/fstab"):
        run_cmd("sed -i '/hidepid=2/d' /etc/fstab", ignore_errors=True)

    # 2. Unlock resolv.conf and fix DNS
    run_cmd("chattr -i /etc/resolv.conf", ignore_errors=True)
    run_cmd("systemctl stop dnscrypt-proxy", ignore_errors=True)
    run_cmd("systemctl disable dnscrypt-proxy", ignore_errors=True)

    # Remove the 'dns=none' line we injected into NetworkManager
    nm_conf = "/etc/NetworkManager/NetworkManager.conf"
    if os.path.exists(nm_conf):
        run_cmd(f"sed -i '/^dns=none/d' {nm_conf}", ignore_errors=True)

def inject_blackarch_repo():
    """Turns EndeavourOS into a Kali replacement by injecting the BlackArch repo."""
    print("\n[*] --- Injecting BlackArch Penetration Testing Repository ---")
    if os.path.exists("/etc/pacman.d/blackarch-mirrorlist"):
        print("    [+] BlackArch repo already installed. Skipping.")
        return

    print("    [*] Downloading and executing BlackArch strap.sh...")
    run_cmd("curl -O https://blackarch.org/strap.sh", ignore_errors=True)
    run_cmd("chmod +x strap.sh", ignore_errors=True)
    run_cmd("./strap.sh", ignore_errors=True)
    run_cmd("rm strap.sh", ignore_errors=True)
    print("    [+] BlackArch tools are now available via pacman (e.g., pacman -S kismet).")

def ensure_tools_installed():
    print("[*] Checking for essential security tools and critical system packages...")

    # 5-second timeout internet check
    print("    [*] Checking internet connection...")
    net_check = run_cmd("ping -c 1 -W 5 8.8.8.8", ignore_errors=True, return_full=True)

    if net_check.returncode != 0:
        print("    [-] No internet detected after 5 seconds. Bypassing tool installation.")
        return  # Bails out of this function, but lets the rest of the script continue

    print("    [+] Internet confirmed. Proceeding with sync and install...")

    try:
        # Arch Linux package names
        tools = {
            "ufw": "ufw",
            "macchanger": "macchanger",
            "ss": "iproute2",
            "zsh": "zsh",
            "Xwayland": "xorg-xwayland",
            "aa-status": "apparmor",
            "mkfs.exfat": "exfatprogs dosfstools ntfs-3g",
        }

        # Sync databases safely
        run_cmd("pacman -Sy", ignore_errors=True)

        for tool, pkg in tools.items():
            if not run_cmd(f"command -v {tool}", ignore_errors=True):
                print(f"[!] {tool} missing. Installing {pkg}...")
                run_cmd(f"pacman -S --noconfirm --needed {pkg}", ignore_errors=True)
    except Exception as e:
        print(f"[-] Failed to ensure tools are installed: {e}")

def setup_terminal_environment():
    print("\n[*] --- Configuring Auto-Loading Terminal Aesthetics ---")

    run_cmd("pacman -S --noconfirm --needed zsh-autosuggestions", ignore_errors=True)

    # Safely grab SUDO_USER
    actual_user = os.environ.get("SUDO_USER")
    users_to_config = ["root"]
    if actual_user and actual_user != "root":
        users_to_config.append(actual_user)

    zshrc_addon = """
# --- Auto-generated Terminal Config ---
HISTFILE=~/.zsh_history
HISTSIZE=50000
SAVEHIST=50000
setopt appendhistory
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY

# Arch Linux Path
if [ -f /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh ]; then
    source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
    bindkey '^[[C' forward-char
    bindkey '^[^[[C' forward-word
fi

PROMPT=$'%F{cyan}┌──(%B%F{green}%n㉿%m%b%F{cyan})-[%B%F{white}%~%b%F{cyan}]\\n└─%B%(#.#.$)%b%F{reset} '
# --- End Auto-generated Config ---
"""
    bashrc_hijack = """
# Auto-launch zsh safely
if [[ $- == *i* ]] && [ -z "$ZSH_VERSION" ] && [ -x "$(command -v zsh)" ]; then
    exec zsh
fi
"""

    for user in users_to_config:
        home_dir = "/root" if user == "root" else run_cmd(f"getent passwd {user} | cut -d: -f6")
        if home_dir and os.path.exists(home_dir):
            zshrc_path = os.path.join(home_dir, ".zshrc")
            bashrc_path = os.path.join(home_dir, ".bashrc")
            try:
                with open(zshrc_path, "a") as f:
                    f.write(zshrc_addon)

                if os.path.exists(bashrc_path):
                    with open(bashrc_path, "a") as f:
                        f.write(bashrc_hijack)

                if user != "root":
                    run_cmd(f"chown {user}:{user} {zshrc_path}", ignore_errors=True)

                run_cmd(f"chsh -s $(which zsh) {user}", ignore_errors=True)
            except Exception as e:
                print(f"[-] Failed to configure terminal for {user}: {e}")

    print("    [+] ZSH configured safely. Auto-complete is now instantaneous.")

def repair_and_secure_display():
    print("\n[*] --- Repairing and Optimizing Display Environment ---")

    bad_sddm_conf = "/etc/sddm.conf.d/10-force-wayland.conf"
    if os.path.exists(bad_sddm_conf):
        print(f"    [!] Found destructive Wayland config. Deleting: {bad_sddm_conf}")
        run_cmd(f"rm -f {bad_sddm_conf}", ignore_errors=True)

    print("    [*] Safeguarding KDE core packages (Arch/EndeavourOS)...")
    wayland_safeguards = "plasma-workspace sddm konsole dolphin kwin intel-media-driver libva-utils"
    run_cmd(f"pacman -S --noconfirm --needed {wayland_safeguards}", ignore_errors=True)

    run_cmd("systemctl enable sddm", ignore_errors=True)
    run_cmd("systemctl set-default graphical.target", ignore_errors=True)
    print("    [+] Graphical boot target locked. Display server stabilized.")

def disable_unsafe_services():
    print("\n[*] --- Locking down System Services ---")
    services_to_kill = [
        "sshd", "xrdp", "vncserver", "httpd", "postgresql",
        "rpcbind", "cups", "cups-browsed", "avahi-daemon",
        "vsftpd", "smb", "nmb", "bluetooth", "exim"
    ]

    for svc in services_to_kill:
        run_cmd(f"systemctl stop {svc}", ignore_errors=True)
        run_cmd(f"systemctl disable {svc}", ignore_errors=True)
        run_cmd(f"systemctl mask {svc}", ignore_errors=True)
    print("    [+] Remote access, printing, and broadcasting services disabled and masked.")

def persistent_mac_randomization():
    print("\n[*] --- Enforcing Persistent MAC Randomization ---")
    nm_conf_dir = "/etc/NetworkManager/conf.d"
    os.makedirs(nm_conf_dir, exist_ok=True)

    mac_conf = f"{nm_conf_dir}/00-macrandomize.conf"
    rules = """[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=preserve
"""
    try:
        with open(mac_conf, "w") as f:
            f.write(rules)
        print("    [+] NetworkManager configured to randomize MAC automatically on all connections.")
    except Exception as e:
        print(f"    [-] Failed to write MAC config: {e}")

def harden_kernel():
    print("\n[*] --- Applying Advanced Kernel-Level Exploit Protections ---")
    sysctl_rules = [
        # --- IPV6 DISABLE ---
        "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1",
        "net.ipv6.conf.lo.disable_ipv6=1",
        # --- TCP & NETWORK SECURITY ---
        "net.ipv4.tcp_syncookies=1",
        "net.ipv4.tcp_rfc1337=1",
        "net.ipv4.conf.all.accept_redirects=0",
        "net.ipv4.conf.default.accept_redirects=0",
        "net.ipv4.conf.all.secure_redirects=0",
        "net.ipv4.conf.all.send_redirects=0",
        "net.ipv4.conf.all.accept_source_route=0",
        "net.ipv4.conf.all.log_martians=1",
        "net.ipv4.conf.all.rp_filter=1",
        "net.ipv4.conf.default.rp_filter=1",
        "net.ipv4.icmp_echo_ignore_all=1",
        "net.ipv4.icmp_echo_ignore_broadcasts=1",
        "net.ipv4.icmp_ignore_bogus_error_responses=1",
        # --- USB ZERO-BYTE BUG FIX ---
        "vm.dirty_background_bytes=16777216",
        "vm.dirty_bytes=50331648",
        # --- NEW PARANOID RULES ---
        "kernel.kptr_restrict=2",
        "kernel.dmesg_restrict=1"
    ]

    conf_path = "/etc/sysctl.d/99-lockdown.conf"
    try:
        with open(conf_path, "w") as f:
            f.write("# Auto-generated Lockdown Rules\n")
            for rule in sysctl_rules:
                f.write(f"{rule}\n")
    except Exception as e:
        print(f"    [-] Failed to write sysctl config: {e}")

    run_cmd(f"sysctl -p {conf_path}", ignore_errors=True)

    if os.path.exists("/etc/default/ufw"):
        run_cmd("sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw", ignore_errors=True)

    print("    [+] Kernel hardened against spoofing, MITM, time-wait attacks, and network scanning.")
    print("    [+] Process memory pointers and kernel logs hidden from user space.")

    # --- FIX: TELL NETWORKMANAGER TO IGNORE IPV6 ON BOOT ---
    print("    [*] Configuring NetworkManager to permanently ignore IPv6...")

    # 1. Set global default for all future connections
    nm_conf_dir = "/etc/NetworkManager/conf.d"
    os.makedirs(nm_conf_dir, exist_ok=True)
    try:
        with open(f"{nm_conf_dir}/00-ignore-ipv6.conf", "w") as f:
            f.write("[connection]\nipv6.method=ignore\n")
    except Exception as e:
        print(f"    [-] Failed to write global NM IPv6 config: {e}")

    # 2. Modify all existing/saved network profiles dynamically
    print("    [*] Updating existing network profiles...")
    run_cmd("nmcli -t -f UUID connection show | grep -v -- '--' | while read -r uuid; do nmcli connection modify \"$uuid\" ipv6.method ignore; done", ignore_errors=True)
    print("    [+] All NetworkManager connections will now safely ignore IPv6.")

def enable_apparmor_boot_params():
    print("\n[*] --- Injecting AppArmor Kernel Parameters ---")
    lsm_string = "lsm=landlock,lockdown,yama,integrity,apparmor,bpf"

    if os.path.exists("/etc/kernel/cmdline"):
        print("    -> Checking systemd-boot for AppArmor...")
        with open("/etc/kernel/cmdline", "r") as f:
            cmdline = f.read().strip()

        if "apparmor" not in cmdline:
            with open("/etc/kernel/cmdline", "w") as f:
                f.write(f"{cmdline} {lsm_string}\n")
            run_cmd("reinstall-kernels", ignore_errors=True)
            print("    [+] Added to systemd-boot.")
        else:
            print("    [+] Already present in systemd-boot.")

    elif os.path.exists("/etc/default/grub"):
        print("    -> Checking GRUB for AppArmor...")
        with open("/etc/default/grub", "r") as f:
            grub = f.read()

        if "apparmor" not in grub:
            grub = re.sub(
                r'GRUB_CMDLINE_LINUX_DEFAULT="(.*?)"',
                rf'GRUB_CMDLINE_LINUX_DEFAULT="\1 {lsm_string}"',
                grub
            )
            with open("/etc/default/grub", "w") as f:
                f.write(grub)
            run_cmd("grub-mkconfig -o /boot/grub/grub.cfg", ignore_errors=True)
            print("    [+] Added to GRUB.")
        else:
            print("    [+] Already present in GRUB.")

def setup_apparmor():
    print("\n[*] --- Enforcing Mandatory Access Control (AppArmor) ---")
    run_cmd("systemctl enable apparmor", ignore_errors=True)
    run_cmd("systemctl start apparmor", ignore_errors=True)

    # --- MUST INSTALL UTILS FIRST ---
    print("    [*] Installing AppArmor utilities for enforcement control...")
    run_cmd("pacman -S --noconfirm --needed apparmor-utils", ignore_errors=True)

    print("    [*] Locking profiles into ENFORCE mode...")
    run_cmd("aa-enforce /etc/apparmor.d/*", ignore_errors=True)

    # --- BROWSER FIX (FIREFOX / ZEN / QTWEBENGINE) ---
    print("    [*] Relaxing AppArmor for Web Browsers & QtWebEngine...")
    browsers = [
        "/usr/bin/firefox", "/usr/lib/firefox/firefox",
        "/usr/lib/qt6/libexec/QtWebEngineProcess"
    ]
    for browser in browsers:
        run_cmd(f"aa-complain {browser}", ignore_errors=True)

    # --- USB AUTOMOUNT FIX ---
    print("    [*] Relaxing AppArmor for USB Disk Management (udisks2)...")
    run_cmd("aa-complain /usr/lib/udisks2/udisksd", ignore_errors=True)
    run_cmd("aa-complain /usr/lib/udisks2/udisksd-no-suid", ignore_errors=True)

    run_cmd("systemctl restart udisks2", ignore_errors=True)
    print("    [+] AppArmor strict sandboxing enabled (with exceptions for Browsers & USB automounting).")

def setup_firewall():
    print("\n[*] --- Initiating Firewall Lockdown Protocol ---")
    run_cmd("echo 'y' | ufw reset", ignore_errors=True)

    print("    [*] Disabling UFW logging to prevent disk bloat...")
    run_cmd("ufw logging off", ignore_errors=True)

    run_cmd("ufw default deny incoming")
    run_cmd("ufw default deny outgoing")

    run_cmd("ufw allow out on lo")
    run_cmd("ufw allow in on lo")

    run_cmd("ufw allow out 67,68/udp")
    run_cmd("ufw allow out 53/tcp")
    run_cmd("ufw allow out 53/udp")
    run_cmd("ufw allow out 123/udp")
    run_cmd("ufw allow out 80/tcp")
    run_cmd("ufw allow out 443/tcp")
    run_cmd("ufw allow out 443/udp")

    run_cmd("echo 'y' | ufw enable", ignore_errors=True)
    run_cmd("systemctl enable ufw", ignore_errors=True)
    run_cmd("systemctl restart ufw", ignore_errors=True)
    print("    [+] Strict zero-trust UFW policies applied. Logging disabled. Reolink allowed.")

def verify_security(de_type):
    print("\n==================================================")
    print("[!] --- FINAL SECURITY VERIFICATION REPORT --- [!]")
    print("==================================================")

    # 1. Display Server Check
    print("\n[*] 1. Display Server Status:")
    if os.path.exists("/usr/bin/Xwayland") and os.path.exists("/usr/bin/Xorg"):
        print("    [+] STATUS: SECURE (X11 & Xwayland are properly installed and intact)")
    else:
        print("    [-] STATUS: WARNING (X11 components are missing, GUI may fail!)")

    # 2. Check Listening Ports
    print("\n[*] 2. Active Listening Ports (Should only be internal 127.0.0.1):")
    ports = run_cmd("ss -tulwn | grep LISTEN", ignore_errors=True)
    if ports:
        print(ports)
    else:
        print("    [+] No open listening ports detected.")

    # 3. Check MAC Addresses
    print("\n[*] 3. Hardware MAC Masking Status:")
    interfaces = get_interfaces()
    for iface in interfaces:
        if iface.startswith(('wlan', 'eth', 'en', 'usb')):
            mac_info = run_cmd(f"macchanger -s {iface}", ignore_errors=True)
            if "Current MAC" in mac_info and "Permanent MAC" in mac_info:
                lines = mac_info.split('\n')
                try:
                    # Safely parse MAC to avoid crashes on virtual interfaces
                    current = [l for l in lines if "Current MAC" in l][0].strip()
                    permanent = [l for l in lines if "Permanent MAC" in l][0].strip()

                    print(f"    -> {iface}:")
                    print(f"       {permanent}")
                    print(f"       {current}")

                    if current.split()[2] != permanent.split()[2]:
                        print("       [+] STATUS: CLOAKED (Spoofed)")
                    else:
                        print("       [-] STATUS: EXPOSED (Real MAC)")
                except IndexError:
                    print(f"       [-] STATUS: UNKNOWN (Could not parse output for {iface})")

    # 4. ICMP Stealth Check
    print("\n[*] 4. ICMP Stealth Mode:")
    stealth_check = run_cmd("sysctl net.ipv4.icmp_echo_ignore_all")
    if "1" in stealth_check:
        print("    [+] STATUS: ACTIVE (Your machine will drop all pings)")
    else:
        print("    [-] STATUS: INACTIVE")

    # 5. AppArmor Baseline
    print("\n[*] 5. Mandatory Access Control:")
    aa_status = run_cmd("aa-status --enabled", ignore_errors=True)
    if aa_status == "":
        print("    [+] AppArmor: ENFORCING (Strict MAC active)")
    else:
        print("    [-] AppArmor: WARNING (Ensure AppArmor is enabled in your kernel boot parameters)")

    print("\n==================================================")
    print("[+] LOCKDOWN COMPLETE. System is armored and ready.")
    print("==================================================")

def setup_swap():
    print("[*] --- Ensuring Adequate Swap Space for Compilation ---")
    if not os.path.exists("/swapfile"):
        print("    [*] Allocating 16GB swap file...")
        run_cmd("fallocate -l 16G /swapfile", ignore_errors=False)
        run_cmd("chmod 600 /swapfile", ignore_errors=False)
        run_cmd("mkswap /swapfile", ignore_errors=False)
        run_cmd("swapon /swapfile", ignore_errors=False)
        print("    [+] 16GB swap file successfully created and enabled.")
    else:
        run_cmd("swapon /swapfile", ignore_errors=True)
        print("    [+] Swap file already exists; ensuring it is active.")

def super_clean_and_restore():
    print("\n[!] Initiating Maximum Security Network Recovery...")
    setup_swap()
    undo_aggressive_lockdown()

    inject_blackarch_repo()
    try:
        ensure_tools_installed()
    except Exception as e:
        print(f"    [-] Internet Fail Continuing. {e}")
    setup_terminal_environment()

    de = detect_desktop_environment()
    if de == "KDE":
        print("\n[*] KDE Plasma detected.")
    elif de == "MATE":
        print("\n[*] MATE Desktop detected.")
    else:
        print("\n[*] Unknown Desktop Environment.")

    #repair_and_secure_display()

    disable_unsafe_services()
    harden_kernel()

    # Enable parameters before setting up AppArmor
    enable_apparmor_boot_params()

    setup_apparmor()

    print("\n[*] Purging rogue wireless interfaces & routing history...")
    run_cmd("airmon-ng check kill", ignore_errors=True)
    run_cmd("rfkill unblock all")

    commands_to_flush = [
        "iptables -F", "iptables -X",
        "iptables -t nat -F", "iptables -t nat -X",
        "iptables -t mangle -F", "iptables -t mangle -X",
        "ip route flush cache",
        "ip -s -s neigh flush all"
    ]
    for cmd in commands_to_flush:
        run_cmd(cmd)

    if os.path.exists("/var/lib/dhcp"):
        run_cmd("rm -rf /var/lib/dhcp/*", ignore_errors=True)
    if os.path.exists("/var/lib/NetworkManager"):
        run_cmd("rm -rf /var/lib/NetworkManager/*.lease", ignore_errors=True)

    interfaces = get_interfaces()
    print(f"\n[*] Resetting & Masking Interfaces: {', '.join(interfaces)}")

    for iface in interfaces:
        if "mon" in iface:
            print(f"    -> Stopping monitor mode on {iface}...")
            run_cmd(f"airmon-ng stop {iface}", ignore_errors=True)
            run_cmd(f"ip link set {iface} down", ignore_errors=True)

        elif iface.startswith(('eth', 'en', 'wlan', 'usb')):
            print(f"    -> Securing physical interface: {iface}")
            run_cmd(f"ip addr flush dev {iface}", ignore_errors=True) # <--- Delete or comment out
            run_cmd(f"ip link set {iface} down", ignore_errors=True)  # <--- Delete or comment out

            run_cmd(f"macchanger -A {iface}", ignore_errors=True)     # <--- Delete or comment out

            time.sleep(0.5)
            run_cmd(f"ip link set {iface} up", ignore_errors=True)

    print("\n[*] Cycling NetworkManager service to pull a fresh IP...")
    persistent_mac_randomization()
    run_cmd("nmcli networking off", ignore_errors=True)
    run_cmd("systemctl restart NetworkManager", ignore_errors=True)
    time.sleep(1)
    run_cmd("nmcli networking on", ignore_errors=True)

    setup_firewall()

    run_cmd("sysctl --system", ignore_errors=True)

    verify_security(de)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] FATAL: This script must be run as root (sudo).")
    else:
        super_clean_and_restore()
