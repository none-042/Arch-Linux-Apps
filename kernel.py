#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import re
import getpass
import time

# ANSI Color Codes for clean visual formatting
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_CYAN   = "\033[1;36m"
C_GREEN  = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED    = "\033[1;31m"
C_BLUE   = "\033[1;34m"

TOTAL_STEPS = 10

def print_banner():
    print(f"\n{C_CYAN}╔══════════════════════════════════════════════════════════════════════╗{C_RESET}")
    print(f"{C_CYAN}║{C_RESET} {C_BOLD}EndeavourOS: Kernel + Full NVIDIA Stack + Secure Boot Setup{C_RESET}       {C_CYAN}║{C_RESET}")
    print(f"{C_CYAN}╚══════════════════════════════════════════════════════════════════════╝{C_RESET}\n")

def show_progress(step, total, title):
    """Renders a high-visibility horizontal progress bar in the terminal."""
    bar_length = 32
    filled_length = int(round(bar_length * step / float(total)))
    percent = round(100.0 * step / float(total), 1)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)

    print(f"\n{C_CYAN}┌──────────────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_CYAN}│{C_RESET} {C_GREEN}[{bar}] {percent:>5.1f}%{C_RESET}  {C_BOLD}(Step {step}/{total}){C_RESET}")
    print(f"{C_CYAN}│{C_RESET} {C_YELLOW}» {title}{C_RESET}")
    print(f"{C_CYAN}└──────────────────────────────────────────────────────────────────────┘{C_RESET}\n")
    time.sleep(0.3)

def run(cmd, ignore_errors=False):
    """Executes commands while streaming output live so pacman & build bars work."""
    print(f"{C_BLUE}[*] Executing:{C_RESET} {C_BOLD}{cmd}{C_RESET}")
    process = subprocess.run(cmd, shell=True)
    if process.returncode != 0:
        if not ignore_errors:
            print(f"{C_RED}[-] Error executing command: {cmd}{C_RESET}")
        return False
    return True

def setup_eos_nvidia_secureboot():
    if os.geteuid() != 0:
        sys.exit(f"{C_RED}[!] Please run this script as root: sudo python3 kernel.py{C_RESET}")

    print_banner()

    # Prompt user for kernel choice
    print(f"{C_CYAN}[?] KERNEL SELECTION{C_RESET}")
    while True:
        print("  [1] Linux Zen (Optimized for desktop responsiveness & gaming)")
        print("  [2] Linux Hardened (Optimized for security & memory protection)")
        choice = input(f"{C_BOLD}Enter 1 or 2: {C_RESET}").strip()

        if choice == '1':
            kernel_pkg = "linux-zen"
            kernel_name = "Zen"
            hook_suffix = "zen"
            break
        elif choice == '2':
            kernel_pkg = "linux-hardened"
            kernel_name = "Hardened"
            hook_suffix = "hardened"
            break
        print(f"{C_RED}Invalid choice. Please enter 1 or 2.{C_RESET}\n")

    # Prompt user for NVIDIA driver choice
    print(f"\n{C_CYAN}[?] GPU DRIVER SELECTION{C_RESET}")
    while True:
        print("  [1] Proprietary (Closed DKMS - Complete bundle for KDE Wayland)")
        print("  [2] Open (NVIDIA Open DKMS - Official open kernel modules)")
        print("  [3] Mesa (Nouveau/NVK - Fully open-source userspace & kernel)")
        driver_choice = input(f"{C_BOLD}Enter 1, 2, or 3: {C_RESET}").strip()

        nvidia_base_pkgs = "nvidia-utils lib32-nvidia-utils nvidia-settings opencl-nvidia lib32-opencl-nvidia egl-wayland"

        if driver_choice == '1':
            driver_pkgs = f"nvidia-dkms {nvidia_base_pkgs}"
            driver_name = "Proprietary NVIDIA DKMS Bundle"
            is_nouveau = False
            break
        elif driver_choice == '2':
            driver_pkgs = f"nvidia-open-dkms {nvidia_base_pkgs}"
            driver_name = "Open NVIDIA DKMS Bundle"
            is_nouveau = False
            break
        elif driver_choice == '3':
            driver_pkgs = "mesa lib32-mesa vulkan-nouveau lib32-vulkan-nouveau mesa-vdpau"
            driver_name = "Mesa (NVK/Nouveau)"
            is_nouveau = True
            break
        print(f"{C_RED}Invalid choice. Please enter 1, 2, or 3.{C_RESET}\n")

    # Prompt for MOK password securely
    print(f"\n{C_YELLOW}[!] SECURE BOOT MOK SETUP{C_RESET}")
    print("Create a one-time password for the blue MOK screen upon reboot.")
    while True:
        mok_pass = getpass.getpass(f"{C_BOLD}Enter new MOK password: {C_RESET}")
        mok_pass2 = getpass.getpass(f"{C_BOLD}Confirm MOK password: {C_RESET}")
        if mok_pass == mok_pass2 and len(mok_pass) > 0:
            break
        print(f"{C_RED}Passwords do not match or are empty. Try again.{C_RESET}\n")

    # =========================================================================
    # STEP 1: Clean Pacman Lock
    # =========================================================================
    show_progress(1, TOTAL_STEPS, "Checking and unlocking package manager database...")
    if os.path.exists("/var/lib/pacman/db.lck"):
        os.remove("/var/lib/pacman/db.lck")
        print(f"{C_GREEN}[+] Removed stale pacman lock file.{C_RESET}")
    else:
        print(f"{C_GREEN}[+] Pacman database is clean.{C_RESET}")

    # =========================================================================
    # STEP 2: Install Secure Boot Tools First
    # =========================================================================
    show_progress(2, TOTAL_STEPS, "Installing core Secure Boot and DKMS dependencies...")
    run("pacman -Syu --noconfirm --needed dkms openssl mokutil sbsigntools")

    if not shutil.which("mokutil"):
        print(f"\n{C_RED}[!] FATAL: mokutil failed to install. Check internet/mirrors.{C_RESET}")
        sys.exit(1)

    # =========================================================================
    # STEP 3: Generate Keys & Configure DKMS Signing
    # =========================================================================
    show_progress(3, TOTAL_STEPS, "Generating Machine Owner Keys (MOK) & setting up DKMS...")
    os.makedirs("/var/lib/dkms", exist_ok=True)

    run('openssl req -new -x509 -newkey rsa:2048 -keyout /var/lib/dkms/mok.key -out /var/lib/dkms/mok.pem -nodes -days 36500 -subj "/CN=EndeavourOS_MOK/"', ignore_errors=True)
    run('openssl x509 -in /var/lib/dkms/mok.pem -outform der -out /var/lib/dkms/mok.der', ignore_errors=True)
    run('openssl x509 -in /var/lib/dkms/mok.pem -out /var/lib/dkms/mok.pub', ignore_errors=True)

    dkms_conf = "/etc/dkms/framework.conf"
    if os.path.exists(dkms_conf):
        with open(dkms_conf, "r") as f:
            conf_data = f.read()
        if "mok.key" not in conf_data:
            with open(dkms_conf, "a") as f:
                f.write('\nmok_signing_key="/var/lib/dkms/mok.key"\n')
                f.write('mok_certificate="/var/lib/dkms/mok.pem"\n')
    print(f"{C_GREEN}[+] DKMS is now configured to automatically sign all compiled modules.{C_RESET}")

    # =========================================================================
    # STEP 4: Enroll MOK Key in Motherboard NVRAM
    # =========================================================================
    show_progress(4, TOTAL_STEPS, "Queuing MOK key for motherboard enrollment...")
    process = subprocess.Popen(
        ['mokutil', '--import', '/var/lib/dkms/mok.der'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    out, err = process.communicate(input=f"{mok_pass}\n{mok_pass}\n")
    if process.returncode == 0 or "already enrolled" in err:
        print(f"{C_GREEN}[+] MOK key successfully staged for next boot.{C_RESET}")

    # =========================================================================
    # STEP 5: Clean Conflicting GPU Drivers (No more red errors!)
    # =========================================================================
    show_progress(5, TOTAL_STEPS, "Purging existing GPU packages to prevent file conflicts...")

    print(f"{C_BLUE}[*] Temporarily neutralizing Dracut configs to prevent hook panics...{C_RESET}")
    run("rm -f /etc/dracut.conf.d/nvidia.conf /etc/dracut.conf.d/nouveau.conf", ignore_errors=True)

    bad_packages = [
        "nvidia", "nvidia-open", "nvidia-dkms", "nvidia-open-dkms",
        "nvidia-utils", "lib32-nvidia-utils", "nvidia-settings",
        "opencl-nvidia", "lib32-opencl-nvidia", "egl-wayland"
    ]
    if not is_nouveau:
        bad_packages.extend(["vulkan-nouveau", "lib32-vulkan-nouveau"])

    for pkg in bad_packages:
        # Silently check if the package is installed first
        is_installed = subprocess.run(f"pacman -Qq {pkg}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if is_installed.returncode == 0:
            # Package exists, uninstall it
            print(f"{C_YELLOW}[*] Found conflicting package '{pkg}'. Removing...{C_RESET}")
            run(f"pacman -Rdd --noconfirm {pkg}", ignore_errors=True)
        else:
            # Package doesn't exist, print a clean green status
            print(f"{C_GREEN}[+] '{pkg}' not found (already clean).{C_RESET}")

    # =========================================================================
    # STEP 6: Install Kernel & Driver Stack
    # =========================================================================
    show_progress(6, TOTAL_STEPS, f"Downloading & Installing {kernel_name} kernel and {driver_name}...")
    run(f"pacman -S --noconfirm --needed {kernel_pkg} {kernel_pkg}-headers {driver_pkgs}")

    # =========================================================================
    # STEP 7: Set up Kernel Auto-Signing Pacman Hook
    # =========================================================================
    show_progress(7, TOTAL_STEPS, f"Configuring auto-signing pacman hook for {kernel_name}...")
    os.makedirs("/etc/pacman.d/hooks", exist_ok=True)

    hook_content = (
        "[Trigger]\n"
        "Operation = Install\n"
        "Operation = Upgrade\n"
        "Type = Package\n"
        f"Target = {kernel_pkg}\n\n"
        "[Action]\n"
        f"Description = Signing Linux-{kernel_name} kernel for Secure Boot...\n"
        "When = PostTransaction\n"
        f"Exec = /usr/bin/sbsign --key /var/lib/dkms/mok.key --cert /var/lib/dkms/mok.pem --output /boot/vmlinuz-{kernel_pkg} /boot/vmlinuz-{kernel_pkg}\n"
    )

    with open(f"/etc/pacman.d/hooks/75-secureboot-{hook_suffix}.hook", "w") as f:
        f.write(hook_content)

    if os.path.exists(f"/boot/vmlinuz-{kernel_pkg}"):
        run(f'sbsign --key /var/lib/dkms/mok.key --cert /var/lib/dkms/mok.pem --output /boot/vmlinuz-{kernel_pkg} /boot/vmlinuz-{kernel_pkg}')

    # =========================================================================
    # STEP 8: Configure Dracut, Modprobe & KDE Wayland Optimizations
    # =========================================================================
    show_progress(8, TOTAL_STEPS, "Applying Dracut KMS, Modprobe & Wayland power management...")
    os.makedirs("/etc/dracut.conf.d", exist_ok=True)
    os.makedirs("/etc/modprobe.d", exist_ok=True)

    if is_nouveau:
        dracut_drivers = 'force_drivers+=" nouveau "\n'
        run("rm -f /etc/modprobe.d/nvidia.conf /etc/modprobe.d/nvidia-power-management.conf /etc/modprobe.d/blacklist-nouveau.conf", ignore_errors=True)
        run("systemctl disable nvidia-suspend nvidia-hibernate nvidia-resume", ignore_errors=True)
    else:
        dracut_drivers = 'force_drivers+=" nvidia nvidia_modeset nvidia_uvm nvidia_drm "\n'

        with open("/etc/modprobe.d/nvidia-power-management.conf", "w") as f:
            f.write("options nvidia NVreg_PreserveVideoMemoryAllocations=1\n")
            f.write("options nvidia NVreg_TemporaryFilePath=/var/tmp\n")

        with open("/etc/modprobe.d/blacklist-nouveau.conf", "w") as f:
            f.write("blacklist nouveau\n")
            f.write("options nouveau modeset=0\n")

        run("systemctl enable nvidia-suspend nvidia-hibernate nvidia-resume", ignore_errors=True)

    with open("/etc/dracut.conf.d/nvidia.conf", "w") as f:
        f.write(dracut_drivers)

    # =========================================================================
    # STEP 9: Inject Kernel Parameters (systemd-boot & GRUB)
    # =========================================================================
    show_progress(9, TOTAL_STEPS, "Injecting DRM kernel parameters into bootloader...")

    uses_systemd_boot = os.path.exists("/etc/kernel/cmdline")
    uses_grub = os.path.exists("/etc/default/grub")

    if uses_systemd_boot:
        with open("/etc/kernel/cmdline", "r") as f:
            cmdline = f.read().strip()

        cmdline = re.sub(r'\bnvidia_drm\.modeset=1\b', '', cmdline)
        cmdline = re.sub(r'\bnvidia_drm\.fbdev=1\b', '', cmdline)
        cmdline = re.sub(r'\bnouveau\.config=NvGspRm=1\b', '', cmdline)

        if is_nouveau:
            cmdline += " nouveau.config=NvGspRm=1"
        else:
            cmdline += " nvidia_drm.modeset=1 nvidia_drm.fbdev=1"

        cmdline = " ".join(cmdline.split())
        with open("/etc/kernel/cmdline", "w") as f:
            f.write(cmdline + "\n")

    if uses_grub:
        with open("/etc/default/grub", "r") as f:
            grub = f.read()

        match = re.search(r'^GRUB_CMDLINE_LINUX_DEFAULT="(.*?)"', grub, re.MULTILINE)
        if match:
            new_params = match.group(1)
            new_params = re.sub(r'\bnvidia_drm\.modeset=1\b', '', new_params)
            new_params = re.sub(r'\bnvidia_drm\.fbdev=1\b', '', new_params)
            new_params = re.sub(r'\bnouveau\.config=NvGspRm=1\b', '', new_params)

            if is_nouveau:
                new_params += " nouveau.config=NvGspRm=1"
            else:
                new_params += " nvidia_drm.modeset=1 nvidia_drm.fbdev=1"

            new_params = " ".join(new_params.split())
            grub = re.sub(r'^GRUB_CMDLINE_LINUX_DEFAULT=".*?"', f'GRUB_CMDLINE_LINUX_DEFAULT="{new_params}"', grub, flags=re.MULTILINE)
            with open("/etc/default/grub", "w") as f:
                f.write(grub)
            run("grub-mkconfig -o /boot/grub/grub.cfg")

    # =========================================================================
    # STEP 10: Rebuild Initramfs via Dracut / kernel-install
    # =========================================================================
    show_progress(10, TOTAL_STEPS, f"Rebuilding initramfs and syncing bootloader...")

    if uses_systemd_boot and os.path.exists("/usr/bin/reinstall-kernels"):
        run("reinstall-kernels")
    elif uses_grub and shutil.which("dracut-rebuild"):
        run("dracut-rebuild")
    else:
        run("dracut --regenerate-all --force")

    # =========================================================================
    # COMPLETE
    # =========================================================================
    print(f"\n{C_GREEN}╔══════════════════════════════════════════════════════════════════════╗{C_RESET}")
    print(f"{C_GREEN}║{C_RESET} {C_BOLD}[✓] Installation Complete! All drivers and keys configured.{C_RESET}        {C_GREEN}║{C_RESET}")
    print(f"{C_GREEN}╚══════════════════════════════════════════════════════════════════════╝{C_RESET}")

    print(f"\n{C_YELLOW}[!] REQUIRED REBOOT INSTRUCTIONS (MOK ENROLLMENT):{C_RESET}")
    print("  1. Reboot your system.")
    print("  2. When the blue MOK screen appears, hit any key.")
    print("  3. Select 'Enroll MOK'.")
    print("  4. Select 'Continue' -> 'Yes'.")
    print("  5. Type the MOK password you entered in this script and press Enter.")
    print("  6. Select 'Reboot' and boot normally into KDE.\n")

if __name__ == "__main__":
    setup_eos_nvidia_secureboot()
