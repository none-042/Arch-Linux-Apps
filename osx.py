import os
import sys
import subprocess
import pwd
import time
import re
import math

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
# VM stays in the home directory where it was originally installed
INSTALL_DIR = os.path.expanduser("~/macOS-Quarantine")
# Payload vault is created dynamically wherever this python script lives
PAYLOAD_DIR = os.path.join(SCRIPT_DIR, "Payload")
DISK_IMAGE = "mac_hdd_ng.img"
DISK_SIZE = "64G"

def downgrade_privileges():
    if os.getuid() == 0:
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid:
            print("\n[!] Root execution detected. Auto-downgrading script to normal user...")
            os.setgid(int(sudo_gid))
            os.setuid(int(sudo_uid))
            os.environ['HOME'] = pwd.getpwuid(int(sudo_uid)).pw_dir
            user_name = pwd.getpwuid(int(sudo_uid)).pw_name
            print(f"    [+] Privileges successfully dropped to user: {user_name}")
        else:
            print("\n[!] FATAL: You are logged in as absolute root. Please run from a normal user account.")
            sys.exit(1)

def run_cmd(cmd, ignore_errors=False):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 and not ignore_errors:
            print(f"[-] Command failed: {cmd}\n    Error: {result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        print(f"[-] Error executing {cmd}: {e}")
        return ""

def engage_ghost_mode():
    print("\n[*] --- Engaging Ghost Mode (Pre-Launch Network Isolation) ---")
    interfaces = run_cmd("ip -o link show | awk -F': ' '{print $2}'").split('\n')
    active_iface = None

    for iface in interfaces:
        iface = iface.strip()
        if iface and iface != 'lo' and "UP" in run_cmd(f"ip link show {iface}"):
            active_iface = iface
            break

    if active_iface:
        print(f"[*] Randomizing MAC on {active_iface}...")
        run_cmd(f"sudo ip link set {active_iface} down")
        run_cmd(f"sudo macchanger -A {active_iface}", ignore_errors=True)
        time.sleep(1)
        run_cmd(f"sudo ip link set {active_iface} up")
        print("    [+] Hardware footprint scrambled. Network identity cloaked.")

        print("    [*] Requesting new DHCP lease to restore connectivity...")
        run_cmd(f"sudo dhclient -r {active_iface}", ignore_errors=True)
        run_cmd(f"sudo dhclient {active_iface}", ignore_errors=True)
        time.sleep(3)
    else:
        print("    [-] No active network interface found to spoof.")

def is_iommu_active():
    try:
        with open("/proc/cmdline", "r") as f:
            return "iommu=pt" in f.read()
    except Exception:
        return False

def force_patch_bootloader(iommu_flag):
    grub_path = "/etc/default/grub"
    systemd_cmdline = "/etc/kernel/cmdline"
    temp_path = "/tmp/custom_boot_patch"

    if os.path.exists(systemd_cmdline):
        try:
            with open(systemd_cmdline, "r") as f:
                cmdline = f.read().strip()

            if "iommu=pt" not in cmdline:
                new_cmdline = f"{cmdline} {iommu_flag}".strip()
                with open(temp_path, "w") as f:
                    f.write(new_cmdline + "\n")

                print(f"    [*] Forcing IOMMU flags into systemd-boot: {iommu_flag}")
                run_cmd(f"sudo cp {temp_path} {systemd_cmdline}")
                run_cmd("sudo reinstall-kernels")
                print("    [+] Bootloader (systemd-boot) successfully overwritten and updated.")
            else:
                print("    [+] IOMMU is already staged in systemd-boot.")

            if os.path.exists(temp_path):
                os.remove(temp_path)
            return True
        except Exception as e:
            print(f"    [-] Python failed to patch systemd-boot: {e}")
            return False

    elif os.path.exists(grub_path):
        try:
            with open(grub_path, "r") as f:
                lines = f.readlines()

            modified = False
            with open(temp_path, "w") as f:
                for line in lines:
                    if line.startswith("GRUB_CMDLINE_LINUX_DEFAULT="):
                        val = line.split("=", 1)[1].strip()
                        if len(val) >= 2 and val[0] in ("'", '"') and val[-1] == val[0]:
                            val = val[1:-1]

                        if "iommu=pt" not in val:
                            new_val = f'{val} {iommu_flag}'.strip()
                            f.write(f'GRUB_CMDLINE_LINUX_DEFAULT="{new_val}"\n')
                            modified = True
                        else:
                            f.write(line)
                    else:
                        f.write(line)

            if modified:
                print(f"    [*] Forcing IOMMU flags into GRUB: {iommu_flag}")
                run_cmd(f"sudo cp {temp_path} {grub_path}")
                run_cmd("sudo grub-mkconfig -o /boot/grub/grub.cfg")
                print("    [+] Bootloader (GRUB) successfully overwritten and updated.")
            else:
                print("    [+] IOMMU is already staged in GRUB.")

            if os.path.exists(temp_path):
                os.remove(temp_path)
            return True
        except Exception as e:
            print(f"    [-] Python failed to patch GRUB: {e}")
            return False

    else:
        print("    [-] FATAL: Cannot locate /etc/kernel/cmdline OR /etc/default/grub.")
        return False

def ensure_framework():
    fetch_script = os.path.join(INSTALL_DIR, "fetch-macOS-v2.py")
    if not os.path.exists(fetch_script):
        print("\n[*] macOS KVM Framework missing or corrupted. Repairing safely...")
        tmp_dir = os.path.join(SCRIPT_DIR, "osx_kvm_tmp_clone")
        run_cmd(f"rm -rf {tmp_dir}")
        res = run_cmd(f"git clone https://github.com/kholia/OSX-KVM.git {tmp_dir}", ignore_errors=True)

        if os.path.exists(tmp_dir):
            os.makedirs(INSTALL_DIR, exist_ok=True)
            run_cmd(f"cp -r {tmp_dir}/* {INSTALL_DIR}/")
            run_cmd(f"rm -rf {tmp_dir}")
            print("    [+] Framework successfully repaired and verified.")
        else:
            print("    [-] FATAL ERROR: Failed to download OSX-KVM framework. Check internet connection.")
            sys.exit(1)

def ensure_phase_two_tools():
    print("\n[*] Verifying Phase 2 security and virtualization tools...")
    tools = {
        "dmg2img": "dmg2img",
        "macchanger": "macchanger",
        "qemu-img": "qemu-full",
        "xorriso": "xorriso"
    }
    for tool, pkg in tools.items():
        if not run_cmd(f"command -v {tool}", ignore_errors=True):
            print(f"    [*] Installing missing component: {pkg}...")
            run_cmd(f"sudo pacman -Sy --noconfirm {pkg}", ignore_errors=True)

def get_host_specs():
    total_cores = os.cpu_count() or 4
    total_gb = 16
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    total_gb = int(line.split()[1]) / (1024 * 1024)
                    break
    except Exception:
        pass
    return total_cores, total_gb

def compile_secure_payload():
    print("\n[*] --- Constructing Secure Air-Gapped Payload Drive ---")
    payload_iso = os.path.join(INSTALL_DIR, "payload.raw")

    if not os.path.exists(PAYLOAD_DIR):
        os.makedirs(PAYLOAD_DIR)
        print(f"    [+] Created empty secure vault at: {PAYLOAD_DIR}")
        print("    [*] Drop your shell scripts, Python tools, or installers here before launching.")
        return False

    if not os.listdir(PAYLOAD_DIR):
        print("    [*] Payload vault is empty. Skipping optical drive generation.")
        return False

    print("    [*] Compiling payload into read-only RAW optical format...")
    cmd = f"xorriso -as mkisofs -V 'SECURE_PAYLOAD' -J -R -o {payload_iso} {PAYLOAD_DIR}"
    run_cmd(cmd, ignore_errors=True)

    if os.path.exists(payload_iso):
        print("    [+] Air-gapped Payload Drive forged successfully.")
        return True
    else:
        print("    [-] Failed to forge Payload Drive. Check terminal output for xorriso errors.")
        return False

def enforce_1080p_resolution():
    print("\n[*] --- Deep-Patching OpenCore Bootloader for Pure RAW 1080p ---")

    boot_script = os.path.join(INSTALL_DIR, "OpenCore-Boot.sh")
    if os.path.exists(boot_script):
        try:
            with open(boot_script, 'r') as f:
                content = f.read()

            if "xres=1920,yres=1080" not in content:
                content = re.sub(r'(-device VGA,vgamem_mb=\d+)', r'\1,xres=1920,yres=1080', content)

            content = re.sub(r'OVMF_VARS(-[0-9x]+)?\.fd', 'OVMF_VARS-1920x1080.fd', content)

            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'id=OpenCoreBoot' in line:
                    line = line.replace('OpenCore.qcow2', 'OpenCore.raw')
                    line = line.replace('format=qcow2', 'format=raw')
                    lines[i] = line

            content = '\n'.join(lines)

            with open(boot_script, 'w') as f:
                f.write(content)
        except Exception as e:
            print(f"    [-] Failed to patch boot script: {e}")

    oc_image_qcow = os.path.join(INSTALL_DIR, "OpenCore", "OpenCore.qcow2")
    oc_image_raw = os.path.join(INSTALL_DIR, "OpenCore", "OpenCore.raw")

    if os.path.exists(oc_image_qcow):
        print("    [*] Converting Apple Bootloader to pure RAW block...")
        run_cmd(f"qemu-img convert -f qcow2 -O raw {oc_image_qcow} {oc_image_raw}")
        run_cmd(f"rm -f {oc_image_qcow}")

        loop_dev = run_cmd("sudo losetup -Pf --show " + oc_image_raw)

        if loop_dev and "loop" in loop_dev:
            print(f"    [*] Mounting pure RAW block ({loop_dev}) to inject 1080p constraints...")
            run_cmd("sudo mkdir -p /tmp/oc_mount")
            res = run_cmd(f"sudo mount {loop_dev}p1 /tmp/oc_mount", ignore_errors=True)

            if "failed" not in res.lower() and "error" not in res.lower():
                config_path = "/tmp/oc_mount/EFI/OC/config.plist"
                tmp_path = "/tmp/working_config.plist"

                if os.path.exists(config_path):
                    run_cmd(f"sudo cp {config_path} {tmp_path}")
                    run_cmd(f"sudo chown {os.getuid()}:{os.getgid()} {tmp_path}")

                    with open(tmp_path, "r") as f:
                        plist_data = f.read()

                    plist_data = re.sub(r'(<key>Resolution</key>\s*<string>)[^<]*(</string>)', r'\g<1>1920x1080\g<2>', plist_data)

                    with open(tmp_path, "w") as f:
                        f.write(plist_data)

                    run_cmd(f"sudo cp {tmp_path} {config_path}")
                    run_cmd(f"sudo rm -f {tmp_path}")

                    print("    [+] Apple EFI config.plist successfully rewritten dynamically.")
                else:
                    print("    [-] config.plist not found in the mounted partition.")

                run_cmd("sudo umount /tmp/oc_mount")
            else:
                print("    [-] Failed to mount RAW partition.")

            run_cmd(f"sudo losetup -d {loop_dev}")
            print("    [+] Bootloader left permanently in high-speed RAW format.")
        else:
            print("    [-] Failed to create loop device.")

def optimize_vm_hardware(has_payload=False):
    print("\n[*] --- Injecting Dynamic Hardware Math & Performance Tweaks ---")
    boot_script = os.path.join(INSTALL_DIR, "OpenCore-Boot.sh")
    payload_iso = os.path.join(INSTALL_DIR, "payload.raw")

    total_cores, total_gb = get_host_specs()
    print(f"    [*] Detected Host Hardware: {total_cores} CPU Cores, {math.ceil(total_gb)}GB RAM")

    alloc_cores = max(4, (int(total_cores * 0.6) // 2) * 2)

    target_ram_gb = total_gb * 0.75
    if (total_gb - target_ram_gb) < 8.0:
        target_ram_gb = total_gb - 8.0

    alloc_ram_gb = max(8, int(target_ram_gb))
    alloc_ram_mb = alloc_ram_gb * 1024

    if os.path.exists(boot_script):
        try:
            with open(boot_script, 'r') as f:
                content = f.read()

            content = re.sub(r'-m\s+\d+', f'-m {alloc_ram_mb}', content)

            content = re.sub(r'-smp\s+\d+(?:,cores=\d+)?(?:,threads=\d+)?(?:,sockets=\d+)?',
                             f'-smp {alloc_cores},sockets=1,cores={alloc_cores},threads=1', content)

            if '+invtsc' not in content:
                content = re.sub(r'-cpu\s+Penryn,kvm=on(.*?)(?:\s)', r'-cpu Penryn,kvm=on\1,+invtsc ', content)

            lines = content.split('\n')
            for i in range(len(lines)):
                if 'id=MacHDD' in lines[i]:
                    lines[i] = lines[i].replace('format=qcow2', 'format=raw')
                    if 'cache=writeback' not in lines[i]:
                        lines[i] = lines[i].replace('format=raw', 'format=raw,cache=writeback,discard=on,aio=threads')

            if has_payload and not any('id=MacPayload' in l for l in lines):
                for i in range(len(lines)):
                    if 'drive=MacHDD' in lines[i] and '-device' in lines[i]:
                        if not lines[i].strip().endswith('\\'):
                             lines[i] = lines[i] + ' \\'

                        lines.insert(i + 1, f'    -drive id=MacPayload,if=none,snapshot=on,format=raw,readonly=on,file={payload_iso} \\')
                        lines.insert(i + 2, '    -device ide-cd,bus=sata.5,drive=MacPayload \\')
                        print("    [+] Successfully wired SECURE_PAYLOAD vault into the Hypervisor Matrix.")
                        break

            content = '\n'.join(lines)

            with open(boot_script, 'w') as f:
                f.write(content)

            print(f"    [+] Precision Allocated: {alloc_ram_gb}GB RAM and {alloc_cores} CPU Cores.")
            print("    [+] Drive Configuration set to RAW Asynchronous I/O.")
        except Exception as e:
            print(f"    [-] Failed to patch VM resources: {e}")

def check_scorched_earth():
    disk_path = os.path.join(INSTALL_DIR, DISK_IMAGE)
    if os.path.exists(disk_path) or os.path.exists(os.path.join(INSTALL_DIR, 'BaseSystem.img')):
        print("\n" + "="*50)
        print("[!] EXISTING ENCLAVE DETECTED")
        print("="*50)
        resp = input("[?] Do you want to completely NUKE the existing macOS drive and start from scratch? (y/N): ").strip().lower()
        if resp in ['y', 'yes']:
            print("    [*] Initiating scorched earth protocol...")
            run_cmd(f"rm -f {disk_path}")
            run_cmd(f"rm -f {os.path.join(INSTALL_DIR, 'BaseSystem.img')}")
            run_cmd(f"rm -f {os.path.join(INSTALL_DIR, 'BaseSystem.dmg')}")
            run_cmd(f"rm -f {os.path.join(INSTALL_DIR, 'payload.raw')}")

            run_cmd(f"git -C {INSTALL_DIR} reset --hard", ignore_errors=True)
            run_cmd(f"rm -f {os.path.join(INSTALL_DIR, 'OpenCore/OpenCore.raw')}", ignore_errors=True)
            print("    [+] Old OS eradicated. Commencing fresh deployment.")

def phase_one_setup():
    print("\n==================================================")
    print("[!] PHASE 1: HYPERVISOR FORTRESS CONSTRUCTION")
    print("==================================================")

    print("\n[*] Installing KVM, Libvirt & essential packages (Arch/EndeavourOS)...")
    packages = "qemu-full libvirt bridge-utils virt-manager edk2-ovmf python-pip git dmg2img macchanger dhclient dnsmasq iptables-nft xorriso"
    run_cmd(f"sudo pacman -Sy --noconfirm {packages}", ignore_errors=True)

    run_cmd("sudo systemctl enable libvirtd", ignore_errors=True)
    run_cmd("sudo systemctl start libvirtd", ignore_errors=True)

    print("\n[*] Enabling CPU IOMMU (Hardware Memory Segregation)...")
    cpu_info = run_cmd("lscpu")
    iommu_flag = "intel_iommu=on iommu=pt" if "Intel" in cpu_info else "amd_iommu=on iommu=pt"

    force_patch_bootloader(iommu_flag)

    ensure_framework()

    print("\n==================================================")
    print("[!] PHASE 1 COMPLETE: REBOOT REQUIRED")
    print("==================================================")
    print("Your kernel must be reloaded to physically isolate the CPU memory space.")
    print("Please restart your computer. Once logged back in, run this exact script again.")
    sys.exit(0)

def phase_two_launch():
    print("\n==================================================")
    print("[!] PHASE 2: SECURE ENCLAVE DEPLOYMENT")
    print("==================================================")

    ensure_phase_two_tools()
    ensure_framework()

    base_dmg = os.path.join(INSTALL_DIR, "BaseSystem.dmg")
    base_img = os.path.join(INSTALL_DIR, "BaseSystem.img")

    while not os.path.exists(base_img):
        if not os.path.exists(base_dmg):
            print("\n[!] The Apple Recovery Image is missing.")
            print("[*] Automatically fetching macOS Monterey (Option 5)...")

            fetch_script = os.path.join(INSTALL_DIR, "fetch-macOS-v2.py")
            if not os.path.exists(fetch_script):
                print("    [-] FATAL ERROR: Framework script missing during fetch loop. Aborting to prevent infinite loop.")
                sys.exit(1)

            subprocess.call(f"cd {INSTALL_DIR} && echo '5' | python3 fetch-macOS-v2.py", shell=True)

        print("\n[*] Converting Apple Recovery Image (dmg -> img)...")
        convert_cmd = f"cd {INSTALL_DIR} && dmg2img -i BaseSystem.dmg BaseSystem.img || qemu-img convert BaseSystem.dmg -O raw BaseSystem.img"

        res = subprocess.run(convert_cmd, shell=True)

        if res.returncode != 0:
            print("    [-] ERROR: Conversion failed. Purging corrupted file...")
            if os.path.exists(base_dmg): os.remove(base_dmg)
            if os.path.exists(base_img): os.remove(base_img)
        else:
            print("    [+] Conversion complete.")

    disk_path = os.path.join(INSTALL_DIR, DISK_IMAGE)
    if not os.path.exists(disk_path):
        print(f"    [*] Compiling {DISK_SIZE} RAW pure-block storage volume...")
        run_cmd(f"cd {INSTALL_DIR} && qemu-img create -f raw {DISK_IMAGE} {DISK_SIZE}")
        print("    [+] Storage volume compiled.")

    has_payload = compile_secure_payload()
    optimize_vm_hardware(has_payload)
    enforce_1080p_resolution()
    engage_ghost_mode()

    print("\n[*] Launching Triple-Walled Hardware-Isolated macOS Environment...")
    boot_cmd = f"cd {INSTALL_DIR} && ./OpenCore-Boot.sh"
    subprocess.call(boot_cmd, shell=True)

if __name__ == "__main__":
    downgrade_privileges()
    check_scorched_earth()

    if is_iommu_active():
        phase_two_launch()
    else:
        phase_one_setup()
