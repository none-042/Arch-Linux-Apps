# EndeavourOS / Arch Linux / Nvidia

Everything in this repository is designed exclusively for NVIDIA GPU, INTEL CPU, EndeavourOS KDE Wayland, UFW Firewall (install ufw if missing or run super.py).

**A collection of AI-assisted Python scripts and utilities.**

This repository contains standalone Python scripts optimized for EndeavourOS and Arch Linux, developed with the assistance of AI.

## Included Scripts

* **`android.py`** — Android Crosvm Cuttlefish KVM
* **`osx.py`** — Mac OSX Qemu KVM
* **`web.py`** — Chrome with dev tools to monitor traffic
* **`kernel.py`** — EndeavourOS Nvidia (Proprietary,Open,Mesa | Best: Proprietary Driver) with hardened or zen kernel and kde on wayland
* **`super.py`** — Run with internet to install UFW firewall, limit internet access, secure vulnerable services, enforce apparmor, install zsh.

* `python3 android.py help`

Commands might not all work as expected.

* **Example:** `python3 android.py`
* **Example:** `python3 android.py ai`
* **Example:** `python3 android.py no-root ai`
* **Example Reset:** `python3 android.py ai reset`

Create a file in home directory called `password` with sudo password in it if you do not want to type your password at `sudo`

**Commands:** `docker(Container)` `sandbox(Crosvm)` `no-root(User)` `reset(Delete)` `console(No UI)` `ai(Experimental)` `help(Info)`

* **`help`** command is strictly for information.
* **`docker`** docker container.
* **`no-root`** compile the Android Open Source Project operating system without root/admin access.
* **`reset`** completely delete everything and start fresh.
* **`console`** without dashboard and with cuttlefish webrtc client page enabled
* **`sandbox`** crosvm sandbox.
* **`ai`** diagnostics.
