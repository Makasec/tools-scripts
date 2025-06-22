#!/bin/bash

echo "🔐 System Hardening Script Started..."

# 1. Lock root account
echo "[*] Locking root account to disable direct login..."
sudo passwd -l root

# 2. Set /usr/sbin/nologin for sync account (legacy)
echo "[*] Disabling interactive shell for 'sync' user..."
sudo usermod -s /usr/sbin/nologin sync

# 3. Show real users (UID >= 1000, not 'nobody')
echo -e "\n[+] Regular user accounts (UID ≥ 1000):"
awk -F: '$3 >= 1000 && $1 != "nobody" { print $1 }' /etc/passwd

# 4. Show accounts with valid login shells
echo -e "\n[+] Accounts with interactive login shells:"
awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1, $7 }' /etc/passwd

# 5. List users in the sudo group
echo -e "\n[+] Users with sudo privileges:"
getent group sudo

# 6. Optional: Install Lynis for advanced auditing
read -p "[?] Install Lynis for a full system security audit? (y/n): " install_lynis
if [[ "$install_lynis" =~ ^[Yy]$ ]]; then
    echo "[*] Installing Lynis..."
    sudo apt update && sudo apt install -y lynis
    echo "[*] Running Lynis audit..."
    sudo lynis audit system
else
    echo "[*] Skipping Lynis installation."
fi

echo -e "\n✅ Basic system hardening complete."
