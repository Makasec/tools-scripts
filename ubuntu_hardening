#!/bin/bash

# === CONFIG ===
read -p "Enter the new admin username: " USERNAME
read -p "Enter SSH port to use [default: 22]: " SSH_PORT
SSH_PORT=${SSH_PORT:-22}

read -p "Enter comma-separated ports to allow through UFW (e.g. 22,80,443,1883): " OPEN_PORTS

# === CREATE USER ===
echo "[*] Creating user '$USERNAME'..."
sudo adduser --gecos "" $USERNAME
sudo usermod -aG sudo $USERNAME

# === SETUP SSH KEY AUTH ===
echo "[*] Setting up SSH directory for $USERNAME..."
sudo mkdir -p /home/$USERNAME/.ssh
sudo touch /home/$USERNAME/.ssh/authorized_keys
sudo chmod 700 /home/$USERNAME/.ssh
sudo chmod 600 /home/$USERNAME/.ssh/authorized_keys
sudo chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh

echo "[!] Paste your public SSH key for $USERNAME and press Ctrl+D:"
cat >> /home/$USERNAME/.ssh/authorized_keys

# === HARDEN SSH CONFIG ===
echo "[*] Hardening SSH configuration..."
sudo sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?Port.*/Port $SSH_PORT/" /etc/ssh/sshd_config

# === RESTART SSH ===
echo "[*] Restarting SSH service..."
sudo systemctl restart ssh

# === INSTALL AND CONFIGURE UFW ===
echo "[*] Installing and configuring UFW firewall..."
sudo apt update
sudo apt install -y ufw

IFS=',' read -ra PORT_LIST <<< "$OPEN_PORTS"
for PORT in "${PORT_LIST[@]}"; do
    sudo ufw allow ${PORT}/tcp
done

sudo ufw --force enable

# === DONE ===
echo -e "\n✅ System hardening complete."
echo "You can now connect using:"
echo "ssh -i <your-key.pem> $USERNAME@<your-server-ip> -p $SSH_PORT"
