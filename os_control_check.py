import os
import subprocess

def check(desc, command, expected=None, expect_in=True):
    try:
        result = subprocess.check_output(command, shell=True).decode().strip()
        if expected is None:
            print(f"[✔] {desc}")
        elif (expected in result if expect_in else expected == result):
            print(f"[✔] {desc}")
        else:
            print(f"[!] {desc} — Got: {result}")
    except Exception as e:
        print(f"[✘] {desc} — Error: {e}")

print("\n🔐 LINUX PHASE 0 HARDENING CHECK\n")

# SSH Port Check
check("SSH runs on port 2222", "ss -tulpn | grep sshd | grep ':2222'")

# SSH Key-only Auth
check("SSH password authentication disabled", "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config", "no")
check("Root login disabled over SSH", "grep -i '^PermitRootLogin' /etc/ssh/sshd_config", "no")

# UFW (Firewall)
check("UFW default input policy is deny", "ufw status verbose | grep 'Default'", "deny")
check("UFW is active", "ufw status", "Status: active")

# Sysctl (Kernel Hardening)
check("IP forwarding disabled", "sysctl net.ipv4.ip_forward", "net.ipv4.ip_forward = 0")
check("SYN cookies enabled", "sysctl net.ipv4.tcp_syncookies", "net.ipv4.tcp_syncookies = 1")
check("ICMP broadcast ignore enabled", "sysctl net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.icmp_echo_ignore_broadcasts = 1")

# Time Sync
check("System clock synchronized (NTP)", "timedatectl | grep 'System clock synchronized'", "yes")

# Lynis Hardening Index
print("\n📊 Running Lynis audit...")
try:
    output = subprocess.check_output("lynis audit system | tee /tmp/lynis.txt", shell=True).decode()
    score_line = [line for line in output.splitlines() if "Hardening index" in line]
    if score_line:
        score = int(score_line[0].split()[-1])
        if score >= 90:
            print(f"[✔] Lynis Hardening Score: {score}")
        else:
            print(f"[!] Lynis Score below threshold: {score}")
except Exception as e:
    print(f"[✘] Lynis check failed — {e}")
