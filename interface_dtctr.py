import psutil

def check_interfaces():
    print("Cross-Platform Network Interface Status\n")
    stats = psutil.net_if_stats()

    for iface, data in stats.items():
        status = "🟢 UP" if data.isup else "🔴 DOWN"
        print(f"{iface}: {status}")

if __name__ == "__main__":
    check_interfaces()
