import hashlib, json, os, re, stat, subprocess, sys, time
from pathlib import Path

DEFAULT_EXTS = {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".hta", ".lnk", ".apk", ".iso", ".zip", ".jar"}

def find_mpcmdrun() -> Path:
    plat = Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform")
    if plat.exists():
        vers = sorted([p for p in plat.iterdir() if p.is_dir()], reverse=True)
        for v in vers:
            exe = v / "MpCmdRun.exe"
            if exe.exists():
                return exe
    legacy = Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe")
    if legacy.exists():
        return legacy
    raise FileNotFoundError("MpCmdRun.exe not found")

def run(args:list[str]):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def update_sigs(mp:Path):
    code,out,err = run([str(mp), "-SignatureUpdate"])
    if out.strip(): print(out.strip(), file=sys.stderr)
    if err.strip(): print(err.strip(), file=sys.stderr)
    return code

def is_regular_file(p: Path) -> bool:
    """True only for real, non-symlink regular files."""
    try:
        if p.is_symlink():
            return False
        st = p.stat()
        return stat.S_ISREG(st.st_mode)
    except Exception:
        return False

def sha256(path: Path):
    """
    Return (hexdigest, error_str). hexdigest is None if hashing failed.
    """
    try:
        if not is_regular_file(path):
            return None, "not_regular_file_or_symlink"
        h = hashlib.sha256()
        with path.open("rb") as f:
            for ch in iter(lambda: f.read(1 << 20), b""):
                h.update(ch)
        return h.hexdigest(), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

def extract_threat_name(text:str):
    # Pattern like: "Threat 1: Trojan:Win32/Agent_xyz"
    for ln in text.splitlines():
        m = re.match(r"^\s*Threat\s+\d+\s*:\s*(.+)$", ln.strip(), re.I)
        if m:
            return m.group(1).strip()
    # Fallback: look under LIST OF DETECTED THREATS
    lines=[ln.strip() for ln in text.splitlines() if ln.strip()]
    for i,ln in enumerate(lines):
        if "LIST OF DETECTED THREATS" in ln.upper():
            for j in range(i+1, min(i+6, len(lines))):
                m = re.search(r":\s*(.+)$", lines[j])
                if m:
                    return m.group(1).strip()
    return None

def norm_name(s:str):
    return re.sub(r'[:/\\!<>|"*?]', ".", s)

def scan_file(mp:Path, path:Path):
    sha, hash_err = sha256(path)

    args = [str(mp), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"]
    code,out,err = run(args)
    thr = extract_threat_name(out + ("\n"+err if err else ""))

    rec = {
        "path": str(path),
        "size": path.stat().st_size if path.exists() else None,
        "sha256": sha,
        "hash_error": hash_err,                # present if hashing failed or file not regular
        "defender_exit": code,                 # 0 OK, 2 threats found
        "threat_name": thr,
        "threat_name_norm": norm_name(thr) if thr else None,
        "timestamp": int(time.time())
    }
    return rec

def iter_targets(root:Path, scan_all:bool):
    if root.is_file():
        yield root
        return
    for r, _, files in os.walk(root, onerror=lambda e: None):
        for fn in files:
            p = Path(r) / fn
            # If not scanning all, keep only “risky” extensions
            if not scan_all and p.suffix.lower() not in DEFAULT_EXTS:
                continue
            yield p

def main():
    user_path = input("Enter the file or directory path to scan: ").strip('" ')
    root = Path(user_path).expanduser().resolve()
    if not root.exists():
        print(f"[!] Path not found: {root}")
        sys.exit(1)

    scan_all_input = input("Scan ALL files? (y/N): ").strip().lower()
    scan_all = (scan_all_input == "y")

    mp = find_mpcmdrun()
    update_sigs(mp)

    for target in iter_targets(root, scan_all):
        rec = scan_file(mp, target)
        print(json.dumps(rec, ensure_ascii=False))

if __name__ == "__main__":
    import re
    main()
