import sys
import json
from pathlib import Path
from datetime import datetime
from mitreattack.stix20 import MitreAttackData

# ─── Locate & load the MITRE ATT&CK JSON ────────────────────────
BASE = Path(__file__).parent
DATA_FILE = BASE / "enterprise-attack.json"
if not DATA_FILE.exists():
    print(f"ERROR: {DATA_FILE} not found.")
    sys.exit(1)

# Load raw STIX objects
bundle = json.loads(DATA_FILE.read_text())
objects = bundle.get("objects", [])

# Preload GUID <-> external ID mappings
intrusion_extid_to_guid = {}
guid_to_intrusion_extid = {}
pattern_extid_to_guid = {}
guid_to_pattern_extid = {}
software_extid_to_guid = {}
guid_to_software_extid = {}

for o in objects:
    typ = o.get("type")
    for ext in o.get("external_references", []) or []:
        eid = ext.get("external_id")
        if not eid:
            continue
        if typ == "intrusion-set":
            intrusion_extid_to_guid[eid] = o["id"]
            guid_to_intrusion_extid[o["id"]] = eid
        elif typ == "attack-pattern":
            pattern_extid_to_guid[eid] = o["id"]
            guid_to_pattern_extid[o["id"]] = eid
        elif typ in ("malware", "tool"):
            software_extid_to_guid[eid] = o["id"]
            guid_to_software_extid[o["id"]] = eid

# Preload "uses" relationships: intrusion-set ➔ pattern/tool
uses_rels = [
    r for r in objects
    if r.get("type") == "relationship" and r.get("relationship_type") == "uses"
]

# Load via mitreattack-python
try:
    attack = MitreAttackData(str(DATA_FILE))
except Exception as e:
    print("ERROR loading MITRE data:", e)
    sys.exit(1)

# Precompute GUID->name maps for convenience
tech_guid_to_name = {t["id"]: t["name"] for t in attack.get_techniques()}
soft_guid_to_name = {s["id"]: s["name"] for s in attack.get_software()}

def _short_desc(text, sents=2):
    parts = [s.strip() for s in text.split('. ') if s]
    out = '. '.join(parts[:sents])
    return (out + '.') if out and not out.endswith('.') else out

def safe_next(iterable, default=None):
    try:
        return next(iterable)
    except StopIteration:
        return default

# ─── Query Implementations ──────────────────────────────────────
def match_group(q):
    q = q.lower()
    for g in attack.get_groups():
        name = g.get("name", "")
        extid = guid_to_intrusion_extid.get(g["id"], g["id"])
        if q in name.lower() or any(q in a.lower() for a in g.get("aliases", [])):
            print(f"\n{name} ({extid})")
            if g.get("aliases"):
                print(f"  Aliases: {', '.join(g.get('aliases'))}")
            created = g.get("created")
            if created:
                date = created if isinstance(created, str) else created.isoformat()
                print(f"  First seen: {date.split('T')[0]}")
            desc = _short_desc(g.get("description", ""), 2)
            if desc:
                print(f"  Description: {desc}")
            pattern_guids = [r["target_ref"] for r in uses_rels if r["source_ref"] == g["id"] and r["target_ref"] in guid_to_pattern_extid]
            if pattern_guids:
                techs = []
                for guid in pattern_guids[:5]:
                    tid = guid_to_pattern_extid.get(guid)
                    name = tech_guid_to_name.get(guid, "")
                    techs.append(f"{tid} ({name})")
                print(f"  Techniques: {', '.join(techs)}")
            soft_guids = [r["target_ref"] for r in uses_rels if r["source_ref"] == g["id"] and r["target_ref"] in guid_to_software_extid]
            if soft_guids:
                tools = []
                for guid in soft_guids[:5]:
                    sid = guid_to_software_extid.get(guid)
                    name = soft_guid_to_name.get(guid, "")
                    tools.append(f"{sid} ({name})")
                print(f"  Software: {', '.join(tools)}")

def match_technique(q):
    qlow = q.lower()
    for t in attack.get_techniques():
        tid = guid_to_pattern_extid.get(t["id"], t["id"])
        name = t.get("name", "")
        if qlow in name.lower() or qlow in tid.lower():
            print(f"\n{name} ({tid})")
            phases = [p["phase_name"] for p in t.get("kill_chain_phases", [])]
            if phases:
                print(f"  Tactics: {', '.join(phases)}")
            desc = _short_desc(t.get("description", ""), 2)
            if desc:
                print(f"  Desc: {desc}")
            plats = t.get("x_mitre_platforms", [])
            if plats:
                print(f"  Platforms: {', '.join(plats)}")
            det = t.get("x_mitre_detection", "")
            if det:
                print(f"  Detection: {_short_desc(det,1)}")
            users = [rel["source_ref"] for rel in uses_rels if rel["target_ref"] == t["id"]]
            if users:
                names = [safe_next((g["name"] for g in attack.get_groups() if g["id"] == uid), "Unknown") for uid in users]
                print(f"  Used by: {', '.join(names)}")

def match_software(q):
    qlow = q.lower()
    for s in attack.get_software():
        name = s.get("name", "")
        if qlow in name.lower() or qlow in s.get("id", "").lower():
            sid = guid_to_software_extid.get(s["id"], s.get("id"))
            print(f"\n{name} ({sid})")
            print(f"  Type: {s.get('type', 'N/A')}")
            desc = _short_desc(s.get("description", ""), 2)
            if desc:
                print(f"  Desc: {desc}")
            plats = s.get("x_mitre_platforms", [])
            if plats:
                print(f"  Platforms: {', '.join(plats)}")
            users = [rel["source_ref"] for rel in uses_rels if rel["target_ref"] == s["id"]]
            if users:
                names = [safe_next((g["name"] for g in attack.get_groups() if g["id"] == uid), "Unknown") for uid in users]
                print(f"  Used by: {', '.join(names)}")

def since_year(year_str):
    try:
        year = int(year_str)
    except ValueError:
        print("Invalid year format.")
        return

    print(f"\nShowing entries created or first seen since {year}:\n")

    print("Groups:")
    for g in attack.get_groups():
        date = g.get("created")
        if not date:
            continue
        y = int(str(date)[:4])
        if y >= year:
            extid = guid_to_intrusion_extid.get(g["id"], g["id"])
            print(f"  {g.get('name')} ({extid}) - First Seen: {str(date)[:10]}")

    print("\nSoftware:")
    for s in attack.get_software():
        date = s.get("created")
        if not date:
            continue
        y = int(str(date)[:4])
        if y >= year:
            sid = guid_to_software_extid.get(s["id"], s["id"])
            print(f"  {s.get('name')} ({sid}) - Created: {str(date)[:10]}")

# ─── REPL & Dispatch ────────────────────────────────────────────
def print_help():
    print("""
Supported commands:
  group <name>
  <raw name or extid> (auto-detect)
  technique <id|name>
  software <name>
  tactic <name>
  search <keyword>
  since <year>
  uses <group> <software>
  filter <criteria>  combine:
    group=<text>
    year>=<YYYY>
    technique=<text>
    software=<text>
    tactic=<text>
  help
  exit
""")

def repl():
    print("MITRE ATT&CK Query Tool")
    print_help()
    while True:
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break
        if not raw:
            continue
        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts)>1 else ''

        if cmd == 'group' and arg:
            match_group(arg)
        elif cmd == 'technique' and arg:
            match_technique(arg)
        elif cmd == 'software' and arg:
            match_software(arg)
        elif cmd == 'tactic' and arg:
            print("Tactic search is not implemented.")
        elif cmd == 'search' and arg:
            print("Search is not implemented.")
        elif cmd == 'since' and arg.isdigit():
            since_year(arg)
        elif cmd == 'uses' and arg:
            a,b = arg.split(maxsplit=1) if ' ' in arg else (arg,'')
            if b:
                print("Uses command is not implemented.")
            else:
                print("usage: uses <group> <software>")
        elif cmd == 'filter' and arg:
            print("Filter command is not implemented.")
        elif cmd in ('help','?'):
            print_help()
        elif cmd in ('exit','quit'):
            break
        else:
            token = cmd
            if token.upper().startswith('T') and token[1:].isdigit():
                match_technique(token)
            elif any(token.lower() in g['name'].lower() for g in attack.get_groups()):
                match_group(token)
            elif any(token.lower() in s['name'].lower() for s in attack.get_software()):
                match_software(token)
            else:
                print("Unknown command. Type 'help'.")
    print("Exiting.")

if __name__ == '__main__':
    repl()
