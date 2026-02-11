import requests
import argparse
from packaging import version

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def get_kev_list():
    try:
        r = requests.get(CISA_KEV, timeout=10)
        return {v["cveID"] for v in r.json()["vulnerabilities"]}
    except:
        return set()

def search_vulns(product, ver):
    params = {
        "keywordSearch": f"{product} {ver}",
        "resultsPerPage": 50
    }

    r = requests.get(NVD_API, params=params, timeout=15)
    data = r.json()

    return data.get("vulnerabilities", [])

def print_results(product, ver):
    kev_set = get_kev_list()
    vulns = search_vulns(product, ver)

    print(f"\n=== Results for {product} {ver} ===\n")

    if not vulns:
        print("No vulnerabilities found.")
        return

    for item in vulns:
        cve = item["cve"]
        cve_id = cve["id"]

        severity = "Unknown"
        score = "N/A"

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss["baseSeverity"]
            score = cvss["baseScore"]

        exploited = "YES" if cve_id in kev_set else "NO"

        print("-" * 60)
        print(f"CVE: {cve_id}")
        print(f"Severity: {severity} ({score})")
        print(f"Known Exploited: {exploited}")
        print(f"Published: {cve['published']}")
        print(f"Description: {cve['descriptions'][0]['value'][:200]}...")
    print("-" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Software Version Vulnerability Lookup")
    parser.add_argument("product", help="Software name (e.g. docker)")
    parser.add_argument("version", help="Software version (e.g. 18.06)")
    args = parser.parse_args()

    print_results(args.product.lower(), args.version)