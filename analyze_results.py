import json
import os
import glob

def analyze_findings():
    metadata_path = "metadata.json"
    if not os.path.exists(metadata_path):
        print("metadata.json not found")
        return

    with open(metadata_path, "r") as f:
        metadata = json.load(f)
    
    rules_map = {r["code"]: r["name"] for r in metadata.get("rules", [])}
    
    target_vulnerabilities = {
        1: "Insecure logging",
        2: "Hardcoded master key",
        3: "Hardcoded password",
        4: "Insecure deserialization",
        5: "Arbitrary file deletion",
        6: "Arbitrary file read",
        7: "Blind SQL injection",
        8: "Intent redirection",
        9: "Overwriting arbitrary files via a symlink",
        10: "Stealing arbitrary files via a symlink",
        11: "Stealing arbitrary files via a content provider",
        12: "Theft of arbitrary files via an activity",
        13: "Accessing sensitive data over HTTP",
        14: "Loading arbitrary native libraries",
        15: "Executing arbitrary code",
        16: "XSS in a WebView",
        17: "Insecure deep link"
    }

    # Map MT rule codes to OVAA categories
    # This is a heuristic mapping based on our rules.json definitions
    mt_to_ovaa = {
        7: [1],
        9: [2, 3],
        8: [4],
        13: [5, 6, 9, 10, 11, 12],
        2: [5, 6, 9, 10, 11, 12],
        4: [7],
        12: [8, 17],
        11: [13],
        10: [14, 18],
        1: [15, 18],
        5: [16]
    }

    detected = {} # category -> list of finding details

    for filename in glob.glob("model@*.json"):
        with open(filename, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    issues = entry.get("issues", [])
                    if not issues: continue
                    
                    method = entry.get("method")
                    for issue in issues:
                        rule_code = issue.get("rule")
                        categories = mt_to_ovaa.get(rule_code, [])
                        
                        for cat_id in categories:
                            cat_name = target_vulnerabilities[cat_id]
                            if cat_id not in detected:
                                detected[cat_id] = []
                            
                            detected[cat_id].append({
                                "method": method,
                                "location": issue.get("position", {}),
                                "rule": rule_code,
                                "rule_name": rules_map.get(rule_code)
                            })
                except:
                    continue

    print("# OVAA Vulnerability Detection Report\n")
    print(f"Total Categories Detected: {len(detected)} / 17\n")
    
    for cat_id in sorted(target_vulnerabilities.keys()):
        status = "✅ DETECTED" if cat_id in detected else "❌ MISSING"
        name = target_vulnerabilities[cat_id]
        print(f"## {cat_id}. {name} [{status}]")
        
        if cat_id in detected:
            # Show top 3 unique findings for this category
            unique_findings = {}
            for item in detected[cat_id]:
                key = f"{item['method']}@{item['location'].get('line')}"
                if key not in unique_findings:
                    unique_findings[key] = item
            
            for i, (key, item) in enumerate(list(unique_findings.items())[:3]):
                print(f"- **Method**: `{item['method']}`")
                print(f"  - Location: Line {item['location'].get('line')}")
                print(f"  - MT Rule: {item['rule']} ({item['rule_name']})")
        print("")

if __name__ == "__main__":
    analyze_findings()
