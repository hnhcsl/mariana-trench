import json
import os
import glob

def summarize_issues():
    metadata_path = "metadata.json"
    if not os.path.exists(metadata_path):
        print("metadata.json not found")
        return

    with open(metadata_path, "r") as f:
        metadata = json.load(f)
    
    codes = metadata.get("codes", {})
    
    all_issues = []
    
    for filename in glob.glob("model@*.json"):
        with open(filename, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    issues = entry.get("issues", [])
                    if issues:
                        method = entry.get("method")
                        for issue in issues:
                            issue["method"] = method
                            all_issues.append(issue)
                except json.JSONDecodeError:
                    continue
    
    print(f"Total issues found: {len(all_issues)}")
    if not all_issues:
        return

    # Debug first issue
    print("\nDebug First Issue:", json.dumps(all_issues[0], indent=2))
    
    # Actually, the issue dict in MT output might have different keys
    # Let's see what's in 'issue'
    # According to some MT output examples, it's 'rule' instead of 'code'
    
    for issue in all_issues:
        code = str(issue.get("rule", issue.get("code")))
        rule_name = codes.get(code, f"Unknown Rule ({code})")
        method = issue.get("method")
        print(f"\nRule {code}: {rule_name}")
        print(f"Method: {method}")
        # Show sinks/sources if available
        sink = issue.get("sink_kind")
        source = issue.get("source_kind")
        if sink and source:
            print(f"Source: {source} -> Sink: {sink}")
        
        # Position
        pos = issue.get("position", {})
        if pos:
            print(f"Location: {pos.get('path')}:{pos.get('line')}")
            
    print("-" * 50)

if __name__ == "__main__":
    summarize_issues()
