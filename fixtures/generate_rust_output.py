"""
Run the Rust vivbin tool on test binaries and capture structured output
for comparison against Python golden files.

Usage: python generate_rust_output.py <binary_path> <output_json_path>
"""

import json
import subprocess
import sys
import os
import re


VIVBIN = os.path.join(os.path.dirname(__file__), "..", "target", "debug", "vivbin.exe")


def run_vivbin(subcmd, filepath):
    """Run vivbin subcommand and return stdout."""
    cmd = [VIVBIN, subcmd, filepath]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f"  [!] vivbin {subcmd} failed: {result.stderr[:200]}")
        return None
    return result.stdout


def parse_sections(output):
    """Parse vivbin sections output."""
    sections = []
    if not output:
        return sections
    lines = output.strip().split("\n")
    for line in lines[2:]:  # Skip header lines
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            sections.append({
                "name": parts[0],
                "va": int(parts[1], 16),
                "size": int(parts[2]),
                "perms": parts[3],
            })
    return sections


def parse_imports(output):
    """Parse vivbin imports output."""
    imports = []
    if not output:
        return imports
    lines = output.strip().split("\n")
    for line in lines[1:]:  # Skip header
        line = line.strip()
        m = re.match(r'(0x[0-9a-fA-F]+)\s+(.+)', line)
        if m:
            imports.append({
                "va": int(m.group(1), 16),
                "name": m.group(2).strip(),
            })
    return imports


def parse_exports(output):
    """Parse vivbin exports output."""
    exports = []
    if not output:
        return exports
    lines = output.strip().split("\n")
    for line in lines[1:]:
        line = line.strip()
        m = re.match(r'(0x[0-9a-fA-F]+)\s+(.+)', line)
        if m:
            exports.append({
                "va": int(m.group(1), 16),
                "name": m.group(2).strip(),
            })
    return exports


def parse_info(output):
    """Parse vivbin info output."""
    info = {}
    if not output:
        return info
    for line in output.strip().split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_path> <output_json_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(VIVBIN):
        print(f"Error: vivbin not found at {VIVBIN}")
        print("Run 'cargo build' first")
        sys.exit(1)

    result = {"source": "vivisect-rs", "file": os.path.basename(binary_path)}

    print(f"[*] Running vivbin info on {binary_path}...")
    info_out = run_vivbin("info", binary_path)
    result["info"] = parse_info(info_out)

    print("[*] Running vivbin sections...")
    sections_out = run_vivbin("sections", binary_path)
    result["sections"] = parse_sections(sections_out)

    print("[*] Running vivbin imports...")
    imports_out = run_vivbin("imports", binary_path)
    result["imports"] = parse_imports(imports_out)

    print("[*] Running vivbin exports...")
    exports_out = run_vivbin("exports", binary_path)
    result["exports"] = parse_exports(exports_out)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n[+] Rust output written to {output_path}")
    print(f"    Sections: {len(result['sections'])}")
    print(f"    Imports:  {len(result['imports'])}")
    print(f"    Exports:  {len(result['exports'])}")


if __name__ == "__main__":
    main()
