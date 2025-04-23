import os
import re
import argparse
import time


def compile_patterns():
    # Detect nested quantifiers patterns
    nested_quantifier = re.compile(r"\((?:[^)]*?[+*?][^)]*?)\)[+*?]")
    # JavaScript regex literals: /pattern/flags
    literal_regex = re.compile(r"/((?:[^/\\]|\\.)+)/[gimsuy]*")
    # RegExp constructor: new RegExp('pattern')
    constructor_regex = re.compile(r"new\s+RegExp\s*\(\s*(['\"])(.*?)\1\s*\)")
    return nested_quantifier, literal_regex, constructor_regex


def is_vulnerable(pattern):
    """
    Dynamically test the regex for catastrophic backtracking using a crafted input.
    Returns (True, duration_sec) if execution exceeds threshold.
    """
    try:
        regex = re.compile(pattern)
    except re.error:
        return False, 0.0
    # Choose a character likely in the quantified class
    test_char = 'a'
    if r"\d" in pattern or r"[0-9]" in pattern:
        test_char = '0'
    # Build evil payload: many repeats + failing suffix
    evil = test_char * 20000 + 'X'
    start = time.perf_counter()
    regex.search(evil)
    duration = time.perf_counter() - start
    # Threshold: 100 ms
    return duration > 0.1, duration


def scan_file(path, nested_q, lit_re, ctor_re):
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                # Test JS-style literals
                for m in lit_re.finditer(line):
                    pat = m.group(1)
                    if nested_q.search(pat):
                        vuln, dur = is_vulnerable(pat)
                        if vuln:
                            findings.append((lineno, pat, dur))
                # Test RegExp constructors
                for m in ctor_re.finditer(line):
                    pat = m.group(2)
                    if nested_q.search(pat):
                        vuln, dur = is_vulnerable(pat)
                        if vuln:
                            findings.append((lineno, pat, dur))
    except Exception:
        return []
    return findings


def scan_directory(directory):
    nested_q, lit_re, ctor_re = compile_patterns()
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.js', '.jsx', '.ts', '.py', '.java')):
                fullpath = os.path.join(root, file)
                if not os.path.isfile(fullpath):
                    continue
                results = scan_file(fullpath, nested_q, lit_re, ctor_re)
                for lineno, pat, dur in results:
                    print(f"{fullpath}:{lineno}\t{pat}\t{dur * 1000:.1f}ms")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Detect and dynamically validate nested-quantifier ReDoS patterns in codebase'
    )
    parser.add_argument(
        'path', nargs='?', default='.', help='Directory to scan (default: current)'
    )
    args = parser.parse_args()
    scan_directory(args.path)
