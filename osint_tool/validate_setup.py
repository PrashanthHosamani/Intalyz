#!/usr/bin/env python3
"""
osint_tool/validate_setup.py
Validate OSINT configuration and API key setup.

Usage:
    python osint_tool/validate_setup.py
"""

import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def color(code):
    """ANSI color codes."""
    codes = {
        'reset': '\033[0m', 'bold': '\033[1m', 'green': '\033[92m',
        'red': '\033[91m', 'yellow': '\033[93m', 'cyan': '\033[96m',
    }
    return codes.get(code, '')

def check(condition, pass_msg, fail_msg):
    """Print a check result."""
    if condition:
        print(f"  {color('green')}✓{color('reset')} {pass_msg}")
        return True
    else:
        print(f"  {color('red')}✗{color('reset')} {fail_msg}")
        return False

def main():
    print(f"\n{color('bold')}{color('cyan')}OSINT Setup Validator v1.0{color('reset')}\n")
    
    results = []
    
    # =========================================================================
    # 1. Check Python Version
    # =========================================================================
    print(f"{color('bold')}1. Python Environment:{color('reset')}")
    results.append(check(
        sys.version_info >= (3, 8),
        f"Python {sys.version.split()[0]} (3.8+ required)",
        f"Python {sys.version.split()[0]} (need 3.8+)"
    ))
    
    # =========================================================================
    # 2. Check .env File
    # =========================================================================
    print(f"\n{color('bold')}2. Configuration File:{color('reset')}")
    
    config_dir = Path(__file__).parent / "config"
    env_file = config_dir / ".env"
    results.append(check(env_file.exists(), f".env found at {env_file}", ".env not found"))
    
    if env_file.exists():
        with open(env_file) as f:
            env_content = f.read()
    else:
        env_content = ""
    
    # =========================================================================
    # 3. Check Required Imports
    # =========================================================================
    print(f"\n{color('bold')}3. Required Libraries:{color('reset')}")
    
    libs_check = {
        'django': 'Django',
        'dotenv': 'python-dotenv',
        'requests': 'requests',
        'reportlab': 'reportlab (PDF generation)',
        'rapidfuzz': 'rapidfuzz (fuzzy matching)',
    }
    
    for lib_name, lib_label in libs_check.items():
        try:
            __import__(lib_name)
            results.append(check(True, f"{lib_label} installed", ""))
        except ImportError:
            results.append(check(False, "", f"{lib_label} not installed"))
    
    # =========================================================================
    # 4. Check API Keys
    # =========================================================================
    print(f"\n{color('bold')}4. API Key Configuration:{color('reset')}")
    
    api_keys = {
        'GITHUB_TOKEN': ('GitHub', True),          # Critical
        'HIBP_API_KEY': ('HIBP (Breach Detection)', False),
        'NEWS_API_KEY': ('NewsAPI (News Intel)', False),
        'OPENCORPORATES_TOKEN': ('OpenCorporates (Corp Registry)', False),
    }
    
    api_status = {}
    found_keys = 0
    
    for key_name, (label, required) in api_keys.items():
        is_set = False
        for line in env_content.split('\n'):
            if line.startswith(key_name) and '=' in line:
                value = line.split('=', 1)[1].strip()
                is_set = bool(value)
                api_status[key_name] = is_set
                break
        
        if is_set:
            msg = f"{label} — {color('green')}CONFIGURED{color('reset')}"
            print(f"  {color('green')}✓{color('reset')} {msg}")
            results.append(True)
            found_keys += 1
        elif required:
            msg = f"{label} — {color('red')}MISSING (CRITICAL){color('reset')}"
            print(f"  {color('red')}✗{color('reset')} {msg}")
            results.append(False)
        else:
            msg = f"{label} — {color('yellow')}optional{color('reset')}"
            print(f"  {color('yellow')}!{color('reset')} {msg}")
            results.append(True)
    
    # =========================================================================
    # 5. Check Directories
    # =========================================================================
    print(f"\n{color('bold')}5. Project Structure:{color('reset')}")
    
    dirs_to_check = {
        'osint_tool/adapters': 'Adapters module',
        'osint_tool/analysis': 'Analysis module',
        'osint_tool/reporting': 'Reporting module',
        'osint_tool/config': 'Configuration module',
        'osint_web': 'Django web app',
        'output': 'Output directory',
    }
    
    root = Path(__file__).parent.parent
    for rel_path, label in dirs_to_check.items():
        full_path = root / rel_path
        results.append(check(full_path.exists(), f"{label} found", f"{label} missing"))
    
    # =========================================================================
    # 6. Test Imports
    # =========================================================================
    print(f"\n{color('bold')}6. Module Imports:{color('reset')}")
    
    test_imports = [
        ('osint_tool.core.orchestrator', 'Orchestrator'),
        ('osint_tool.adapters.github_adapter', 'GitHub Adapter'),
        ('osint_tool.adapters.contextual_adapter', 'Contextual Adapter'),
        ('osint_tool.analysis.entity_resolver', 'Entity Resolver'),
        ('osint_tool.analysis.risk_scorer', 'Risk Scorer'),
        ('osint_tool.reporting.pdf_reporter', 'PDF Reporter'),
    ]
    
    sys.path.insert(0, str(root / 'osint_tool'))
    
    for module_path, label in test_imports:
        try:
            __import__(module_path)
            results.append(check(True, f"{label} imports successfully", ""))
        except Exception as e:
            results.append(check(False, "", f"{label} import failed: {e}"))
    
    # =========================================================================
    # Summary
    # =========================================================================
    print(f"\n{color('bold')}{color('cyan')}{'='*60}{color('reset')}")
    
    passed = sum(results)
    total = len(results)
    pct = int((passed / total) * 100) if total > 0 else 0
    
    if pct == 100:
        status = f"{color('green')}✅ ALL CHECKS PASSED{color('reset')}"
    elif pct >= 80:
        status = f"{color('yellow')}⚠️  MOSTLY OK{color('reset')}"
    else:
        status = f"{color('red')}❌ ISSUES FOUND{color('reset')}"
    
    print(f"{status}")
    print(f"Score: {passed}/{total} checks passed ({pct}%)")
    
    # =========================================================================
    # Recommendations
    # =========================================================================
    print(f"\n{color('bold')}Recommendations:{color('reset')}")
    
    if not api_status.get('GITHUB_TOKEN'):
        print(f"  {color('red')}1. Add GITHUB_TOKEN{color('reset')} — Get from https://github.com/settings/tokens")
    
    if not api_status.get('HIBP_API_KEY'):
        print(f"  {color('yellow')}2. Add HIBP_API_KEY (~$3.50/mo){color('reset')} — https://haveibeenpwned.com/API/v3")
        print(f"     {color('yellow')}   This is the most important upgrade for better risk assessment{color('reset')}")
    
    if not api_status.get('NEWS_API_KEY'):
        print(f"  {color('yellow')}3. Add NEWS_API_KEY (FREE){color('reset')} — https://newsapi.org/")
    
    if found_keys == 0:
        print(f"  {color('yellow')}Set up API keys for best results. See API_SETUP_GUIDE.md{color('reset')}")
    
    print(f"\n{color('bold')}Next Steps:{color('reset')}")
    print(f"  1. Read: API_SETUP_GUIDE.md (how to get API keys)")
    print(f"  2. Edit: osint_tool/config/.env (add your keys)")
    print(f"  3. Test: python osint_tool/main.py --entity 'Apple' --type company")
    print(f"  4. Deploy: python osint_web/manage.py runserver")
    
    print(f"\n{color('cyan')}For detailed configuration help, see CONFIGURATION_PROFILES.md{color('reset')}\n")
    
    return 0 if pct >= 80 else 1

if __name__ == '__main__':
    sys.exit(main())
