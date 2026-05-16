#!/bin/bash

TARGET=${1:-"127.0.0.0/24"}
EMPLOYEES=${2:-"employees.json"}

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          Securthy — Full Security Assessment            ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Network target : $TARGET"
echo "║  Employees file : $EMPLOYEES"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Step 1 — Network scan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [1/4] NETWORK SCAN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
./scanner_bin "$TARGET"

echo ""

# Step 2 — Employee scan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [2/4] EMPLOYEE SCAN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
./employee_bin "$EMPLOYEES"

echo ""

# Step 3 — Employee remediation plan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [3/4] GENERATING REMEDIATION PLANS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
LATEST_EMP=$(ls -t employee_report_*.json 2>/dev/null | head -1)
if [ -n "$LATEST_EMP" ]; then
    ./employee_packs_bin "$LATEST_EMP"
else
    echo "  [!] No employee report found, skipping"
fi

echo ""

# Step 4 — Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [4/4] ASSESSMENT COMPLETE — FILES GENERATED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Reports:"
ls -t network_report_*.json 2>/dev/null | head -1 | xargs -I{} echo "  • Network:   {}"
ls -t employee_report_*.json 2>/dev/null | head -1 | xargs -I{} echo "  • Employee:  {}"
ls -t employee_remediation_*.txt 2>/dev/null | head -1 | xargs -I{} echo "  • Remediation plan: {}"
echo "  • Pack targets: targets.json"
echo ""
echo "  Next step — apply network fixes:"
echo "  ./packs_bin --targets=targets.json --ssh-user=\$USER --ssh-key=~/.ssh/id_rsa"
echo ""
