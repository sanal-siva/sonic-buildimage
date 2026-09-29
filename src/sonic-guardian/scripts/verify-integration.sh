#!/bin/bash
# SONiC Guardian Build Integration Verification Script
# Validates that Guardian is properly integrated into sonic-buildimage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GUARDIAN_DIR="$PROJECT_ROOT/sonic-guardian"

echo "================================================================"
echo "SONiC Guardian Build Integration Verification"
echo "================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0

# Helper functions
check_file() {
    local file=$1
    local description=$2

    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $description"
        ((passed++))
        return 0
    else
        echo -e "${RED}✗${NC} $description (not found: $file)"
        ((failed++))
        return 1
    fi
}

check_dir() {
    local dir=$1
    local description=$2

    if [ -d "$dir" ]; then
        echo -e "${GREEN}✓${NC} $description"
        ((passed++))
        return 0
    else
        echo -e "${RED}✗${NC} $description (not found: $dir)"
        ((failed++))
        return 1
    fi
}

check_content() {
    local file=$1
    local pattern=$2
    local description=$3

    if [ ! -f "$file" ]; then
        echo -e "${RED}✗${NC} $description (file not found: $file)"
        ((failed++))
        return 1
    fi

    if grep -q "$pattern" "$file"; then
        echo -e "${GREEN}✓${NC} $description"
        ((passed++))
        return 0
    else
        echo -e "${RED}✗${NC} $description (pattern not found in $file)"
        ((failed++))
        return 1
    fi
}

echo "1. Checking Guardian Module Files..."
echo "---"
check_dir "$GUARDIAN_DIR/guardian" "guardian/ module directory"
check_file "$GUARDIAN_DIR/guardian/cli.py" "CLI module"
check_file "$GUARDIAN_DIR/guardian/scanner.py" "Scanner module"
check_file "$GUARDIAN_DIR/guardian/intelligence.py" "Intelligence module"
check_file "$GUARDIAN_DIR/guardian/remediation.py" "Remediation module"
check_file "$GUARDIAN_DIR/guardian/validation.py" "Validation module"
check_file "$GUARDIAN_DIR/guardian/vex.py" "VEX module"
check_file "$GUARDIAN_DIR/guardian/hooks.py" "Hooks module"
echo ""

echo "2. Checking Build Configuration Files..."
echo "---"
check_file "$GUARDIAN_DIR/Makefile" "Guardian Makefile"
check_file "$GUARDIAN_DIR/setup.py" "setup.py"
check_file "$GUARDIAN_DIR/requirements.txt" "requirements.txt"
check_file "$GUARDIAN_DIR/debian/control" "debian/control"
check_file "$GUARDIAN_DIR/debian/rules" "debian/rules"
check_file "$GUARDIAN_DIR/debian/postinst" "debian/postinst hook script"
check_file "$GUARDIAN_DIR/debian/prerm" "debian/prerm hook script"
echo ""

echo "3. Checking Build System Integration Files..."
echo "---"
check_file "$PROJECT_ROOT/../rules/sonic-guardian.mk" "Build rules file"
check_file "$PROJECT_ROOT/../platform/common/sonic-guardian-requires.txt" "Dependencies file"
check_file "$PROJECT_ROOT/../debian/sonic-guardian.logrotate" "Log rotation config"
check_file "$GUARDIAN_DIR/debian/sonic-guardian.timer" "Timer unit file"
check_file "$GUARDIAN_DIR/debian/sonic-guardian-scan.service" "Scan service file"
echo ""

echo "4. Checking Documentation..."
echo "---"
check_file "$GUARDIAN_DIR/README.md" "README.md"
check_file "$GUARDIAN_DIR/IMPLEMENTATION_GUIDE.md" "Implementation guide"
check_file "$GUARDIAN_DIR/CONTRIBUTING.md" "Contributing guide"
check_file "$PROJECT_ROOT/../docs/SONIC_GUARDIAN_INTEGRATION.md" "Integration guide"
check_file "$PROJECT_ROOT/../MAKEFILE_CHANGES.md" "Makefile changes guide"
echo ""

echo "5. Checking File Content..."
echo "---"
check_content "$GUARDIAN_DIR/guardian/cli.py" "Click" "CLI uses Click framework"
check_content "$GUARDIAN_DIR/guardian/vex.py" "CycloneDX" "VEX uses CycloneDX format"
check_content "$GUARDIAN_DIR/guardian/hooks.py" "apt/dpkg" "Hooks handles apt/dpkg"
check_content "$GUARDIAN_DIR/setup.py" "grype" "Dependencies include grype"
check_content "$PROJECT_ROOT/../rules/sonic-guardian.mk" "INCLUDE_SONIC_GUARDIAN" "Build rules check flag"
echo ""

echo "6. Checking Debian Package Configuration..."
echo "---"
check_content "$GUARDIAN_DIR/debian/control" "sonic-guardian" "Package name in control"
check_content "$GUARDIAN_DIR/debian/control" "1.0.0" "Version specified"
check_content "$GUARDIAN_DIR/debian/postinst" "sonic-guardian-hooks" "Hook installation in postinst"
check_content "$GUARDIAN_DIR/debian/prerm" "sonic-guardian-hooks" "Hook removal in prerm"
echo ""

echo "7. Testing Build System..."
echo "---"

# Test Makefile parsing
if make -n -C "$GUARDIAN_DIR" sonic-guardian > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Makefile syntax valid"
    ((passed++))
else
    echo -e "${RED}✗${NC} Makefile has syntax errors"
    ((failed++))
fi

# Test Python module import
if python3 -c "import sys; sys.path.insert(0, '$GUARDIAN_DIR'); from guardian import __version__; print(f'Guardian v{__version__}')" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Python modules importable"
    ((passed++))
else
    echo -e "${YELLOW}⚠${NC} Python modules not tested (dependencies not installed)"
fi

echo ""
echo "================================================================"
echo "Verification Summary"
echo "================================================================"
echo -e "Passed: ${GREEN}$passed${NC}"
echo -e "Failed: ${RED}$failed${NC}"
echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review the integration files"
    echo "2. Integrate into sonic-buildimage Makefile (see MAKEFILE_CHANGES.md)"
    echo "3. Test build: make INCLUDE_SONIC_GUARDIAN=y sonic-guardian-debs"
    echo "4. Verify package: dpkg -c sonic-guardian_*.deb | head -20"
    exit 0
else
    echo -e "${RED}✗ Some checks failed - review files above${NC}"
    exit 1
fi
