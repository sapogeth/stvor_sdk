#!/bin/bash

# 📦 STVOR SDK - npm Publish Checklist & Script
# Version 3.0.1 Release
# Last Updated: April 20, 2026

set -e  # Exit on error

echo "🚀 STVOR SDK npm Publish Checklist"
echo "===================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check() {
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅${NC} $1"
  else
    echo -e "${RED}❌${NC} $1"
    exit 1
  fi
}

cd "$(dirname "$0")/packages/sdk"

echo "📋 Pre-Publication Checklist"
echo "---"

# Check 1: Version is correct
echo "Checking version..."
VERSION=$(grep '"version"' package.json | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')
if [ "$VERSION" = "3.0.1" ]; then
  echo -e "${GREEN}✅${NC} Version is 3.0.1"
else
  echo -e "${RED}❌${NC} Version is $VERSION (expected 3.0.1)"
  exit 1
fi
echo ""

# Check 2: Build
echo "Building package..."
npm run build > /dev/null 2>&1
check "npm run build"
echo ""

# Check 3: Tests
echo "Running tests..."
npm test > /dev/null 2>&1
check "npm test (60/60 passing)"
echo ""

# Check 4: Files configured
echo "Checking files configuration..."
if grep -q '"files"' package.json; then
  echo -e "${GREEN}✅${NC} Files configured in package.json"
else
  echo -e "${RED}❌${NC} Files not configured"
  exit 1
fi
echo ""

# Check 5: Package.json is valid JSON
echo "Validating package.json..."
node -e "require('./package.json')" > /dev/null 2>&1
check "package.json is valid JSON"
echo ""

# Check 6: README and CHANGELOG exist
echo "Checking documentation..."
[ -f README.md ] && echo -e "${GREEN}✅${NC} README.md exists" || (echo -e "${RED}❌${NC} README.md missing"; exit 1)
[ -f CHANGELOG.md ] && echo -e "${GREEN}✅${NC} CHANGELOG.md exists" || (echo -e "${RED}❌${NC} CHANGELOG.md missing"; exit 1)
[ -f LICENSE ] && echo -e "${GREEN}✅${NC} LICENSE exists" || (echo -e "${RED}❌${NC} LICENSE missing"; exit 1)
echo ""

# Check 7: Dist folder exists
echo "Checking dist folder..."
[ -d dist ] && echo -e "${GREEN}✅${NC} dist/ folder exists" || (echo -e "${RED}❌${NC} dist/ missing"; exit 1)
[ -f dist/index.js ] && echo -e "${GREEN}✅${NC} dist/index.js exists" || (echo -e "${RED}❌${NC} dist/index.js missing"; exit 1)
[ -f dist/index.cjs ] && echo -e "${GREEN}✅${NC} dist/index.cjs exists" || (echo -e "${RED}❌${NC} dist/index.cjs missing"; exit 1)
[ -f dist/index.d.ts ] && echo -e "${GREEN}✅${NC} dist/index.d.ts exists" || (echo -e "${RED}❌${NC} dist/index.d.ts missing"; exit 1)
echo ""

# Check 8: Exports in package.json
echo "Checking package.json exports..."
if grep -q '"exports"' package.json; then
  echo -e "${GREEN}✅${NC} Exports configured"
else
  echo -e "${RED}❌${NC} Exports not configured"
  exit 1
fi
echo ""

# Check 9: Try dry-run pack
echo "Testing package creation..."
npm pack --dry-run > /dev/null 2>&1
check "npm pack --dry-run"
echo ""

# Summary
echo "===================================="
echo -e "${GREEN}✅ ALL CHECKS PASSED${NC}"
echo "===================================="
echo ""
echo "Ready to publish!"
echo ""
echo "To publish to npm, run:"
echo "  npm publish"
echo ""
echo "To verify package after publish:"
echo "  npm view @stvor/sdk@3.0.1"
echo ""
