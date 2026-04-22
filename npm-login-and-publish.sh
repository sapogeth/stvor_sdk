#!/bin/bash

# 🔧 NPM Login & Publish Script
# Version: 3.0.1
# Purpose: Login to npm and publish @stvor/sdk

set -e

echo "🔧 STVOR SDK - npm Login & Publish Setup"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check current login status
echo "Checking npm login status..."
if npm whoami > /dev/null 2>&1; then
  USER=$(npm whoami)
  echo -e "${GREEN}✅${NC} Already logged in as: $USER"
else
  echo -e "${RED}❌${NC} Not logged in to npm"
  echo ""
  echo "Please login to npm:"
  echo ""
  read -p "Enter npm username: " username
  
  echo "Running: npm login"
  npm login
  
  if npm whoami > /dev/null 2>&1; then
    USER=$(npm whoami)
    echo -e "${GREEN}✅${NC} Successfully logged in as: $USER"
  else
    echo -e "${RED}❌${NC} Login failed"
    exit 1
  fi
fi

echo ""
echo "Proceeding with publication..."
echo ""

# Navigate to sdk directory
cd "$(dirname "$0")/packages/sdk"

echo "Running pre-publish checks..."
npm run prepublishOnly > /dev/null 2>&1
echo -e "${GREEN}✅${NC} Pre-publish checks passed"
echo ""

# Show what will be published
echo "Package contents:"
npm pack --dry-run 2>&1 | grep "📦\|name:\|version:\|filename:\|package size:" | head -10
echo ""

# Ask for confirmation
read -p "Ready to publish? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Publishing @stvor/sdk@3.0.1..."
  npm publish
  
  echo ""
  echo "✅ Publication successful!"
  echo ""
  echo "Next steps:"
  echo "1. View package: npm view @stvor/sdk@3.0.1"
  echo "2. Install: npm install @stvor/sdk@3.0.1"
  echo "3. Verify: npm ls @stvor/sdk"
else
  echo "Publication cancelled"
  exit 1
fi
