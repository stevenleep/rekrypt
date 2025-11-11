#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 stenvenleep
#
# Release preparation script for rekrypt

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🚀 Preparing rekrypt for release..."
echo ""

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
        exit 1
    fi
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 1. Check git status
echo "📋 Checking git status..."
if [ -n "$(git status --porcelain)" ]; then
    print_warning "Working directory has uncommitted changes"
    git status --short
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    print_status 0 "Working directory is clean"
fi
echo ""

# 2. Run tests
echo "🧪 Running tests..."
cargo test --lib
print_status $? "Tests passed"
echo ""

# 3. Run clippy
echo "🔍 Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings
print_status $? "Clippy passed"
echo ""

# 4. Format check
echo "📝 Checking code format..."
cargo fmt --all -- --check
print_status $? "Code is formatted"
echo ""

# 5. Build documentation
echo "📚 Building documentation..."
cargo doc --no-deps --lib
print_status $? "Documentation built successfully"
echo ""

# 6. Check documentation warnings
echo "📖 Checking for documentation warnings..."
DOC_WARNINGS=$(cargo doc --no-deps --lib 2>&1 | grep -c "warning:" || true)
if [ "$DOC_WARNINGS" -eq 0 ]; then
    print_status 0 "No documentation warnings"
else
    print_warning "Found $DOC_WARNINGS documentation warning(s)"
    cargo doc --no-deps --lib 2>&1 | grep "warning:"
fi
echo ""

# 7. Run doc tests
echo "🧪 Running doc tests..."
cargo test --doc
print_status $? "Doc tests passed"
echo ""

# 8. Package check
echo "📦 Checking package..."
cargo package --list > /dev/null
print_status $? "Package structure is valid"
echo ""

# 9. Dry run publish
echo "🚢 Dry run publish..."
cargo publish --dry-run
print_status $? "Dry run publish successful"
echo ""

# 10. Check version
VERSION=$(cargo pkgid | cut -d# -f2)
echo "📌 Current version: $VERSION"
echo ""

# 11. Check if version exists on crates.io
echo "🔎 Checking if version exists on crates.io..."
if curl -s "https://crates.io/api/v1/crates/rekrypt" | grep -q "\"num\":\"$VERSION\""; then
    print_warning "Version $VERSION already exists on crates.io"
    echo "   You need to bump the version in Cargo.toml"
    exit 1
else
    print_status 0 "Version $VERSION is new"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✓ All checks passed!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Ready to publish rekrypt v$VERSION"
echo ""
echo "Next steps:"
echo "  1. cargo login           # If not already logged in"
echo "  2. cargo publish         # Publish to crates.io"
echo ""
echo "After publishing:"
echo "  - Package: https://crates.io/crates/rekrypt"
echo "  - Documentation: https://docs.rs/rekrypt"
echo "  - Create git tag: git tag v$VERSION && git push origin v$VERSION"
echo ""

