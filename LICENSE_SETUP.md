# AGPL-3.0 License Setup Complete ✅

This document confirms the complete setup of GNU Affero General Public License v3.0 (AGPL-3.0) for the Rekrypt project.

## Files Created/Updated

### 1. License Files

- ✅ **`LICENSE`** - Full AGPL-3.0 license text (34KB)
- ✅ **`COPYRIGHT`** - Copyright notice and license summary
- ✅ **`README.md`** - Added license section with key terms

### 2. Source Code Headers

All source files now include SPDX license identifier headers:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep
```

**Updated files:**
- `src/lib.rs` ✓
- `src/crypto.rs` ✓
- `src/keys.rs` ✓
- `src/keystore.rs` ✓
- `src/types.rs` ✓
- `src/errors.rs` ✓
- `src/validation.rs` ✓
- `src/i18n.rs` ✓

### 3. Package Metadata

The `Cargo.toml` already specifies:
```toml
license = "AGPL-3.0"
```

## What is AGPL-3.0?

### Key Features

**Permissions:**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Patent grant
- ✅ Private use

**Conditions:**
- ⚠️ **Network use clause**: Modified versions used over network must provide source code
- ⚠️ **Same license**: Derivatives must use AGPL-3.0
- ⚠️ **State changes**: Must document modifications
- ⚠️ **Disclose source**: Full source code must be available

**Limitations:**
- ❌ Liability
- ❌ Warranty

### Network Use Clause (Section 13)

This is the key difference from GPL-3.0:

> **If you modify this software and allow users to interact with it over a network, you MUST make the modified source code available to those users.**

This prevents the "SaaS loophole" where companies could use modified GPL software in web services without releasing changes.

## For Users of This Software

### If you just USE the software:
- ✅ No obligations - use freely

### If you MODIFY and DISTRIBUTE:
- ⚠️ You must release your changes under AGPL-3.0
- ⚠️ You must include the license and copyright notices
- ⚠️ You must provide the complete source code

### If you MODIFY and run as a NETWORK SERVICE:
- ⚠️ You must provide the source code to your users
- ⚠️ This includes web services, APIs, SaaS platforms, etc.
- ⚠️ Even if you don't "distribute" binaries

## For Contributors

By contributing to this project, you agree that your contributions will be licensed under AGPL-3.0.

## Compliance Checklist

When distributing or deploying modifications:

- [ ] Include the `LICENSE` file
- [ ] Include the `COPYRIGHT` notice
- [ ] Keep SPDX headers in source files
- [ ] Document your modifications
- [ ] Make source code available (including for network services)
- [ ] Use AGPL-3.0 for your derivative work

## References

- Full license text: [LICENSE](LICENSE)
- Official AGPL-3.0: https://www.gnu.org/licenses/agpl-3.0.html
- SPDX License List: https://spdx.org/licenses/AGPL-3.0-or-later.html
- FSF AGPL FAQ: https://www.gnu.org/licenses/agpl-3.0-faq.html

## Contact

For licensing questions or commercial licensing inquiries, please contact the project maintainers.

---

**Note**: This is not legal advice. Consult with a lawyer for specific legal questions about AGPL-3.0 compliance.

