<div align="center">
  <img width="125px" src="assets/Havoc.png" />
  <h1>Havoc</h1>
</div>

A modern post-exploitation command and control framework, originally created by [@C5pider](https://twitter.com/C5pider).

This project has been heavily **vibe coded** (including this README :3) to address critical issues in the original project — frequent client crashes, stability problems, and various bugs that made it unreliable during operations. It is not a clean rewrite; expect rough edges.

> **Warning:** The changes has not been extensively tested. Things may break. Use at your own risk and report issues if you find them.

### What Changed

- Resolved all client crashes that made the original unusable during long operations
- Replaced the key exchange mechanism (the original was fingerprinted by detection tools)
- Per-build hash rotation — API hashes are no longer static across builds (removed it)
- Rewrote agent signatures targeted by public Elastic YARA rules (reverted some of it)
- Added admin panel with role-based permissions and per-operator agent access control (not fully done)
- Migrated to a new database backend
- Handled agent-side crashes and unhandled edge cases (not fully published)
- Added network topology diagram in the client (not fully tested)

---

### Install

**Requirements:** Debian/Ubuntu/Kali, Python 3.10+, Qt5, Go, CMake

```bash
git clone https://github.com/MAA20010/VibedHavoc.git
cd Havoc
make all
```

The first build downloads musl cross-compilers (~200MB) and installs dependencies via apt.

### Usage

**Start the teamserver:**
```bash
# With the default profile
./havoc server --default

# With a custom profile
./havoc server --profile profiles/havoc.yaotl
```

**Start the client:**
```bash
./havoc client
```

### Credits

- [C5pider](https://github.com/Cracked5pider) — original Havoc Framework author
- [HavocFramework](https://github.com/HavocFramework/Havoc) — upstream project 
