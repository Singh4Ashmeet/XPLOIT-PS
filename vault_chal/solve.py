#!/usr/bin/env python3
"""
XPLOIT Vault System — Full Solve Script
Patches the binary and feeds the computed unlock code.

Usage:
    python3 solve.py          # patches + solves in one step
"""

import subprocess
import sys
import os

BINARY   = "./chal"
PATCHED  = "./chal_patched"
VAULT    = ".vault_state"

# ── Step 1: Patch the binary ────────────────────────────────────────────────

def patch_binary():
    data = bytearray(open(BINARY, "rb").read())

    # Patch 1 — file offset 0x1954
    # Original instruction: movl $0x1, -0x54(%rbp)
    #   C7 45 AC | 01 00 00 00
    # Patched:   movl $0x3e7, -0x54(%rbp)   (999 = 0x3E7)
    #   C7 45 AC | E7 03 00 00
    assert data[0x1951:0x1958] == bytes.fromhex("c745ac01000000"), \
        "Patch 1 anchor mismatch — wrong binary?"
    data[0x1954:0x1958] = bytes.fromhex("e7030000")
    print("[+] Patch 1 applied: auth level 1 → 999")

    # Patch 2 — file offset 0x1b8e
    # Original: call puts  ("Terminating session...")   E8 CD F5 FF FF
    # Patched:  call unlock_vault_sequence              E8 5F FE FF FF
    # Verification: target = 0x19f2, next_ip = 0x1b93, rel = -0x1a1 = 0xFFFFFE5F ✓
    assert data[0x1b8e:0x1b93] == bytes.fromhex("e8cdf5ffff"), \
        "Patch 2 anchor mismatch — wrong binary?"
    data[0x1b8f:0x1b93] = bytes.fromhex("5ffeffff")
    print("[+] Patch 2 applied: main → unlock_vault_sequence after auth")

    open(PATCHED, "wb").write(data)
    os.chmod(PATCHED, 0o755)
    print(f"[+] Written {PATCHED}")


# ── Step 2: First run creates .vault_state ───────────────────────────────────

def ensure_vault_state():
    if os.path.exists(VAULT):
        print(f"[*] {VAULT} already exists — skipping cold start run")
        return
    print("[*] Running first time to create .vault_state …")
    subprocess.run([PATCHED], input=b"", capture_output=True)
    if not os.path.exists(VAULT):
        sys.exit("[-] .vault_state was not created — aborting")
    print(f"[+] {VAULT} created")


# ── Step 3: Compute the unlock code ─────────────────────────────────────────
#
#   unlock_vault_sequence computes:
#       key = strlen(g_argv0) XOR g_pid_seed XOR g_vault_byte
#
#   g_vault_byte  = byte 0 of .vault_state  (set by check_vault_state)
#   g_pid_seed    = (pid >> 8) & 0xFF  XOR  pid & 0xFF  (set by emit_system_diagnostics)
#   g_argv0       = argv[0]  (stored by main)

def compute_and_solve():
    vault_byte = open(VAULT, "rb").read(1)[0]
    argv0      = PATCHED
    strlen_v   = len(argv0)       # byte-level: only low 8 bits used

    print(f"[*] vault_byte    = 0x{vault_byte:02x}")
    print(f"[*] strlen(argv0) = 0x{strlen_v:02x}  ('{argv0}')")

    proc = subprocess.Popen(
        [argv0],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    pid        = proc.pid
    pid_seed   = ((pid >> 8) & 0xFF) ^ (pid & 0xFF)
    unlock_key = (strlen_v ^ pid_seed ^ vault_byte) & 0xFF

    print(f"[*] PID           = {pid}  (0x{pid:04x})")
    print(f"[*] pid_seed      = 0x{pid_seed:02x}")
    print(f"[*] unlock_code   = 0x{unlock_key:02x}")

    # operator ID (any non-empty line) + hex unlock code
    payload = b"admin\n" + f"{unlock_key:x}\n".encode()
    out, _  = proc.communicate(input=payload, timeout=10)

    print("\n" + "─" * 60)
    print(out.decode(), end="")
    print("─" * 60)

    if b"VAULT SYSTEM CLEARED" in out:
        print("\n[✓] SUCCESS")
    else:
        print("\n[✗] Something went wrong — check the output above")


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(BINARY):
        sys.exit(f"[-] '{BINARY}' not found — place chal in the current directory")

    patch_binary()
    ensure_vault_state()
    compute_and_solve()