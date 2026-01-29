from __future__ import annotations

from typing import Literal

Bits = Literal[32, 64]


def capstone_disasm(shellcode: bytes, *, bits: Bits = 32, base_addr: int = 0x1000) -> str:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    except Exception:
        return "(Capstone) non disponible: installez la dépendance 'capstone'."

    mode = CS_MODE_32 if bits == 32 else CS_MODE_64
    md = Cs(CS_ARCH_X86, mode)
    md.detail = False

    lines = []
    addr = base_addr
    try:
        for insn in md.disasm(shellcode, addr):
            lines.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}".strip())
    except Exception as e:
        lines.append(f"(Capstone) erreur: {e}")
    return "\n".join(lines) if lines else "(Capstone) aucun désassemblage"
