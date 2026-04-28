#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from emulator.pzu_memory import CodeImage
from emulator.sfr_model import SBUF_CANDIDATE_ADDRS, SfrModel
from emulator.trace import TraceLog


@dataclass
class CPU8051State:
    pc: int = 0
    acc: int = 0
    b: int = 0
    dptr: int = 0
    psw: int = 0
    sp: int = 0x07
    regs: list[int] = field(default_factory=lambda: [0] * 8)
    idata: list[int] = field(default_factory=lambda: [0] * 256)
    xdata: dict[int, int] = field(default_factory=dict)
    call_stack: list[int] = field(default_factory=list)
    step_counter: int = 0


class CPU8051Subset:
    def __init__(
        self,
        code_image: CodeImage,
        state: CPU8051State,
        trace: TraceLog,
        watchpoints: set[int] | None = None,
        stub_calls: dict[int, Callable[[CPU8051State, TraceLog], None]] | None = None,
        allow_skip_unsupported: bool = False,
        sfr: SfrModel | None = None,
    ) -> None:
        self.code = code_image
        self.s = state
        self.trace = trace
        self.watchpoints = watchpoints or set()
        self.stub_calls = stub_calls or {}
        self.allow_skip_unsupported = allow_skip_unsupported
        self.sfr = sfr or SfrModel()

    def fetch(self, addr: int) -> int:
        return self.code.get_byte(addr)

    def _rel(self, offset: int) -> int:
        return offset - 256 if offset & 0x80 else offset

    def _log_instr(self, op: str, args: str, pc: int, acc_before: int, dptr_before: int, notes: str = "") -> None:
        bank = (self.s.psw >> 3) & 0x03
        self.trace.add(
            {
                "step": self.s.step_counter,
                "pc": pc,
                "op": op,
                "args": args,
                "acc_before": f"0x{acc_before:02X}",
                "acc_after": f"0x{self.s.acc:02X}",
                "dptr_before": dptr_before,
                "dptr_after": self.s.dptr,
                "r0": f"0x{self.s.regs[0]:02X}",
                "r1": f"0x{self.s.regs[1]:02X}",
                "r2": f"0x{self.s.regs[2]:02X}",
                "r3": f"0x{self.s.regs[3]:02X}",
                "r4": f"0x{self.s.regs[4]:02X}",
                "r5": f"0x{self.s.regs[5]:02X}",
                "r6": f"0x{self.s.regs[6]:02X}",
                "r7": f"0x{self.s.regs[7]:02X}",
                "trace_type": "instruction",
                "notes": f"bank={bank};{notes}".strip(";"),
            }
        )

    def _sync_regs_from_idata(self) -> None:
        bank = ((self.s.psw >> 3) & 0x03) * 8
        for i in range(8):
            self.s.regs[i] = self.s.idata[(bank + i) & 0xFF] & 0xFF

    def _set_reg(self, n: int, value: int) -> None:
        bank = ((self.s.psw >> 3) & 0x03) * 8
        self.s.idata[(bank + n) & 0xFF] = value & 0xFF
        self._sync_regs_from_idata()

    def _push_stack(self, value: int) -> None:
        self.s.sp = (self.s.sp + 1) & 0xFF
        self.s.idata[self.s.sp] = value & 0xFF
        self.sfr.write(0x81, self.s.sp, step=self.s.step_counter, pc=self.s.pc, notes="stack_sp_update")

    def _pop_stack(self) -> int:
        value = self.s.idata[self.s.sp] & 0xFF
        self.s.sp = (self.s.sp - 1) & 0xFF
        self.sfr.write(0x81, self.s.sp, step=self.s.step_counter, pc=self.s.pc, notes="stack_sp_update")
        return value

    def step(self) -> tuple[bool, str | None]:
        s = self.s
        pc = s.pc
        op = self.fetch(pc)
        acc_before = s.acc
        dptr_before = s.dptr
        self._sync_regs_from_idata()

        if op == 0x74:  # MOV A,#imm
            imm = self.fetch(pc + 1)
            s.acc = imm
            s.pc += 2
            self._log_instr("MOV", f"A,#0x{imm:02X}", pc, acc_before, dptr_before)
            return True, None

        if 0xE8 <= op <= 0xEF:  # MOV A,Rn
            n = op - 0xE8
            s.acc = s.regs[n]
            s.pc += 1
            self._log_instr("MOV", f"A,R{n}", pc, acc_before, dptr_before)
            return True, None

        if 0xF8 <= op <= 0xFF:  # MOV Rn,A
            n = op - 0xF8
            self._set_reg(n, s.acc)
            s.pc += 1
            self._log_instr("MOV", f"R{n},A", pc, acc_before, dptr_before)
            return True, None

        if 0x78 <= op <= 0x7F:  # MOV Rn,#imm
            n = op - 0x78
            imm = self.fetch(pc + 1)
            self._set_reg(n, imm)
            s.pc += 2
            self._log_instr("MOV", f"R{n},#0x{imm:02X}", pc, acc_before, dptr_before)
            return True, None

        if op == 0x90:
            hi = self.fetch(pc + 1)
            lo = self.fetch(pc + 2)
            s.dptr = ((hi << 8) | lo) & 0xFFFF
            s.pc += 3
            self._log_instr("MOV", f"DPTR,#0x{s.dptr:04X}", pc, acc_before, dptr_before)
            return True, None

        if op == 0xF0:
            addr = s.dptr
            prev = s.xdata.get(addr)
            s.xdata[addr] = s.acc
            s.pc += 1
            note = f"watchpoint_hit={addr in self.watchpoints};prev={prev}"
            self._log_instr("MOVX", "@DPTR,A", pc, acc_before, dptr_before, notes=note)
            self.trace.add({"step": s.step_counter, "pc": pc, "op": "MOVX", "args": "@DPTR,A", "xdata_addr": addr, "xdata_value": f"0x{s.acc:02X}", "trace_type": "xdata_write", "notes": note})
            return True, None

        if op == 0xE0:
            addr = s.dptr
            s.acc = s.xdata.get(addr, 0)
            s.pc += 1
            note = f"watchpoint_hit={addr in self.watchpoints}"
            self._log_instr("MOVX", "A,@DPTR", pc, acc_before, dptr_before, notes=note)
            self.trace.add({"step": s.step_counter, "pc": pc, "op": "MOVX", "args": "A,@DPTR", "xdata_addr": addr, "xdata_value": f"0x{s.acc:02X}", "trace_type": "xdata_read", "notes": note})
            return True, None

        if op == 0xA3:
            s.dptr = (s.dptr + 1) & 0xFFFF
            s.pc += 1
            self._log_instr("INC", "DPTR", pc, acc_before, dptr_before)
            return True, None

        if 0x08 <= op <= 0x0F:  # INC Rn
            n = op - 0x08
            self._set_reg(n, (s.regs[n] + 1) & 0xFF)
            s.pc += 1
            self._log_instr("INC", f"R{n}", pc, acc_before, dptr_before)
            return True, None

        if op == 0x23:  # RL A
            s.acc = ((s.acc << 1) | (s.acc >> 7)) & 0xFF
            s.pc += 1
            self._log_instr("RL", "A", pc, acc_before, dptr_before, notes="carry_unchanged=true")
            return True, None

        if op in (0x54, 0x44, 0x64, 0x24):
            imm = self.fetch(pc + 1)
            if op == 0x54:
                s.acc = s.acc & imm
                opname = "ANL"
            elif op == 0x44:
                s.acc = s.acc | imm
                opname = "ORL"
            elif op == 0x64:
                s.acc = s.acc ^ imm
                opname = "XRL"
            else:
                s.acc = (s.acc + imm) & 0xFF
                opname = "ADD"
            s.pc += 2
            self._log_instr(opname, f"A,#0x{imm:02X}", pc, acc_before, dptr_before)
            return True, None

        if op == 0x25:  # ADD A,direct
            direct = self.fetch(pc + 1)
            value = self._read_direct(direct, pc=pc, notes="add_direct")
            s.acc = (s.acc + value) & 0xFF
            s.pc += 2
            self._log_instr("ADD", f"A,0x{direct:02X}", pc, acc_before, dptr_before, notes="direct_read_model=idata_or_sfr")
            return True, None

        if op == 0x35:  # ADDC A,direct
            direct = self.fetch(pc + 1)
            value = self._read_direct(direct, pc=pc, notes="addc_direct")
            carry_in = (s.psw >> 7) & 0x01
            total = (s.acc & 0xFF) + value + carry_in
            s.acc = total & 0xFF
            carry_out = 1 if total > 0xFF else 0
            s.psw = ((s.psw & 0x7F) | (carry_out << 7)) & 0xFF
            self.sfr.write(0xD0, s.psw, step=s.step_counter, pc=pc, notes="addc_carry_update")
            s.pc += 2
            self._log_instr(
                "ADDC",
                f"A,0x{direct:02X}",
                pc,
                acc_before,
                dptr_before,
                notes="direct_read_model=idata_or_sfr;flags_mode=carry_only",
            )
            return True, None

        if op == 0xF5:  # MOV direct,A
            direct = self.fetch(pc + 1)
            self._write_direct(direct, s.acc, pc=pc, notes="mov_direct_a")
            s.pc += 2
            self._log_instr("MOV", f"0x{direct:02X},A", pc, acc_before, dptr_before, notes="direct_write_model=idata_or_sfr")
            return True, None

        if op == 0x75:  # MOV direct,#imm
            direct = self.fetch(pc + 1)
            imm = self.fetch(pc + 2)
            self._write_direct(direct, imm, pc=pc, notes="mov_direct_imm")
            s.pc += 3
            self._log_instr("MOV", f"0x{direct:02X},#0x{imm:02X}", pc, acc_before, dptr_before, notes="direct_write_model=idata_or_sfr")
            return True, None

        if op == 0x84:  # DIV AB
            # Prefer SFR-backed B register when available to stay consistent with direct SFR writes.
            dividend = s.acc & 0xFF
            divisor = self.sfr.get(0xF0, s.b) & 0xFF
            psw_before = s.psw & 0xFF
            # CY is always cleared for DIV AB.
            s.psw = s.psw & 0x7F
            if divisor == 0:
                # Conservative behavior on divide-by-zero:
                # - do not synthesize quotient/remainder values;
                # - keep ACC/B unchanged;
                # - set OV flag and continue execution.
                s.psw = s.psw | 0x04
                self.sfr.write(0xD0, s.psw, step=s.step_counter, pc=pc, notes="div_ab_divide_by_zero;cy_cleared_ov_set")
                s.pc += 1
                self._log_instr(
                    "DIV",
                    "AB",
                    pc,
                    acc_before,
                    dptr_before,
                    notes="divide_by_zero=conservative;acc_b_unchanged=true;flags=cy_clear_ov_set",
                )
                return True, None

            quotient = dividend // divisor
            remainder = dividend % divisor
            s.acc = quotient & 0xFF
            s.b = remainder & 0xFF
            self.sfr.write(0xF0, s.b, step=s.step_counter, pc=pc, notes="div_ab_remainder_write")
            # OV cleared for non-zero divisor case.
            s.psw = s.psw & 0xFB
            if s.psw != psw_before:
                self.sfr.write(0xD0, s.psw, step=s.step_counter, pc=pc, notes="div_ab_flag_update;cy_clear_ov_clear")
            s.pc += 1
            self._log_instr("DIV", "AB", pc, acc_before, dptr_before, notes=f"quotient=0x{s.acc:02X};remainder=0x{s.b:02X}")
            return True, None

        if op == 0x93:  # MOVC A,@A+DPTR
            code_addr = (s.dptr + s.acc) & 0xFFFF
            s.acc = self.fetch(code_addr)
            s.pc += 1
            self.trace.add({"step": s.step_counter, "pc": pc, "op": "MOVC", "args": "A,@A+DPTR", "trace_type": "code_read", "xdata_addr": code_addr, "xdata_value": f"0x{s.acc:02X}", "notes": "code_table_candidate"})
            self._log_instr("MOVC", "A,@A+DPTR", pc, acc_before, dptr_before)
            return True, None

        if op == 0x83:  # MOVC A,@A+PC
            code_addr = (pc + 1 + s.acc) & 0xFFFF
            s.acc = self.fetch(code_addr)
            s.pc += 1
            self.trace.add({"step": s.step_counter, "pc": pc, "op": "MOVC", "args": "A,@A+PC", "trace_type": "code_read", "xdata_addr": code_addr, "xdata_value": f"0x{s.acc:02X}", "notes": "code_table_candidate_pc_relative"})
            self._log_instr("MOVC", "A,@A+PC", pc, acc_before, dptr_before)
            return True, None

        if op == 0xE4:
            s.acc = 0
            s.pc += 1
            self._log_instr("CLR", "A", pc, acc_before, dptr_before)
            return True, None

        if op == 0xB4:  # CJNE A,#imm,rel
            imm = self.fetch(pc + 1)
            rel = self.fetch(pc + 2)
            self._set_carry_for_cjne(s.acc, imm)
            if s.acc != imm:
                s.pc = (pc + 3 + self._rel(rel)) & 0xFFFF
            else:
                s.pc = (pc + 3) & 0xFFFF
            self._log_instr("CJNE", f"A,#0x{imm:02X},{self._rel(rel)}", pc, acc_before, dptr_before)
            return True, None

        if op == 0xB5:  # CJNE A,direct,rel
            direct = self.fetch(pc + 1)
            rel = self.fetch(pc + 2)
            value = self._read_direct(direct, pc=pc, notes="cjne_a_direct")
            self._set_carry_for_cjne(s.acc, value)
            if s.acc != value:
                s.pc = (pc + 3 + self._rel(rel)) & 0xFFFF
            else:
                s.pc = (pc + 3) & 0xFFFF
            self._log_instr("CJNE", f"A,0x{direct:02X},{self._rel(rel)}", pc, acc_before, dptr_before)
            return True, None

        if op in (0xB6, 0xB7):  # CJNE @R0/@R1,#imm,rel
            n = op - 0xB6
            imm = self.fetch(pc + 1)
            rel = self.fetch(pc + 2)
            addr = s.regs[n] & 0xFF
            value = s.idata[addr]
            self._set_carry_for_cjne(value, imm)
            if value != imm:
                s.pc = (pc + 3 + self._rel(rel)) & 0xFFFF
            else:
                s.pc = (pc + 3) & 0xFFFF
            self._log_instr("CJNE", f"@R{n},#0x{imm:02X},{self._rel(rel)}", pc, acc_before, dptr_before)
            return True, None

        if 0xB8 <= op <= 0xBF:  # CJNE Rn,#imm,rel
            n = op - 0xB8
            imm = self.fetch(pc + 1)
            rel = self.fetch(pc + 2)
            value = s.regs[n]
            self._set_carry_for_cjne(value, imm)
            if value != imm:
                s.pc = (pc + 3 + self._rel(rel)) & 0xFFFF
            else:
                s.pc = (pc + 3) & 0xFFFF
            self._log_instr("CJNE", f"R{n},#0x{imm:02X},{self._rel(rel)}", pc, acc_before, dptr_before)
            return True, None

        if op in (0x60, 0x70, 0x80):
            rel = self.fetch(pc + 1)
            do_jump = (op == 0x80) or (op == 0x60 and s.acc == 0) or (op == 0x70 and s.acc != 0)
            s.pc = (pc + 2 + self._rel(rel)) & 0xFFFF if do_jump else (pc + 2) & 0xFFFF
            opname = "SJMP" if op == 0x80 else ("JZ" if op == 0x60 else "JNZ")
            self._log_instr(opname, str(self._rel(rel)), pc, acc_before, dptr_before)
            return True, None

        if op == 0x12:  # LCALL
            hi = self.fetch(pc + 1)
            lo = self.fetch(pc + 2)
            target = ((hi << 8) | lo) & 0xFFFF
            ret = (pc + 3) & 0xFFFF
            self.trace.add({"step": s.step_counter, "pc": pc, "op": "LCALL", "args": f"0x{target:04X}", "trace_type": "call"})
            if target in self.stub_calls:
                self.stub_calls[target](s, self.trace)
                s.pc = ret
                self.trace.add({"step": s.step_counter, "pc": s.pc, "op": "RET(stub)", "args": f"0x{target:04X}", "trace_type": "ret"})
            else:
                self._push_stack(ret & 0xFF)
                self._push_stack((ret >> 8) & 0xFF)
                s.call_stack.append(ret)
                s.pc = target
            self._log_instr("LCALL", f"0x{target:04X}", pc, acc_before, dptr_before)
            return True, None

        if op == 0x02:  # LJMP
            hi = self.fetch(pc + 1)
            lo = self.fetch(pc + 2)
            target = ((hi << 8) | lo) & 0xFFFF
            s.pc = target
            self._log_instr("LJMP", f"0x{target:04X}", pc, acc_before, dptr_before)
            return True, None

        if op == 0x22:
            self.trace.add({"step": s.step_counter, "pc": pc, "op": "RET", "trace_type": "ret"})
            if s.call_stack:
                hi = self._pop_stack()
                lo = self._pop_stack()
                _stack_ret = ((hi << 8) | lo) & 0xFFFF
                s.pc = s.call_stack.pop()
                self._log_instr("RET", "", pc, acc_before, dptr_before)
                return True, None
            s.pc = (pc + 1) & 0xFFFF
            self._log_instr("RET", "", pc, acc_before, dptr_before)
            return False, "ret_from_entry"

        msg = f"unsupported_opcode 0x{op:02X} at 0x{pc:04X}"
        self.trace.add({"step": s.step_counter, "pc": pc, "op": f"0x{op:02X}", "trace_type": "unsupported_opcode", "notes": msg})
        if self.allow_skip_unsupported:
            s.pc = (pc + 1) & 0xFFFF
            self._log_instr("UNSUPPORTED_SKIP", f"0x{op:02X}", pc, acc_before, dptr_before, notes=msg)
            return True, None
        return False, msg

    def _read_direct(self, direct: int, *, pc: int, notes: str = "") -> int:
        if direct >= 0x80:
            return self.sfr.read(direct, step=self.s.step_counter, pc=pc, notes=notes or "direct_sfr_read")
        value = self.s.idata[direct]
        self.trace.add(
            {
                "step": self.s.step_counter,
                "pc": pc,
                "op": "DIRECT",
                "args": f"0x{direct:02X}",
                "xdata_addr": direct,
                "xdata_value": f"0x{value:02X}",
                "trace_type": "direct_memory_read",
                "notes": notes or "direct_idata_read",
            }
        )
        return value

    def _write_direct(self, direct: int, value: int, *, pc: int, notes: str = "") -> None:
        v = value & 0xFF
        if direct >= 0x80:
            self.sfr.write(direct, v, step=self.s.step_counter, pc=pc, notes=notes or "direct_sfr_write")
            if direct in SBUF_CANDIDATE_ADDRS:
                role = "sbuf0_candidate" if direct == 0x99 else "sbuf1_candidate" if direct == 0x9A else "unknown_sfr_uart_candidate"
                self.trace.add(
                    {
                        "step": self.s.step_counter,
                        "pc": pc,
                        "op": "UART_TX_CANDIDATE",
                        "args": f"0x{direct:02X}",
                        "sfr_addr": direct,
                        "sfr_value": f"0x{v:02X}",
                        "trace_type": "uart_sbuf_write",
                        "notes": f"role={role};confidence=low;evidence_level=hypothesis",
                    }
                )
            return

        prev = self.s.idata[direct]
        self.s.idata[direct] = v
        self._sync_regs_from_idata()
        self.trace.add(
            {
                "step": self.s.step_counter,
                "pc": pc,
                "op": "DIRECT",
                "args": f"0x{direct:02X}",
                "xdata_addr": direct,
                "xdata_value": f"0x{v:02X}",
                "trace_type": "direct_memory_write",
                "notes": f"prev=0x{prev:02X};{notes or 'direct_idata_write'}",
            }
        )

    def _set_carry_for_cjne(self, lhs: int, rhs: int) -> None:
        carry = 1 if (lhs & 0xFF) < (rhs & 0xFF) else 0
        self.s.psw = ((self.s.psw & 0x7F) | (carry << 7)) & 0xFF
        self.sfr.write(0xD0, self.s.psw, step=self.s.step_counter, pc=self.s.pc, notes="cjne_carry_update")
