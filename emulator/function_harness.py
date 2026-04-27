#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass

from emulator.cpu8051_subset import CPU8051State, CPU8051Subset
from emulator.pzu_memory import CodeImage
from emulator.sfr_model import SfrModel
from emulator.trace import TraceContext, TraceLog


@dataclass
class FunctionRunResult:
    run_id: str
    firmware_file: str
    function_addr: int
    steps: int
    stop_reason: str
    calls_seen: int
    returns_seen: int
    xdata_reads: int
    xdata_writes: int
    unsupported_ops: int
    trace: TraceLog


class FunctionHarness:
    def __init__(self, code: CodeImage, watchpoints: list[int] | None = None) -> None:
        self.code = code
        self.watchpoints = set(watchpoints or [])

    @staticmethod
    def default_stubs(enable: bool = True):
        if not enable:
            return {}

        def stub_597F(s: CPU8051State, _t: TraceLog) -> None:
            s.acc &= 0x07

        def stub_7922(s: CPU8051State, _t: TraceLog) -> None:
            s.regs[0] = s.xdata.get(s.dptr, 0)
            s.regs[1] = s.xdata.get((s.dptr + 1) & 0xFFFF, 0)

        def stub_5A7F(_s: CPU8051State, _t: TraceLog) -> None:
            return

        return {0x597F: stub_597F, 0x7922: stub_7922, 0x5A7F: stub_5A7F}

    def run_function(
        self,
        run_id: str,
        function_addr: int,
        max_steps: int = 500,
        max_calls: int = 64,
        init_regs: dict[str, int] | None = None,
        init_xdata: dict[int, int] | None = None,
        allow_skip_unsupported: bool = False,
        use_stubs: bool = True,
    ) -> FunctionRunResult:
        state = CPU8051State(pc=function_addr)
        sfr = SfrModel()
        sfr.write(0x81, state.sp, step=0, pc=state.pc, notes="init_sp")
        sfr.write(0xD0, state.psw, step=0, pc=state.pc, notes="init_psw")
        if init_regs:
            for k, v in init_regs.items():
                vv = v & 0xFF
                if k == "A":
                    state.acc = vv
                elif k == "DPTR":
                    state.dptr = v & 0xFFFF
                elif k.startswith("R") and k[1:].isdigit():
                    idx = int(k[1:])
                    if 0 <= idx <= 7:
                        state.regs[idx] = vv
                        state.idata[idx] = vv
        if init_xdata:
            state.xdata.update({k & 0xFFFF: v & 0xFF for k, v in init_xdata.items()})

        trace = TraceLog(TraceContext(run_id=run_id, firmware_file=self.code.firmware_file, function_addr=function_addr))
        cpu = CPU8051Subset(
            code_image=self.code,
            state=state,
            trace=trace,
            watchpoints=self.watchpoints,
            stub_calls=self.default_stubs(enable=use_stubs),
            allow_skip_unsupported=allow_skip_unsupported,
            sfr=sfr,
        )

        stop_reason = "max_steps"
        for _ in range(max_steps):
            state.step_counter += 1
            if len(state.call_stack) > max_calls:
                stop_reason = "max_calls"
                break
            cont, reason = cpu.step()
            if not cont:
                stop_reason = reason or "stop"
                break

        rows = trace.rows
        for event in sfr.events:
            trace.add(
                {
                    "step": event.step,
                    "pc": event.pc,
                    "op": "SFR",
                    "args": f"0x{event.sfr_addr:02X}",
                    "sfr_addr": event.sfr_addr,
                    "sfr_value": f"0x{event.value:02X}",
                    "trace_type": "sfr_access",
                    "notes": f"{event.access_type};prev={'' if event.previous_value is None else f'0x{event.previous_value:02X}'};role={event.possible_role};{event.notes}".strip(";"),
                }
            )
        return FunctionRunResult(
            run_id=run_id,
            firmware_file=self.code.firmware_file,
            function_addr=function_addr,
            steps=state.step_counter,
            stop_reason=stop_reason,
            calls_seen=sum(1 for r in rows if r["trace_type"] == "call"),
            returns_seen=sum(1 for r in rows if r["trace_type"] == "ret"),
            xdata_reads=sum(1 for r in rows if r["trace_type"] == "xdata_read"),
            xdata_writes=sum(1 for r in rows if r["trace_type"] == "xdata_write"),
            unsupported_ops=sum(1 for r in rows if r["trace_type"] == "unsupported_opcode"),
            trace=trace,
        )
