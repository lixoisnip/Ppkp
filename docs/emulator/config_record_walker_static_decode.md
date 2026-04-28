# Config record walker static decode (hypothesis-focused)

## Scope
- Early boot validator walk: `0x4100..0x4165` (focus `0x4112..0x415F`).
- Runtime/materialization neighborhood: `0x5710..0x5740` with local context at `0x5717` and `0x5725`.
- Firmware image: `90CYE03_19_DKS.PZU`.
- Evidence labels below are conservative (`static_decode`, `emulation_observed`, `hypothesis`).

## A) Boot config walk decode (`0x4100..0x4165`)

| pc | raw bytes | mnemonic | XDATA address source | pointer/counter regs | compare | branch target(s) | write target | notes |
|---|---|---|---|---|---|---|---|---|
| 0x4106 | 90 00 30 | MOV DPTR,#0x0030 | immediate root pointer location | DPTR | - | - | - | **DPTR init starts from XDATA root bytes** `0x0030..0x0031`. |
| 0x4109 | E0 | MOVX A,@DPTR | DPTR=`0x0030` | A, R7 | - | - | - | reads low byte of record-walk root pointer candidate. |
| 0x410C | E0 | MOVX A,@DPTR | DPTR=`0x0031` | A, R6 | - | - | - | reads high byte of record-walk root pointer candidate. |
| 0x410E | 8E 83 | MOV DPH,R6 | register transfer | R6->DPH | - | - | - | DPTR reconstructed from XDATA[0x0030..0x0031]. |
| 0x4110 | 8F 82 | MOV DPL,R7 | register transfer | R7->DPL | - | - | - | record walker head pointer live in DPTR. |
| 0x4112 | E0 | MOVX A,@DPTR | DPTR (record byte 0 candidate) | A | - | - | - | loop body record-tag read point. |
| 0x4113 | B4 FF 03 | CJNE A,#0xFF,+3 | prior MOVX result | A | `0xFF` | `0x4119` / `0x4116` | - | `A==0xFF` takes immediate exit path to `0x415F`. |
| 0x4116 | 02 41 5F | LJMP 0x415F | - | - | - | `0x415F` | - | boot validation exit path. |
| 0x4119 | B4 02 35 | CJNE A,#0x02,+53 | prior MOVX result | A | `0x02` | `0x411C` / `0x4151` | - | non-`0x02` goes to +8 stride path at `0x4151`. |
| 0x411C | A3 / A3 | INC DPTR / INC DPTR | DPTR relative | DPTR | - | - | - | advances to pointer-like fields inside current record candidate. |
| 0x411E | E0 | MOVX A,@DPTR | DPTR | A,R7 | - | - | - | loads high/low half of nested pointer candidate (order inferred). |
| 0x4121 | E0 | MOVX A,@DPTR | DPTR+1 | A,R6 | - | - | - | second half of nested pointer candidate. |
| 0x4123 | 8E 82 | MOV DPL,R6 | register transfer | R6->DPL | - | - | - | nested pointer install. |
| 0x4125 | 8F 83 | MOV DPH,R7 | register transfer | R7->DPH | - | - | - | nested pointer install complete. |
| 0x4127 | E0 | MOVX A,@DPTR | nested DPTR | A | - | - | - | nested record/tag byte read. |
| 0x4128 | B4 00 03 | CJNE A,#0x00,+3 | prior MOVX result | A | `0x00` | `0x412E` / `0x412B` | - | `A==0x00` forces boot exit to `0x415F`. |
| 0x412B | 02 41 5F | LJMP 0x415F | - | - | - | `0x415F` | - | second explicit exit cause. |
| 0x412E | B4 0A 0B | CJNE A,#0x0A,+11 | prior MOVX result | A | `0x0A` | `0x4131` / `0x413C` | - | `0x0A` takes special short path. |
| 0x4131..0x4134 | A3 x4 | INC DPTR (x4) | DPTR relative | DPTR | - | - | - | skip within nested record candidate. |
| 0x4135 | E0 | MOVX A,@DPTR | DPTR+4 from 0x0A site | A | - | - | - | reads flag-like byte. |
| 0x4136 | D2 E0 | SETB ACC.0 | ACC bit op | ACC | - | - | - | sets bit0 in A. |
| 0x4138 | F0 | MOVX @DPTR,A | DPTR | A | - | - | XDATA[DPTR] | writes patched flag-like byte, then exits. |
| 0x4139 | 02 41 5F | LJMP 0x415F | - | - | - | `0x415F` | - | third explicit exit cause. |
| 0x413C..0x414D | pointer reload sequence | INC/MOVX/MOV | DPTR-relative nested pointer reload | R7,R6,DPTR | - | back to `0x4127` via `0x414F` | - | nested walk/redirect path for non-`0x0A` case. |
| 0x4151 | 74 08 | MOV A,#0x08 | immediate | A | - | - | - | **8-byte stride seed**. |
| 0x4153 | 25 82 | ADD A,DPL | direct reg arithmetic | A,DPL | - | - | - | low-byte pointer += 8. |
| 0x4155 | F5 82 | MOV DPL,A | register write | DPL | - | - | - | stores low-byte stride result. |
| 0x4157 | 74 00 | MOV A,#0x00 | immediate | A | - | - | - | carry-propagation setup. |
| 0x4159 | 35 83 | ADDC A,DPH | direct reg arithmetic | A,DPH,CY | - | - | - | high-byte pointer + carry. |
| 0x415B | F5 83 | MOV DPH,A | register write | DPH | - | - | - | stores high-byte stride result. |
| 0x415D | 80 B3 | SJMP -77 | PC-relative | loop back-edge | - | `0x4112` | - | repeats next record candidate at +8. |
| 0x415F | D2 01 | SETB bit 0x01 | bit-RAM/SFR model | - | - | - | bit write | exit flag set block begins. |
| 0x4161 | D2 00 | SETB bit 0x00 | bit-RAM/SFR model | - | - | - | bit write | exit flag set block continues. |
| 0x4163 | D2 02 | SETB bit 0x02 | bit-RAM/SFR model | - | - | - | bit write | exit flag set block continues. |
| 0x4165 | D2 03 | SETB bit 0x03 | bit-RAM/SFR model | - | - | - | bit write | exit flag set block continues. |

### Explicit answers from static decode
- **How DPTR is initialized:** `MOV DPTR,#0x0030` then `MOVX` reads of `0x0030/0x0031` are copied into `R7/R6` and transferred to `DPL/DPH` at `0x410E..0x4110`.
- **How +8 stride is calculated:** `A=0x08`, `ADD A,DPL`, write DPL, then `A=0x00`, `ADDC A,DPH`, write DPH (`0x4151..0x415B`).
- **What causes `0x415F` exit path:** at least four visible causes: `A==0xFF` at `0x4113`, `A==0x00` at `0x4128`, `A==0x0A` path after flag write at `0x4139`, and any upstream call/flow landing directly at `0x415F`.

## B) Materialization neighborhood (`0x5710..0x5740`, focus on `0x5717` and `0x5725`)

| pc | raw bytes | mnemonic | XDATA address source | pointer/counter regs | compare | branch target(s) | write target | notes |
|---|---|---|---|---|---|---|---|---|
| 0x5710 | 90 31 FF | MOV DPTR,#0x31FF | immediate XDATA base | DPTR | - | - | - | materialization table base candidate. |
| 0x5713 | 78 01 | MOV R0,#0x01 | immediate | R0 | - | - | - | address/index counter candidate starts at 1. |
| 0x5715 | 74 80 | MOV A,#0x80 | immediate | A | - | - | - | per-entry header/status constant candidate. |
| 0x5717 | F0 | MOVX @DPTR,A | DPTR current | A,DPTR | - | - | XDATA[DPTR] | **`0x5717` writes `0x80`** to current entry head (first iteration: `0x31FF`). |
| 0x5718 | 74 06 | MOV A,#0x06 | immediate | A | - | - | - | helper selector constant candidate. |
| 0x571A | 12 5A 7F | LCALL 0x5A7F | call context | - | - | callee `0x5A7F` | - | helper likely computes/positions DPTR context. |
| 0x571D | 74 01 | MOV A,#0x01 | immediate | A | - | - | - | fixed field byte candidate. |
| 0x571F | F0 | MOVX @DPTR,A | DPTR current | A,DPTR | - | - | XDATA[DPTR] | writes fixed `0x01` field candidate. |
| 0x5720 | A3 | INC DPTR | DPTR++ | DPTR | - | - | - | advances record offset. |
| 0x5721 | E4 | CLR A | - | A | - | - | - | zero field setup. |
| 0x5722 | F0 | MOVX @DPTR,A | DPTR current | A,DPTR | - | - | XDATA[DPTR] | writes zero field candidate. |
| 0x5723 | A3 | INC DPTR | DPTR++ | DPTR | - | - | - | advances record offset. |
| 0x5724 | E8 | MOV A,R0 | register source | A,R0 | - | - | - | load running index/address candidate. |
| 0x5725 | F0 | MOVX @DPTR,A | DPTR current | A,DPTR,R0 | - | - | XDATA[DPTR] | **`0x5725` writes sequential R0-like value** (`0x01..` in observed traces). |
| 0x5726 | 08 | INC R0 | register increment | R0 | - | - | - | sequence step (1,2,3...). |
| 0x5727 | A3 | INC DPTR | DPTR++ | DPTR | - | - | - | advances record offset. |
| 0x5728 | EE | MOV A,R6 | register source | A,R6 | - | - | - | type/flag source candidate from caller context. |
| 0x5729 | 20 E0 02 | JB ACC.0,+2 | bit-test | A.bit0 | bit0 | `0x572D` / `0x572C` | - | conditionally zeroes field if bit not set. |
| 0x572C | E4 | CLR A | - | A | - | - | - | fallback write value 0. |
| 0x572D | F0 | MOVX @DPTR,A | DPTR current | A,DPTR | - | - | XDATA[DPTR] | tail field write candidate. |
| 0x572E | 74 07 | MOV A,#0x07 | immediate | A | - | - | - | helper selector constant candidate. |
| 0x5730 | 12 5A 7F | LCALL 0x5A7F | call context | - | - | callee `0x5A7F` | - | likely advances to next logical slot/context. |
| 0x5733 | DB E0 | DJNZ R3,-32 | loop counter branch | R3 | - | `0x5715` / `0x5735` | - | confirms iterative materialization loop. |
| 0x5735 | ED | MOV A,R5 | register source | A,R5 | - | - | - | post-loop branch context. |
| 0x5736 | 30 E0 03 | JNB ACC.0,+3 | bit-test | A.bit0 | bit0 | `0x573C` / `0x5739` | - | runtime path fork after materialization loop. |
| 0x5739 | 02 58 B1 | LJMP 0x58B1 | long branch | - | - | `0x58B1` | - | consumer path candidate. |
| 0x573C | 00 | NOP | - | - | - | - | - | boundary marker before next loop family. |
| 0x573D | 78 00 | MOV R0,#0x00 | immediate | R0 | - | - | - | start of separate 8-slot loop at `0x573D..0x5766` neighborhood. |
| 0x573F | 79 01 | MOV R1,#0x01 | immediate | R1 | - | - | - | second counter seed for later loop. |

### Explicit answers from `0x5717` / `0x5725` neighborhood
- **What `0x5717` writes:** `MOVX @DPTR,A` with immediate `A=0x80` from `0x5715`; first loop iteration targets DPTR initialized from `0x31FF`.
- **What `0x5725` writes:** `MOVX @DPTR,A` where `A` is loaded from `R0` (`0x5724`), and `R0` increments at `0x5726`; observed behavior is sequential address-like values.
- **Same loop or different context?** `0x5717` and `0x5725` are in the **same `DJNZ R3` materialization loop** (`0x5715..0x5733`). A later loop starts at `0x573D` and is a different context.
