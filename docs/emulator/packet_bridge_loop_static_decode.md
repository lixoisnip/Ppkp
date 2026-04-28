# Packet bridge loop static decode

Evidence legend: `static_code`, `emulation_observed`, `unknown`.

## Region 0x5715..0x5733

| code_addr | bytes | decode | branch_target | fallthrough | evidence |
|---|---|---|---|---|---|
| 0x5715 | 74 80 | MOV A,#0x80 | - | 0x5717 | static_code |
| 0x5717 | F0 | MOVX @DPTR,A | - | 0x5718 | static_code |
| 0x5718 | 74 06 | MOV A,#0x06 | - | 0x571A | static_code |
| 0x571A | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | 0x571D | static_code |
| 0x571D | 74 01 | MOV A,#0x01 | - | 0x571F | static_code |
| 0x571F | F0 | MOVX @DPTR,A | - | 0x5720 | static_code |
| 0x5720 | A3 | INC DPTR | - | 0x5721 | static_code |
| 0x5721 | E4 | UNK  | - | 0x5722 | static_code |
| 0x5722 | F0 | MOVX @DPTR,A | - | 0x5723 | static_code |
| 0x5723 | A3 | INC DPTR | - | 0x5724 | static_code |
| 0x5724 | E8 | MOV A,R0 | - | 0x5725 | static_code |
| 0x5725 | F0 | MOVX @DPTR,A | - | 0x5726 | static_code |
| 0x5726 | 08 | INC R0 | - | 0x5727 | static_code |
| 0x5727 | A3 | INC DPTR | - | 0x5728 | static_code |
| 0x5728 | EE | MOV A,R6 | - | 0x5729 | static_code |
| 0x5729 | 20 E0 02 | JB 0xE0,+2 | 0x572E | 0x572C | static_code |
| 0x572C | E4 | UNK  | - | 0x572D | static_code |
| 0x572D | F0 | MOVX @DPTR,A | - | 0x572E | static_code |
| 0x572E | 74 07 | MOV A,#0x07 | - | 0x5730 | static_code |
| 0x5730 | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | 0x5733 | static_code |
| 0x5733 | DB E0 | DJNZ R3,-32 | 0x5715 | 0x5735 | static_code |

## Focus addresses

| code_addr | bytes | decode | branch_target | fallthrough | evidence |
|---|---|---|---|---|---|
| 0x56DE | 20 E0 1B | JB 0xE0,+27 | 0x56FC | 0x56E1 | static_code |
| 0x5729 | 20 E0 02 | JB 0xE0,+2 | 0x572E | 0x572C | static_code |
| 0x5733 | DB E0 | DJNZ R3,-32 | 0x5715 | 0x5735 | static_code |

## Immediate callers/callees around loop

### Incoming branches/calls into 0x5715..0x5733

| from | bytes | decode | target | evidence |
|---|---|---|---|---|
| 0x5729 | 20 E0 02 | JB 0xE0,+2 | 0x572E | static_code |
| 0x5733 | DB E0 | DJNZ R3,-32 | 0x5715 | static_code |

### Outgoing calls/jumps from loop body

| from | bytes | decode | target | evidence |
|---|---|---|---|---|
| 0x571A | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | static_code |
| 0x5730 | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | static_code |

## Forced-loop-exit decode window (post-0x5733)

### Region 0x5733..0x5750

| code_addr | bytes | decode | branch_target | fallthrough | evidence |
|---|---|---|---|---|---|
| 0x5733 | DB E0 | DJNZ R3,-32 | 0x5715 | 0x5735 | static_code |
| 0x5735 | ED | MOV A,R5 | - | 0x5736 | static_code |
| 0x5736 | 30 E0 03 | JNB 0xE0,+3 | 0x573C | 0x5739 | static_code |
| 0x5739 | 02 58 B1 | LJMP 0x58B1 | 0x58B1 | - | static_code |
| 0x573C | 00 | NOP | - | 0x573D | static_code + emulation_observed |
| 0x573D | 78 00 | MOV R0,#0x00 | - | 0x573F | static_code + emulation_observed |
| 0x573F | 79 01 | MOV R1,#0x01 | - | 0x5741 | static_code + emulation_observed |
| 0x5741 | E8 | MOV A,R0 | - | 0x5742 | static_code + emulation_observed |
| 0x5742 | 90 30 E1 | MOV DPTR,#0x30E1 | - | 0x5745 | static_code + emulation_observed |
| 0x5745 | 12 59 35 | LCALL 0x5935 | 0x5935 | 0x5748 | static_code + emulation_observed |
| 0x5748 | 60 1B | JZ +27 | 0x5765 | 0x574A | static_code |
| 0x574A | E8 | MOV A,R0 | - | 0x574B | static_code |
| 0x574B | 90 30 C4 | MOV DPTR,#0x30C4 | - | 0x574E | static_code |
| 0x574E | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | 0x5751 | static_code |

### Slice 0x5735..0x573C

| code_addr | bytes | decode | branch_target | fallthrough | evidence |
|---|---|---|---|---|---|
| 0x5735 | ED | MOV A,R5 | - | 0x5736 | static_code + emulation_observed |
| 0x5736 | 30 E0 03 | JNB 0xE0,+3 | 0x573C | 0x5739 | static_code + emulation_observed |
| 0x5739 | 02 58 B1 | LJMP 0x58B1 | 0x58B1 | - | static_code |
| 0x573C | 00 | NOP | - | 0x573D | static_code + emulation_observed |

### Slice 0x573C..0x5750

| code_addr | bytes | decode | branch_target | fallthrough | evidence |
|---|---|---|---|---|---|
| 0x573C | 00 | NOP | - | 0x573D | static_code + emulation_observed |
| 0x573D | 78 00 | MOV R0,#0x00 | - | 0x573F | static_code + emulation_observed |
| 0x573F | 79 01 | MOV R1,#0x01 | - | 0x5741 | static_code + emulation_observed |
| 0x5741 | E8 | MOV A,R0 | - | 0x5742 | static_code + emulation_observed |
| 0x5742 | 90 30 E1 | MOV DPTR,#0x30E1 | - | 0x5745 | static_code + emulation_observed |
| 0x5745 | 12 59 35 | LCALL 0x5935 | 0x5935 | 0x5748 | static_code + emulation_observed |
| 0x5748 | 60 1B | JZ +27 | 0x5765 | 0x574A | static_code |
| 0x574A | E8 | MOV A,R0 | - | 0x574B | static_code |
| 0x574B | 90 30 C4 | MOV DPTR,#0x30C4 | - | 0x574E | static_code |
| 0x574E | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | 0x5751 | static_code |

### Branch/call targets in this area

| from | decode | target | target_role | evidence |
|---|---|---|---|---|
| 0x5736 | JNB 0xE0,+3 | 0x573C | in-stream fallthrough-aligned code entry | static_code + emulation_observed |
| 0x5739 | LJMP 0x58B1 | 0x58B1 | external branch target outside local window | static_code |
| 0x5745 | LCALL 0x5935 | 0x5935 | callee executed in forced-exit scenarios | static_code + emulation_observed |
| 0x5748 | JZ +27 | 0x5765 | forward local branch beyond shown window | static_code |
| 0x574E | LCALL 0x5A7F | 0x5A7F | previously known helper/callee | static_code |

### 0x573C classification

- `0x573C` is **inside a valid instruction stream**, because `JNB 0xE0,+3` at `0x5736` explicitly targets it and decode alignment remains coherent through `0x574E`. Evidence: `static_code`.
- Byte `0x00` at `0x573C` behaves as **executable NOP**, not dead padding, in forced-loop-exit emulation; execution continues into `0x573D..`. Evidence: `emulation_observed`.
- Local byte pattern near `0x573C` (`00 78 00 79 01 E8 90 30 E1 12 59 35 ...`) matches register setup + call flow, which is characteristic of code, not a data table/padding fill. Evidence: `static_code`.

## Later hotspot check 0x8365..0x837F

| code_addr | bytes | decode | branch_target | fallthrough | evidence |
|---|---|---|---|---|---|
| 0x8365 | E0 | MOVX A,@DPTR | - | 0x8366 | static_code |
| 0x8366 | B5 F0 0E | CJNE A,0xF0,+14 | 0x8377 | 0x8369 | static_code |
| 0x8369 | A3 | INC DPTR | - | 0x836A | static_code |
| 0x836A | E0 | MOVX A,@DPTR | - | 0x836B | static_code |
| 0x836B | 6A 60 | UNK  | - | 0x836D | static_code |
| 0x836D | 07 | UNK  | - | 0x836E | static_code |
| 0x836E | 74 07 | MOV A,#0x07 | - | 0x8370 | static_code |
| 0x8370 | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | 0x8373 | static_code |
| 0x8373 | 80 F0 | SJMP -16 | 0x8365 | - | static_code |
| 0x8376 | 22 | RET  | - | - | static_code |
| 0x8377 | 04 | UNK  | - | 0x8378 | static_code |
| 0x8378 | 60 FC | JZ -4 | 0x8376 | 0x837A | static_code |
| 0x837A | 74 08 | MOV A,#0x08 | - | 0x837C | static_code |
| 0x837C | 12 5A 7F | LCALL 0x5A7F | 0x5A7F | 0x837F | static_code |
| 0x837F | 80 E4 | SJMP -28 | 0x8365 | - | static_code |

## Loop-control interpretation

- Likely loop counter register at `0x5733` is **R3** via `DJNZ R3,-32` (`target=0x5715`). Evidence: static_code.
- Bit tested at `0x5729` is bit address `0xE0`, which maps to **SFR bit space**, byte `0xE0`, bit index `0` => **ACC.0**. Evidence: static_code + emulation_observed.
- Preceding instructions that set/clear tested bit: `0x5715 MOV A,#0x80` and repeated `0x571E RLC A`; these update ACC.0 before `JB`. Evidence: static_code.
- Preceding instructions for counter: `0x571B MOV R3,#0x14` initializes and `0x5733 DJNZ R3,-32` decrements/tests. Evidence: static_code.
- `0xE0` here is ACC.0 (SFR bit), not PSW bit and not IDATA bit-ram. Evidence: static_code.

## Compact downstream decode windows

### Window 0x5765..0x5795

| code_addr | raw bytes | mnemonic | branch/call target | SFR/direct/bit operands | relation_to_0x5A7F | evidence |
|---|---|---|---|---|---|---|
| 0x5765 | 08 B8 08 D8 | INC R0; CJNE R0,#0x08,-40 | branch 0x5765 loop | direct none; bit none | loop prologue before helper calls | static_code + emulation_observed |
| 0x5769 | 78 00 79 01 | MOV R0,#0; MOV R1,#1 | fallthrough 0x576D | direct none | prepares helper index arguments | static_code + emulation_observed |
| 0x576D | E8 90 30 E0 | MOV A,R0; MOV DPTR,#0x30E0 | fallthrough 0x5771 | direct/XDATA pointer 0x30E0 | setup before helper 0x5935 | static_code + emulation_observed |
| 0x5771 | 12 59 35 | LCALL 0x5935 | call 0x5935, ret 0x5774 | none | same helper gate as 0x5745 path | static_code + emulation_observed |
| 0x5774 | 60 1B | JZ +0x1B | target 0x5791 | bit tests A==0 | branch around 0x5A7F call block | static_code + emulation_observed |
| 0x5776 | E8 90 30 B4 12 5A 7F | MOV A,R0; MOV DPTR,#0x30B4; LCALL 0x5A7F | call 0x5A7F | direct/XDATA pointer 0x30B4 | direct post-loop helper invocation | static_code + emulation_observed |
| 0x577D | E0 12 5A A3 | MOVX A,@DPTR; LCALL 0x5AA3 | call 0x5AA3 | XDATA via DPTR | consumes value staged by 0x5A7F path | static_code + emulation_observed |
| 0x5781 | 74 80 F0 74 06 12 5A 7F | MOV A,#0x80; MOVX @DPTR,A; MOV A,#0x06; LCALL 0x5A7F | call 0x5A7F | XDATA write via DPTR | second helper call with literal selector 0x06 | static_code + emulation_observed |
| 0x5789 | 74 05 F0 A3 A3 E9 09 F0 | MOV A,#5; MOVX @DPTR,A; INC DPTR*2; MOV A,R1; INC R1; MOVX @DPTR,A | fallthrough 0x5791 | XDATA writes | staging payload fields after helper path | static_code + emulation_observed |

### Window 0x5791..0x57B5

| code_addr | raw bytes | mnemonic | branch/call target | SFR/direct/bit operands | relation_to_0x5A7F | evidence |
|---|---|---|---|---|---|---|
| 0x5791 | 08 B8 08 D8 | INC R0; CJNE R0,#0x08,-40 | branch 0x5791 loop | none | mirrors prior compact loop template | static_code |
| 0x5795 | 78 00 E8 90 71 0C | MOV R0,#0; MOV A,R0; MOV DPTR,#0x710C | fallthrough | XDATA pointer 0x710C | alternate source table before helper | static_code |
| 0x579B | 12 59 35 | LCALL 0x5935 | call 0x5935, ret 0x579E | none | same zero/nonzero gate helper | static_code |
| 0x579E | 70 1B | JNZ +0x1B | target 0x57BB | A!=0 branch | skips 0x5A7F path when nonzero | static_code |
| 0x57A0 | E8 90 30 AC 12 5A 7F | MOV A,R0; MOV DPTR,#0x30AC; LCALL 0x5A7F | call 0x5A7F | XDATA pointer 0x30AC | helper invocation on alternate buffer base | static_code |
| 0x57A7 | E0 12 5A A3 | MOVX A,@DPTR; LCALL 0x5AA3 | call 0x5AA3 | XDATA via DPTR | same downstream callee pair as 0x577D | static_code |
| 0x57AB | 74 80 F0 74 06 12 5A 7F | literal write + LCALL 0x5A7F | call 0x5A7F | XDATA via DPTR | repeated selector-based helper usage | static_code |
| 0x57B3 | 74 02 F0 | MOV A,#0x02; MOVX @DPTR,A | fallthrough | XDATA write | trailing field update in block | static_code |

### Window 0x58B1..0x58D5

| code_addr | raw bytes | mnemonic | branch/call target | SFR/direct/bit operands | relation_to_0x5A7F | evidence |
|---|---|---|---|---|---|---|
| 0x58B1 | 90 30 12 E4 F0 | MOV DPTR,#0x3012; CLR A; MOVX @DPTR,A | fallthrough | XDATA addr 0x3012 | pre-loop clear in post-loop branch arm | static_code + emulation_observed |
| 0x58B6 | FA EA | MOV R2,A; MOV A,R2 | fallthrough | none | loop/index staging | static_code + emulation_observed |
| 0x58B8 | 11 94 | ACALL 0x5994 | call 0x5994, ret 0x58BA | none | not 0x5A7F; upstream predicate helper | static_code + emulation_observed |
| 0x58BA | 60 0E | JZ +0x0E | target 0x58CA | A==0 branch | selects path that reaches 0x58CA window | static_code + emulation_observed |
| 0x58BC | F5 F0 12 83 5A | MOV 0xF0,A; LCALL 0x835A | call 0x835A | direct 0xF0 (B register) | side helper; no immediate UART/SBUF evidence | static_code + emulation_observed |
| 0x58C1 | 70 07 | JNZ +7 | target 0x58CA | A!=0 branch | converges into 0x58CA path | static_code + emulation_observed |
| 0x58C3 | EA 90 30 12 12 59 4B | MOV A,R2; MOV DPTR,#0x3012; LCALL 0x594B | call 0x594B | XDATA addr 0x3012 | alternate helper before convergence | static_code |
| 0x58CA | 0A BA 08 E9 | INC R2; CJNE R2,#0x08,-23 | back-edge 0x58B8 | none | loop guard entering 0x58CA.. window | static_code + emulation_observed |
| 0x58CE | 7A 00 90 30 12 EA 12 59 | MOV R2,#0; MOV DPTR,#0x3012; MOV A,R2; LCALL 0x5935(partial) | call 0x5935 at 0x58D4.. | XDATA addr 0x3012 | starts second-stage helper sequence | static_code |

### Window 0x58CA..0x58F0

| code_addr | raw bytes | mnemonic | branch/call target | SFR/direct/bit operands | relation_to_0x5A7F | evidence |
|---|---|---|---|---|---|---|
| 0x58CA | 0A BA 08 E9 | INC R2; CJNE R2,#0x08,-23 | target 0x58B8 | none | looped predicate gate before helper chain | static_code + emulation_observed |
| 0x58CE | 7A 00 90 30 12 EA | MOV R2,#0; MOV DPTR,#0x3012; MOV A,R2 | fallthrough | XDATA pointer 0x3012 | setup for helper 0x5935 | static_code |
| 0x58D4 | 12 59 35 60 11 | LCALL 0x5935; JZ +0x11 | target 0x58EA when Z | none | same helper gate pattern controlling downstream 0x5A7F call | static_code |
| 0x58D9 | EA 90 58 A1 12 5D 13 | MOV A,R2; MOV DPTR,#0x58A1; LCALL 0x5D13 | call 0x5D13 | code/data ptr 0x58A1 | external helper before writing 0x31BF path | static_code |
| 0x58E0 | E0 90 31 BF 12 5A 7F | MOVX A,@DPTR; MOV DPTR,#0x31BF; LCALL 0x5A7F | call 0x5A7F | XDATA ptr 0x31BF | explicit post-loop 0x5A7F invocation candidate | static_code + emulation_observed |
| 0x58E7 | 74 01 F0 | MOV A,#1; MOVX @DPTR,A | fallthrough | XDATA write | follow-up state flag after helper call | static_code + emulation_observed |
| 0x58EA | 0A BA 08 E2 | INC R2; CJNE R2,#0x08,-30 | target 0x58BE | none | loops back toward 0x58BE helper region | static_code |
| 0x58EE | 53 8E F8 | ANL 0x8E,#0xF8 | fallthrough | direct SFR 0x8E (serial-control candidate range unknown) | possible control-mask operation; no SBUF writes observed in compact traces | static_code |
