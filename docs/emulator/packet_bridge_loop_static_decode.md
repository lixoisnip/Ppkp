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
