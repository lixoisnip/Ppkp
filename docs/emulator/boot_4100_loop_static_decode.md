# Early boot loop static decode (0x4100..0x4165)

## 0x4000..0x4105
| addr | raw bytes | mnemonic | direct/SFR operands | branch target(s) | evidence label |
|---|---|---|---|---|---|
| 0x4000 | 02 41 00 | LJMP 0x4100 | - | 0x4100 | static_decode + emulation_observed |
| 0x4100 | 75 4E E2 | MOV 0x4E,#0xE2 | direct 0x4E | - | emulation_observed |
| 0x4103 | 75 4F 2E | MOV 0x4F,#0x2E | direct 0x4F | - | emulation_observed |

## 0x4100..0x4165
| addr | raw bytes | mnemonic | direct/SFR operands | branch target(s) | evidence label |
|---|---|---|---|---|---|
| 0x4106 | 90 00 30 | MOV DPTR,#0x0030 | DPTR | - | emulation_observed |
| 0x4109 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | emulation_observed |
| 0x410A | FF | MOV R7,A | R7 | - | emulation_observed |
| 0x410B | A3 | INC DPTR | DPTR | - | emulation_observed |
| 0x410C | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | emulation_observed |
| 0x410D | FE | MOV R6,A | R6 | - | emulation_observed |
| 0x410E | 8E 83 | MOV 0x83,R6 | DPH | - | emulation_observed |
| 0x4110 | 8F 82 | MOV 0x82,R7 | DPL | - | emulation_observed |
| 0x4112 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | emulation_observed |
| 0x4113 | B4 FF 03 | CJNE A,#0xFF,+3 | A compare | 0x4119 (A!=0xFF), 0x4116 (A==0xFF) | emulation_observed |
| 0x4116 | 02 41 5F | LJMP 0x415F | - | 0x415F | static_decode |
| 0x4119 | B4 02 35 | CJNE A,#0x02,+53 | A compare | 0x4151 (A!=0x02), 0x411C (A==0x02) | emulation_observed |
| 0x411C | A3 | INC DPTR | DPTR | - | static_decode |
| 0x411D | A3 | INC DPTR | DPTR | - | static_decode |
| 0x411E | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x411F | FF | MOV R7,A | R7 | - | static_decode |
| 0x4120 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4121 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x4122 | FE | MOV R6,A | R6 | - | static_decode |
| 0x4123 | 8E 82 | MOV 0x82,R6 | DPL | - | static_decode |
| 0x4125 | 8F 83 | MOV 0x83,R7 | DPH | - | static_decode |
| 0x4127 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x4128 | B4 00 03 | CJNE A,#0x00,+3 | A compare | 0x412E (A!=0x00), 0x412B (A==0x00) | static_decode |
| 0x412B | 02 41 5F | LJMP 0x415F | - | 0x415F | static_decode |
| 0x412E | B4 0A 0B | CJNE A,#0x0A,+11 | A compare | 0x413C (A!=0x0A), 0x4131 (A==0x0A) | static_decode |
| 0x4131 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4132 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4133 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4134 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4135 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x4136 | D2 E0 | SETB 0xE0 | ACC bit 0 | - | static_decode |
| 0x4138 | F0 | MOVX @DPTR,A | DPTR (XDATA write) | - | static_decode |
| 0x4139 | 02 41 5F | LJMP 0x415F | - | 0x415F | static_decode |
| 0x413C | A3 | INC DPTR | DPTR | - | static_decode |
| 0x413D | A3 | INC DPTR | DPTR | - | static_decode |
| 0x413E | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x413F | FF | MOV R7,A | R7 | - | static_decode |
| 0x4140 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4141 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x4142 | F5 82 | MOV 0x82,A | DPL | - | static_decode |
| 0x4144 | 8F 83 | MOV 0x83,R7 | DPH | - | static_decode |
| 0x4146 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x4147 | FF | MOV R7,A | R7 | - | static_decode |
| 0x4148 | A3 | INC DPTR | DPTR | - | static_decode |
| 0x4149 | E0 | MOVX A,@DPTR | DPTR (XDATA read) | - | static_decode |
| 0x414A | FE | MOV R6,A | R6 | - | static_decode |
| 0x414B | 8E 82 | MOV 0x82,R6 | DPL | - | static_decode |
| 0x414D | 8F 83 | MOV 0x83,R7 | DPH | - | static_decode |
| 0x414F | 80 D6 | SJMP -42 | - | 0x4127 | static_decode |
| 0x4151 | 74 08 | MOV A,#0x08 | ACC | - | emulation_observed |
| 0x4153 | 25 82 | ADD A,0x82 | ACC + DPL | - | emulation_observed |
| 0x4155 | F5 82 | MOV 0x82,A | DPL | - | emulation_observed |
| 0x4157 | 74 00 | MOV A,#0x00 | ACC | - | emulation_observed |
| 0x4159 | 35 83 | ADDC A,0x83 | ACC + DPH + CY | - | emulation_observed |
| 0x415B | F5 83 | MOV 0x83,A | DPH | - | emulation_observed |
| 0x415D | 80 B3 | SJMP -77 | - | 0x4112 (loop back-edge) | emulation_observed |
| 0x415F | D2 01 | SETB 0x01 | bit-addressable RAM bit 0x01 | - | static_decode |
| 0x4161 | D2 00 | SETB 0x00 | bit-addressable RAM bit 0x00 | - | static_decode |
| 0x4163 | D2 02 | SETB 0x02 | bit-addressable RAM bit 0x02 | - | static_decode |
| 0x4165 | D2 03 | SETB 0x03 | bit-addressable RAM bit 0x03 | - | static_decode |

## 0x4149..0x4165 focus
Back-edge and pointer update path is: `0x4149 -> ... -> 0x415D -> 0x4112`.

## Interpretation answers
- **Real runtime loop or init loop?** Most likely boot initialization/memory traversal loop.
- **Instruction that branches back:** `SJMP -77` at **0x415D** to **0x4112**.
- **Loop exit control:** data-dependent `CJNE` checks on MOVX-fetched bytes (`A` vs `0xFF`, `0x02`, `0x00`, `0x0A`) plus DPL/DPH pointer arithmetic at 0x4153/0x4159.
- **Why `last_pc` ~0x415B:** active path repeatedly executes 0x4151..0x415D each iteration before jumping back.
- **Peripheral flag wait?** Not on current observed path; no `JNB/JB` against UART/timer flags in this loop body.
- **Touches XDATA?** Yes, repeated `MOVX A,@DPTR` reads; static path includes `MOVX @DPTR,A` at 0x4138.
- **Touches UART/SBUF/SCON?** No observed access.
- **Touches P0/P1/P2/P3?** No observed access in this loop.
