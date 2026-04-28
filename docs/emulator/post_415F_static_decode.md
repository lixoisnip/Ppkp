# Post-0x415F static decode (0x415F..0x41C0)

## Direct linear decode

| addr | raw bytes | mnemonic | direct/SFR/XDATA operands | branch/call target | notes |
|---|---|---|---|---|---|
| 0x415F | D2 01 | SETB 0x01 | 0x01 | - | boot-exit-bit-set |
| 0x4161 | D2 00 | SETB 0x00 | 0x00 | - | boot-exit-bit-set |
| 0x4163 | D2 02 | SETB 0x02 | 0x02 | - | boot-exit-bit-set |
| 0x4165 | D2 03 | SETB 0x03 | 0x03 | - | boot-exit-bit-set |
| 0x4167 | D2 04 | SETB 0x04 | 0x04 | - | - |
| 0x4169 | 90 2F 22 | MOV DPTR,#0x2F22 | DPTR,#0x2F22 | - | - |
| 0x416C | 74 00 | MOV A,#0x00 | A,#0x00 | - | - |
| 0x416E | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x416F | A3 | INC DPTR | DPTR | - | - |
| 0x4170 | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x4171 | A3 | INC DPTR | DPTR | - | - |
| 0x4172 | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x4173 | A3 | INC DPTR | DPTR | - | - |
| 0x4174 | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x4175 | 22 | RET  | - | - | return |
| 0x4176 | 90 00 35 | MOV DPTR,#0x0035 | DPTR,#0x0035 | - | - |
| 0x4179 | E0 | MOVX A,@DPTR | A,@DPTR | - | - |
| 0x417A | 54 0F | ANL A,#0x0F | A,#0x0F | - | - |
| 0x417C | F5 F0 | MOV 0xF0,A | 0xF0,A | - | - |
| 0x417E | A3 | INC DPTR | DPTR | - | - |
| 0x417F | E0 | MOVX A,@DPTR | A,@DPTR | - | - |
| 0x4180 | 54 0F | ANL A,#0x0F | A,#0x0F | - | - |
| 0x4182 | 23 | UNK  | - | - | - |
| 0x4183 | C3 | UNK  | - | - | - |
| 0x4184 | 95 F0 | UNK  | - | - | - |
| 0x4186 | 40 47 | JC +71 | - | 0x41CF | control-flow |
| 0x4188 | C2 00 | CLR 0x00 | 0x00 | - | - |
| 0x418A | 90 2F 25 | MOV DPTR,#0x2F25 | DPTR,#0x2F25 | - | - |
| 0x418D | E0 | MOVX A,@DPTR | A,@DPTR | - | - |
| 0x418E | 24 C8 | ADD A,#0xC8 | A,#0xC8 | - | - |
| 0x4190 | FF | MOV R7,A | - | - | - |
| 0x4191 | 90 2F 24 | MOV DPTR,#0x2F24 | DPTR,#0x2F24 | - | - |
| 0x4194 | E0 | MOVX A,@DPTR | A,@DPTR | - | - |
| 0x4195 | 34 00 | ADDC A,#0x00 | A,#0x00 | - | - |
| 0x4197 | FE | MOV R6,A | - | - | - |
| 0x4198 | C3 | UNK  | - | - | - |
| 0x4199 | EF | MOV A,R7 | - | - | - |
| 0x419A | 94 E8 | SUBB A,#0xE8 | A,#0xE8 | - | - |
| 0x419C | FD | MOV R5,A | - | - | - |
| 0x419D | EE | MOV A,R6 | - | - | - |
| 0x419E | 94 03 | SUBB A,#0x03 | A,#0x03 | - | - |
| 0x41A0 | FC | MOV R4,A | - | - | - |
| 0x41A1 | 50 0F | JNC +15 | - | 0x41B2 | control-flow |
| 0x41A3 | 90 2F 24 | MOV DPTR,#0x2F24 | DPTR,#0x2F24 | - | - |
| 0x41A6 | C2 AF | CLR 0xAF | 0xAF | - | - |
| 0x41A8 | EE | MOV A,R6 | - | - | - |
| 0x41A9 | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x41AA | A3 | INC DPTR | DPTR | - | - |
| 0x41AB | EF | MOV A,R7 | - | - | - |
| 0x41AC | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x41AD | D2 AF | SETB 0xAF | 0xAF | - | - |
| 0x41AF | 02 41 CD | LJMP 0x41CD | 0x41CD | 0x41CD | control-flow |
| 0x41B2 | 90 2F 24 | MOV DPTR,#0x2F24 | DPTR,#0x2F24 | - | - |
| 0x41B5 | EC | MOV A,R4 | - | - | - |
| 0x41B6 | C2 AF | CLR 0xAF | 0xAF | - | - |
| 0x41B8 | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x41B9 | A3 | INC DPTR | DPTR | - | - |
| 0x41BA | ED | MOV A,R5 | - | - | - |
| 0x41BB | F0 | MOVX @DPTR,A | @DPTR,A | - | - |
| 0x41BC | 90 2F 23 | MOV DPTR,#0x2F23 | DPTR,#0x2F23 | - | - |
| 0x41BF | E0 | MOVX A,@DPTR | A,@DPTR | - | - |
| 0x41C0 | 24 01 | ADD A,#0x01 | A,#0x01 | - | - |

## Clarifications

- `0x415F..0x4165` sets four bit-addressable flags (`SETB 0x01`, `SETB 0x00`, `SETB 0x02`, `SETB 0x03`).
- The straight-line path from boot-exit falls through to `0x4175`, where a `RET` is present; this matches dynamic traces (`ret_from_entry` at `ret_pc=0x4175`).
- No `LCALL`/`LJMP` from the observed `0x415F->0x4175` path to runtime hubs (`0x55AD`, `0x5602`, `0x5710`, `0x5A7F`).
- Therefore `0x4100` behaves like a callable init subroutine under this harness; without caller context/return target, execution terminates at entry-boundary RET.
- Full cold-boot handoff may require an outer low-ROM/reset caller context not modeled by direct-entry function harness runs.