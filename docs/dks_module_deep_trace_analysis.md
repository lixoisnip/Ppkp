# DKS module deep-trace analysis (screen-confirmed modules to static code candidates)

Date: 2026-04-27 (UTC).

## Scope and limits

- Scope: static evidence only from repository CSV artifacts; no runtime execution or bench validation.
- Screen-level module presence and code-level handler candidates are separated explicitly.
- Screen evidence does **not** prove exact function addresses.
- MDS is not merged with generic input-board logic without code evidence.
- MUP is not merged with MVK/output logic without code evidence.
- PVK remains unknown module family unless stronger direct code evidence appears.

## Screen-level vs code-level interpretation

- `module_presence_confidence` is derived from DKS screen labels (`confirmed/probable/hypothesis`).
- `function_candidate_confidence` is independent and derived from static features (calls, XDATA, branch traces, chain overlap).
- Evidence levels: `screen_configuration`, `code_direct`, `code_indirect`, `heuristic_only`.

## Per-firmware findings

### ppkp2001 90cye01.PZU
- MASH: 0x758B (mash_event_generation, probable, score=0.670); 0x758B (mash_event_generation, probable, score=0.670); 0xAB62 (mash_event_generation, probable, score=0.572).
- MDS: 0x758B (mds_event_generation, confirmed, score=0.920); 0x53E6 (mds_event_generation, confirmed, score=0.870); 0xA3FD (mds_event_generation, probable, score=0.690).
- PVK: 0x758B (pvk_unknown_dispatcher, hypothesis, score=0.450); 0x53E6 (pvk_unknown_dispatcher, hypothesis, score=0.370); 0xAB62 (pvk_unknown_dispatcher, hypothesis, score=0.352).

### 90CYE02_27 DKS.PZU
- MDS: 0x673C (mds_event_generation, confirmed, score=0.862); 0x673C (mds_event_generation, confirmed, score=0.862); 0x673C (mds_event_generation, confirmed, score=0.862).
- MDS_or_MAS: 0x673C (unknown_module_state_update, hypothesis, score=0.370); 0x497F (unknown_module_dispatcher, hypothesis, score=0.368); 0x8A42 (unknown_module_dispatcher, unknown, score=0.286).
- MZK_or_PZK: 0x673C (unknown_module_state_update, hypothesis, score=0.370); 0x673C (unknown_module_state_update, hypothesis, score=0.370); 0x497F (unknown_module_dispatcher, hypothesis, score=0.368).
- Visible object tags from screen evidence: 90SAE01AA005, 90SAE01AA006, 90SAE06AA002, 90SAE06AA003, 90SAE02AA001, 90SAE05AA007, 90SAE05AA008, 90SAE15AA003, 90SAE15AA004.

### 90CYE03_19_DKS.PZU
- MDS: 0x497A (mds_event_generation, confirmed, score=0.910); 0x613C (mds_event_generation, confirmed, score=0.870); 0x5A7F (mds_event_generation, probable, score=0.550).
- MUP: 0x497A (mup_feedback_check, probable, score=0.838); 0x613C (mup_feedback_check, probable, score=0.798); 0x5A7F (packet_export_bridge, hypothesis, score=0.548).
- PVK: 0x497A (pvk_unknown_dispatcher, hypothesis, score=0.410); 0x613C (pvk_state_or_feedback, hypothesis, score=0.370); 0x84A6 (pvk_unknown_dispatcher, hypothesis, score=0.356).
- unknown_MEK_like: 0x497A (unknown_module_dispatcher, hypothesis, score=0.410); 0x613C (unknown_module_state_update, hypothesis, score=0.370); 0x84A6 (unknown_module_dispatcher, hypothesis, score=0.356).
- unknown_MSHS_like: 0x497A (unknown_module_dispatcher, hypothesis, score=0.410); 0x613C (unknown_module_state_update, hypothesis, score=0.370); 0x84A6 (unknown_module_dispatcher, hypothesis, score=0.356).

### 90CYE04_19_DKS.PZU
- MDS: 0x497A (mds_event_generation, confirmed, score=0.908); 0x613C (mds_event_generation, confirmed, score=0.870); 0x5A7F (mds_state_update, hypothesis, score=0.500).
- MUP: 0x497A (mup_feedback_check, probable, score=0.836); 0x613C (mup_feedback_check, probable, score=0.798); 0x5A7F (packet_export_bridge, hypothesis, score=0.428).
- PVK: 0x497A (pvk_unknown_dispatcher, hypothesis, score=0.408); 0x613C (pvk_state_or_feedback, hypothesis, score=0.370); 0x737C (pvk_unknown_dispatcher, unknown, score=0.238).
- unknown_MEK_like: 0x497A (unknown_module_dispatcher, hypothesis, score=0.408); 0x613C (unknown_module_state_update, hypothesis, score=0.370); 0x737C (unknown_module_dispatcher, unknown, score=0.238).
- unknown_MSHS_like: 0x497A (unknown_module_dispatcher, hypothesis, score=0.408); 0x613C (unknown_module_state_update, hypothesis, score=0.370); 0x737C (unknown_module_dispatcher, unknown, score=0.238).

## Per-module view

### MDS
- ppkp2001 90cye01.PZU X03 -> 0x758B (mds_event_generation, confirmed, code_direct, score=0.920).
- 90CYE03_19_DKS.PZU X03 -> 0x497A (mds_event_generation, confirmed, code_direct, score=0.910).
- 90CYE04_19_DKS.PZU X03 -> 0x497A (mds_event_generation, confirmed, code_direct, score=0.908).
- 90CYE03_19_DKS.PZU X03 -> 0x613C (mds_event_generation, confirmed, code_direct, score=0.870).
- 90CYE04_19_DKS.PZU X03 -> 0x613C (mds_event_generation, confirmed, code_direct, score=0.870).
- ppkp2001 90cye01.PZU X03 -> 0x53E6 (mds_event_generation, confirmed, code_direct, score=0.870).
- 90CYE02_27 DKS.PZU X03 -> 0x673C (mds_event_generation, confirmed, code_direct, score=0.862).
- 90CYE02_27 DKS.PZU X04 -> 0x673C (mds_event_generation, confirmed, code_direct, score=0.862).

### MUP
- 90CYE03_19_DKS.PZU X06 -> 0x497A (mup_feedback_check, probable, code_direct, score=0.838).
- 90CYE04_19_DKS.PZU X06 -> 0x497A (mup_feedback_check, probable, code_direct, score=0.836).
- 90CYE03_19_DKS.PZU X06 -> 0x613C (mup_feedback_check, probable, code_direct, score=0.798).
- 90CYE04_19_DKS.PZU X06 -> 0x613C (mup_feedback_check, probable, code_direct, score=0.798).
- 90CYE03_19_DKS.PZU X06 -> 0x5A7F (packet_export_bridge, hypothesis, code_indirect, score=0.548).
- 90CYE04_19_DKS.PZU X06 -> 0x5A7F (packet_export_bridge, hypothesis, code_indirect, score=0.428).
- 90CYE03_19_DKS.PZU X06 -> 0x84A6 (mup_feedback_check, hypothesis, code_indirect, score=0.426).
- 90CYE03_19_DKS.PZU X06 -> 0x728A (mup_command_builder, hypothesis, code_indirect, score=0.406).

### MASH
- ppkp2001 90cye01.PZU X05 -> 0x758B (mash_event_generation, probable, code_indirect, score=0.670).
- ppkp2001 90cye01.PZU X06 -> 0x758B (mash_event_generation, probable, code_indirect, score=0.670).
- ppkp2001 90cye01.PZU X05 -> 0xAB62 (mash_event_generation, probable, code_indirect, score=0.572).
- ppkp2001 90cye01.PZU X06 -> 0xAB62 (mash_event_generation, probable, code_indirect, score=0.572).

### PVK
- ppkp2001 90cye01.PZU X04 -> 0x758B (pvk_unknown_dispatcher, hypothesis, code_indirect, score=0.450).
- 90CYE03_19_DKS.PZU X07 -> 0x497A (pvk_unknown_dispatcher, hypothesis, code_indirect, score=0.410).
- 90CYE04_19_DKS.PZU X07 -> 0x497A (pvk_unknown_dispatcher, hypothesis, code_indirect, score=0.408).
- 90CYE03_19_DKS.PZU X07 -> 0x613C (pvk_state_or_feedback, hypothesis, code_indirect, score=0.370).
- 90CYE04_19_DKS.PZU X07 -> 0x613C (pvk_state_or_feedback, hypothesis, code_indirect, score=0.370).
- ppkp2001 90cye01.PZU X04 -> 0x53E6 (pvk_unknown_dispatcher, hypothesis, code_indirect, score=0.370).
- 90CYE03_19_DKS.PZU X07 -> 0x84A6 (pvk_unknown_dispatcher, hypothesis, code_indirect, score=0.356).
- ppkp2001 90cye01.PZU X04 -> 0xAB62 (pvk_unknown_dispatcher, hypothesis, code_indirect, score=0.352).

### unknown_MSHS_like
- 90CYE03_19_DKS.PZU X04 -> 0x497A (unknown_module_dispatcher, hypothesis, code_indirect, score=0.410).
- 90CYE04_19_DKS.PZU X04 -> 0x497A (unknown_module_dispatcher, hypothesis, code_indirect, score=0.408).
- 90CYE03_19_DKS.PZU X04 -> 0x613C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE04_19_DKS.PZU X04 -> 0x613C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE03_19_DKS.PZU X04 -> 0x84A6 (unknown_module_dispatcher, hypothesis, code_indirect, score=0.356).
- 90CYE03_19_DKS.PZU X04 -> 0x728A (unknown_module_dispatcher, hypothesis, heuristic_only, score=0.336).
- 90CYE03_19_DKS.PZU X04 -> 0x7017 (unknown_module_dispatcher, hypothesis, heuristic_only, score=0.334).
- 90CYE03_19_DKS.PZU X04 -> 0x737C (unknown_module_dispatcher, hypothesis, heuristic_only, score=0.320).

### unknown_MEK_like
- 90CYE03_19_DKS.PZU X05 -> 0x497A (unknown_module_dispatcher, hypothesis, code_indirect, score=0.410).
- 90CYE04_19_DKS.PZU X05 -> 0x497A (unknown_module_dispatcher, hypothesis, code_indirect, score=0.408).
- 90CYE03_19_DKS.PZU X05 -> 0x613C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE04_19_DKS.PZU X05 -> 0x613C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE03_19_DKS.PZU X05 -> 0x84A6 (unknown_module_dispatcher, hypothesis, code_indirect, score=0.356).
- 90CYE03_19_DKS.PZU X05 -> 0x728A (unknown_module_dispatcher, hypothesis, heuristic_only, score=0.336).
- 90CYE03_19_DKS.PZU X05 -> 0x7017 (unknown_module_dispatcher, hypothesis, heuristic_only, score=0.334).
- 90CYE03_19_DKS.PZU X05 -> 0x737C (unknown_module_dispatcher, hypothesis, heuristic_only, score=0.320).

### MZK_or_PZK
- 90CYE02_27 DKS.PZU X07 -> 0x673C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE02_27 DKS.PZU X08 -> 0x673C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE02_27 DKS.PZU X07 -> 0x497F (unknown_module_dispatcher, hypothesis, code_indirect, score=0.368).
- 90CYE02_27 DKS.PZU X08 -> 0x497F (unknown_module_dispatcher, hypothesis, code_indirect, score=0.368).
- 90CYE02_27 DKS.PZU X07 -> 0x8A42 (unknown_module_dispatcher, unknown, heuristic_only, score=0.286).
- 90CYE02_27 DKS.PZU X08 -> 0x8A42 (unknown_module_dispatcher, unknown, heuristic_only, score=0.286).
- 90CYE02_27 DKS.PZU X07 -> 0x7574 (unknown_module_dispatcher, unknown, heuristic_only, score=0.262).
- 90CYE02_27 DKS.PZU X07 -> 0x774F (unknown_module_dispatcher, unknown, heuristic_only, score=0.262).

### MDS_or_MAS
- 90CYE02_27 DKS.PZU X06 -> 0x673C (unknown_module_state_update, hypothesis, code_indirect, score=0.370).
- 90CYE02_27 DKS.PZU X06 -> 0x497F (unknown_module_dispatcher, hypothesis, code_indirect, score=0.368).
- 90CYE02_27 DKS.PZU X06 -> 0x8A42 (unknown_module_dispatcher, unknown, heuristic_only, score=0.286).
- 90CYE02_27 DKS.PZU X06 -> 0x7574 (unknown_module_dispatcher, unknown, heuristic_only, score=0.262).
- 90CYE02_27 DKS.PZU X06 -> 0x774F (unknown_module_dispatcher, unknown, heuristic_only, score=0.262).
- 90CYE02_27 DKS.PZU X06 -> 0x6DCB (unknown_module_state_update, unknown, heuristic_only, score=0.252).
- 90CYE02_27 DKS.PZU X06 -> 0x7E49 (unknown_module_dispatcher, unknown, heuristic_only, score=0.234).
- 90CYE02_27 DKS.PZU X06 -> 0x8042 (unknown_module_state_update, unknown, heuristic_only, score=0.108).

## 90CYE03/04 MUP vs known 0x728A/0x6833 chain

- Static evidence links `0x728A`, `0x6833`, and `0x5A7F` through manual/auto branch maps and packet adjacency, but this linkage remains `hypothesis` for MUP module attribution.
- `0x728A` appears as a mode gate candidate with manual-like packet-only vs auto-like output+packet split in current artifacts.
- `0x6833` appears on the auto-like output-start side, but this does not by itself prove MUP handler identity.
- `0x5A7F` is treated as packet/export bridge adjacency, not module identity proof.

## DKS object-status layer

- In `90CYE02_27 DKS.PZU`, screen evidence shows object tags: 90SAE01AA005, 90SAE01AA006, 90SAE06AA002, 90SAE06AA003, 90SAE02AA001, 90SAE05AA007, 90SAE05AA008, 90SAE15AA003, 90SAE15AA004.
- Current static artifacts support existence of an object-status/state-event layer, but physical meaning of each object tag is unknown.
- Candidate state/event/packet paths are reported as probable/hypothesis only; no physical semantics are assigned without direct code/string evidence.

## Next manual decompile targets

- MDS: ppkp2001 90cye01.PZU:0x758B (0.920), 90CYE03_19_DKS.PZU:0x497A (0.910), 90CYE04_19_DKS.PZU:0x497A (0.908), 90CYE03_19_DKS.PZU:0x613C (0.870), 90CYE04_19_DKS.PZU:0x613C (0.870).
- MUP: 90CYE03_19_DKS.PZU:0x497A (0.838), 90CYE04_19_DKS.PZU:0x497A (0.836), 90CYE03_19_DKS.PZU:0x613C (0.798), 90CYE04_19_DKS.PZU:0x613C (0.798), 90CYE03_19_DKS.PZU:0x5A7F (0.548).
- MASH: ppkp2001 90cye01.PZU:0x758B (0.670), ppkp2001 90cye01.PZU:0x758B (0.670), ppkp2001 90cye01.PZU:0xAB62 (0.572), ppkp2001 90cye01.PZU:0xAB62 (0.572).
- PVK: ppkp2001 90cye01.PZU:0x758B (0.450), 90CYE03_19_DKS.PZU:0x497A (0.410), 90CYE04_19_DKS.PZU:0x497A (0.408), 90CYE03_19_DKS.PZU:0x613C (0.370), 90CYE04_19_DKS.PZU:0x613C (0.370).
- object-status layer: 0x673C (MDS, 0.862), 0x673C (MDS, 0.862), 0x673C (MDS, 0.862), 0x497F (MDS, 0.860), 0x497F (MDS, 0.860).
