# Global packet/runtime pipeline mining

This report is **global branch-wide static analysis** and **not a packet format proof**.
All conclusions are marked with confidence and may require runtime validation.

## Scope

Analyzed branches: A03_A04, 90CYE_DKS, 90CYE_v2_1, 90CYE_shifted_DKS, RTOS_service.
Input evidence is sourced from smoke-tested pipeline artifacts (smoke pass 31/31 commands).

## Branch: A03_A04
- branch confidence (from branch comparison): high; checksum_error_count=0
- xdata clusters: ui_object_state:0x3292-0x329C(confirmed); packet_path_window:0x4EAB-0x5003(likely); upper_xdata_flags:0x7FF2-0x7FF6(likely)

### Top runtime dispatcher candidates
- 1. A04_28.PZU:0x497A score=22.595 confidence=high role=dispatcher_or_router
- 2. A03_26.PZU:0x497A score=21.341 confidence=high role=dispatcher_or_router
- 3. A03_26.PZU:0xA900 score=13.038 confidence=high role=dispatcher_or_router
- 4. A04_28.PZU:0xB310 score=12.273 confidence=high role=dispatcher_or_router
- 5. A04_28.PZU:0x722E score=10.903 confidence=high role=state_update_worker

### Top packet/service worker candidates
- 1. A04_28.PZU:0x497A score=24.205 confidence=high role=dispatcher_or_router
- 2. A03_26.PZU:0x497A score=22.898 confidence=high role=dispatcher_or_router
- 3. A04_28.PZU:0x722E score=17.285 confidence=high role=state_update_worker
- 4. A03_26.PZU:0xA900 score=12.323 confidence=high role=dispatcher_or_router
- 5. A04_28.PZU:0xB310 score=11.374 confidence=high role=dispatcher_or_router

### Top xdata writer candidates
- 1. A04_28.PZU:0x497A score=24.625 confidence=high role=dispatcher_or_router
- 2. A03_26.PZU:0x497A score=23.500 confidence=high role=dispatcher_or_router
- 3. A04_28.PZU:0x722E score=20.255 confidence=high role=state_update_worker
- 4. A03_26.PZU:0x7339 score=13.639 confidence=high role=state_update_worker
- 5. A03_26.PZU:0x8904 score=10.688 confidence=high role=dispatcher_or_router

### Top xdata reader candidates
- 1. A04_28.PZU:0x722E score=41.265 confidence=high role=state_update_worker
- 2. A03_26.PZU:0x7339 score=26.040 confidence=high role=state_update_worker
- 3. A04_28.PZU:0x497A score=23.912 confidence=high role=dispatcher_or_router
- 4. A03_26.PZU:0x497A score=22.862 confidence=high role=dispatcher_or_router
- 5. A04_28.PZU:0x950F score=22.334 confidence=high role=state_update_worker

### Top table/string/MOVC candidates
- 1. A04_28.PZU:0x497A score=15.162 confidence=high role=dispatcher_or_router
- 2. A03_26.PZU:0x497A score=13.812 confidence=high role=dispatcher_or_router
- 3. A04_28.PZU:0x722E score=5.796 confidence=high role=state_update_worker
- 4. A03_26.PZU:0x800B score=5.637 confidence=high role=dispatcher_or_router
- 5. A04_28.PZU:0x7F5B score=5.487 confidence=high role=dispatcher_or_router

### Top call hubs
- 1. A04_28.PZU:0x497A score=23.837 confidence=high role=dispatcher_or_router
- 2. A03_26.PZU:0x497A score=22.375 confidence=high role=dispatcher_or_router
- 3. A03_26.PZU:0xA900 score=16.350 confidence=high role=dispatcher_or_router
- 4. A04_28.PZU:0xB310 score=15.750 confidence=high role=dispatcher_or_router
- 5. A03_26.PZU:0x800B score=11.400 confidence=high role=dispatcher_or_router

### Top candidate chains (caller -> core -> callee)
- #1 A03_26.PZU: 0x497A -> 0xA900 -> 0x800B chain_score=15.249 confidence=high
- #2 A04_28.PZU: 0x497A -> 0xB310 -> 0x7F5B chain_score=15.158 confidence=high
- #3 A03_26.PZU: 0x497A -> 0xA900 -> 0x8904 chain_score=15.070 confidence=high
- #4 A04_28.PZU: 0x497A -> 0xB310 -> 0x889F chain_score=14.802 confidence=high
- #5 A04_28.PZU: 0x497A -> 0x714C -> 0x722E chain_score=14.188 confidence=high

## Branch: 90CYE_DKS
- branch confidence (from branch comparison): high; checksum_error_count=0
- xdata clusters: dks_runtime_block:0x30EA-0x30F9(confirmed); dks_snapshot_pair:0x3122-0x3125(likely); dks_service_window:0x360C-0x36D3(likely)

### Top runtime dispatcher candidates
- 1. 90CYE03_19_DKS.PZU:0x497A score=23.531 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_DKS.PZU:0x497A score=23.531 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_DKS.PZU:0x84A6 score=11.179 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_DKS.PZU:0x84A6 score=11.179 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_DKS.PZU:0x7017 score=8.949 confidence=high role=dispatcher_or_router

### Top packet/service worker candidates
- 1. 90CYE03_19_DKS.PZU:0x497A score=30.142 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_DKS.PZU:0x497A score=30.142 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_DKS.PZU:0x613C score=11.186 confidence=high role=state_update_worker
- 4. 90CYE04_19_DKS.PZU:0x613C score=11.186 confidence=high role=state_update_worker
- 5. 90CYE03_19_DKS.PZU:0x7017 score=11.030 confidence=high role=dispatcher_or_router

### Top xdata writer candidates
- 1. 90CYE03_19_DKS.PZU:0x497A score=38.688 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_DKS.PZU:0x497A score=38.688 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_DKS.PZU:0x613C score=14.028 confidence=high role=state_update_worker
- 4. 90CYE04_19_DKS.PZU:0x613C score=14.028 confidence=high role=state_update_worker
- 5. 90CYE03_19_DKS.PZU:0x737C score=11.262 confidence=high role=dispatcher_or_router

### Top xdata reader candidates
- 1. 90CYE03_19_DKS.PZU:0x497A score=34.400 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_DKS.PZU:0x497A score=34.400 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_DKS.PZU:0x613C score=26.334 confidence=high role=state_update_worker
- 4. 90CYE04_19_DKS.PZU:0x613C score=26.334 confidence=high role=state_update_worker
- 5. 90CYE03_19_DKS.PZU:0x7D85 score=24.066 confidence=high role=state_update_worker

### Top table/string/MOVC candidates
- 1. 90CYE03_19_DKS.PZU:0x497A score=11.712 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_DKS.PZU:0x497A score=11.712 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_DKS.PZU:0x737C score=5.487 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_DKS.PZU:0x737C score=5.487 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_DKS.PZU:0x728A score=4.213 confidence=high role=dispatcher_or_router

### Top call hubs
- 1. 90CYE03_19_DKS.PZU:0x497A score=15.100 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_DKS.PZU:0x497A score=15.100 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_DKS.PZU:0x84A6 score=14.375 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_DKS.PZU:0x84A6 score=14.375 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_DKS.PZU:0x5A7F score=12.920 confidence=high role=unknown

### Top candidate chains (caller -> core -> callee)
- #1 90CYE03_19_DKS.PZU: 0x497A -> 0x60E4 -> 0x613C chain_score=12.165 confidence=high
- #2 90CYE04_19_DKS.PZU: 0x497A -> 0x60E4 -> 0x613C chain_score=12.165 confidence=high
- #3 90CYE03_19_DKS.PZU: 0x84A6 -> 0x7017 -> 0x84A6 chain_score=11.918 confidence=high
- #4 90CYE04_19_DKS.PZU: 0x84A6 -> 0x7017 -> 0x84A6 chain_score=11.918 confidence=high
- #5 90CYE03_19_DKS.PZU: 0x84A6 -> 0x737C -> 0x84A6 chain_score=11.722 confidence=high

## Branch: 90CYE_v2_1
- branch confidence (from branch comparison): high; checksum_error_count=0
- xdata clusters: v2_state_block:0x315D-0x3195(confirmed); v2_object_window:0x3270-0x32D7(confirmed); v2_payload_window:0x449D-0x462D(likely); v2_upper_markers:0x740C-0x740F(likely)

### Top runtime dispatcher candidates
- 1. 90CYE03_19_2 v2_1.PZU:0x497F score=22.532 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_2 v2_1.PZU:0x497F score=22.532 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_2 v2_1.PZU:0xAA96 score=15.019 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_2 v2_1.PZU:0xAA96 score=15.019 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_2 v2_1.PZU:0x9F46 score=12.590 confidence=high role=dispatcher_or_router

### Top packet/service worker candidates
- 1. 90CYE03_19_2 v2_1.PZU:0x497F score=24.807 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_2 v2_1.PZU:0x497F score=24.807 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_2 v2_1.PZU:0x9F46 score=15.763 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_2 v2_1.PZU:0x9F46 score=15.763 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_2 v2_1.PZU:0xAA96 score=15.023 confidence=high role=dispatcher_or_router

### Top xdata writer candidates
- 1. 90CYE03_19_2 v2_1.PZU:0x497F score=26.025 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_2 v2_1.PZU:0x497F score=26.025 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_2 v2_1.PZU:0x90B6 score=14.012 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_2 v2_1.PZU:0x90B6 score=14.012 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_2 v2_1.PZU:0x9F46 score=12.150 confidence=high role=dispatcher_or_router

### Top xdata reader candidates
- 1. 90CYE03_19_2 v2_1.PZU:0x9F46 score=31.312 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_2 v2_1.PZU:0x9F46 score=31.312 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_2 v2_1.PZU:0x84FA score=28.297 confidence=high role=state_update_worker
- 4. 90CYE04_19_2 v2_1.PZU:0x84FA score=28.297 confidence=high role=state_update_worker
- 5. 90CYE03_19_2 v2_1.PZU:0x497F score=26.188 confidence=high role=dispatcher_or_router

### Top table/string/MOVC candidates
- 1. 90CYE03_19_2 v2_1.PZU:0x497F score=14.262 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_2 v2_1.PZU:0x497F score=14.262 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_2 v2_1.PZU:0xA7FB score=6.930 confidence=high role=state_reader_or_packet_builder
- 4. 90CYE04_19_2 v2_1.PZU:0xA7FB score=6.930 confidence=high role=state_reader_or_packet_builder
- 5. 90CYE03_19_2 v2_1.PZU:0x8BE5 score=5.787 confidence=high role=dispatcher_or_router

### Top call hubs
- 1. 90CYE03_19_2 v2_1.PZU:0x497F score=22.488 confidence=high role=dispatcher_or_router
- 2. 90CYE04_19_2 v2_1.PZU:0x497F score=22.488 confidence=high role=dispatcher_or_router
- 3. 90CYE03_19_2 v2_1.PZU:0xAA96 score=17.413 confidence=high role=dispatcher_or_router
- 4. 90CYE04_19_2 v2_1.PZU:0xAA96 score=17.413 confidence=high role=dispatcher_or_router
- 5. 90CYE03_19_2 v2_1.PZU:0x72AC score=12.663 confidence=high role=unknown

### Top candidate chains (caller -> core -> callee)
- #1 90CYE03_19_2 v2_1.PZU: 0xAA96 -> 0x90B6 -> 0x9F46 chain_score=14.004 confidence=high
- #2 90CYE04_19_2 v2_1.PZU: 0xAA96 -> 0x90B6 -> 0x9F46 chain_score=14.004 confidence=high
- #3 90CYE03_19_2 v2_1.PZU: 0xAA96 -> 0x8D3B -> 0xAA96 chain_score=12.077 confidence=high
- #4 90CYE04_19_2 v2_1.PZU: 0xAA96 -> 0x8D3B -> 0xAA96 chain_score=12.077 confidence=high
- #5 90CYE03_19_2 v2_1.PZU: 0xAA96 -> 0x9F46 -> 0x78EB chain_score=11.889 confidence=high

## Branch: 90CYE_shifted_DKS
- branch confidence (from branch comparison): medium; checksum_error_count=0
- xdata clusters: n/a

### Top runtime dispatcher candidates
- 1. 90CYE02_27 DKS.PZU:0x497F score=19.248 confidence=high role=dispatcher_or_router
- 2. 90CYE02_27 DKS.PZU:0x8A42 score=9.283 confidence=high role=dispatcher_or_router
- 3. 90CYE02_27 DKS.PZU:0x745A score=8.648 confidence=high role=dispatcher_or_router
- 4. 90CYE02_27 DKS.PZU:0x673C score=7.679 confidence=high role=state_update_worker
- 5. 90CYE02_27 DKS.PZU:0x7E49 score=7.663 confidence=high role=dispatcher_or_router

### Top packet/service worker candidates
- 1. 90CYE02_27 DKS.PZU:0x497F score=20.502 confidence=high role=dispatcher_or_router
- 2. 90CYE02_27 DKS.PZU:0x673C score=12.288 confidence=high role=state_update_worker
- 3. 90CYE02_27 DKS.PZU:0x7E49 score=9.334 confidence=high role=dispatcher_or_router
- 4. 90CYE02_27 DKS.PZU:0x774F score=8.618 confidence=high role=dispatcher_or_router
- 5. 90CYE02_27 DKS.PZU:0x8A42 score=7.848 confidence=high role=dispatcher_or_router

### Top xdata writer candidates
- 1. 90CYE02_27 DKS.PZU:0x497F score=22.037 confidence=high role=dispatcher_or_router
- 2. 90CYE02_27 DKS.PZU:0x673C score=14.816 confidence=high role=state_update_worker
- 3. 90CYE02_27 DKS.PZU:0x774F score=9.150 confidence=high role=dispatcher_or_router
- 4. 90CYE02_27 DKS.PZU:0x7E49 score=7.338 confidence=high role=dispatcher_or_router
- 5. 90CYE02_27 DKS.PZU:0x745A score=5.525 confidence=high role=dispatcher_or_router

### Top xdata reader candidates
- 1. 90CYE02_27 DKS.PZU:0x673C score=30.314 confidence=high role=state_update_worker
- 2. 90CYE02_27 DKS.PZU:0x497F score=19.512 confidence=high role=dispatcher_or_router
- 3. 90CYE02_27 DKS.PZU:0x7E49 score=15.650 confidence=high role=dispatcher_or_router
- 4. 90CYE02_27 DKS.PZU:0x6DCB score=14.123 confidence=high role=state_update_worker
- 5. 90CYE02_27 DKS.PZU:0x774F score=13.325 confidence=high role=dispatcher_or_router

### Top table/string/MOVC candidates
- 1. 90CYE02_27 DKS.PZU:0x497F score=13.062 confidence=high role=dispatcher_or_router
- 2. 90CYE02_27 DKS.PZU:0x745A score=5.787 confidence=high role=dispatcher_or_router
- 3. 90CYE02_27 DKS.PZU:0x7574 score=3.612 confidence=high role=dispatcher_or_router
- 4. 90CYE02_27 DKS.PZU:0x8A42 score=3.462 confidence=high role=dispatcher_or_router
- 5. 90CYE02_27 DKS.PZU:0x72E4 score=3.372 confidence=high role=code_table_or_ui_worker

### Top call hubs
- 1. 90CYE02_27 DKS.PZU:0x497F score=20.500 confidence=high role=dispatcher_or_router
- 2. 90CYE02_27 DKS.PZU:0x8A42 score=13.088 confidence=high role=dispatcher_or_router
- 3. 90CYE02_27 DKS.PZU:0x745A score=12.000 confidence=high role=dispatcher_or_router
- 4. 90CYE02_27 DKS.PZU:0x7574 score=7.500 confidence=high role=dispatcher_or_router
- 5. 90CYE02_27 DKS.PZU:0x604B score=7.372 confidence=high role=unknown

### Top candidate chains (caller -> core -> callee)
- #1 90CYE02_27 DKS.PZU: 0x497F -> 0x8A42 -> 0x745A chain_score=12.876 confidence=high
- #2 90CYE02_27 DKS.PZU: 0x497F -> 0x8A42 -> 0x774F chain_score=12.163 confidence=high
- #3 90CYE02_27 DKS.PZU: 0x497F -> 0x8A42 -> 0x7574 chain_score=11.751 confidence=high
- #4 90CYE02_27 DKS.PZU: 0x497F -> 0x8A42 -> 0x7E49 chain_score=11.710 confidence=high
- #5 90CYE02_27 DKS.PZU: 0x497F -> 0x6667 -> 0x673C chain_score=11.463 confidence=high

## Branch: RTOS_service
- branch confidence (from branch comparison): high; checksum_error_count=2
- xdata clusters: rtos_dispatch_core:0x6406-0x6422(confirmed); rtos_service_flags:0x759C-0x75AE(confirmed); rtos_secondary_flags:0x769C-0x76AA(likely)

### Top runtime dispatcher candidates
- 1. ppkp2001 90cye01.PZU:0x758B score=44.622 confidence=medium role=dispatcher_or_router
- 2. ppkp2012 a01.PZU:0x5436 score=38.951 confidence=medium role=dispatcher_or_router
- 3. ppkp2001 90cye01.PZU:0x53E6 score=38.715 confidence=medium role=dispatcher_or_router
- 4. ppkp2012 a01.PZU:0x75F7 score=38.150 confidence=medium role=dispatcher_or_router
- 5. ppkp2019 a02.PZU:0x57DB score=31.790 confidence=medium role=dispatcher_or_router

### Top packet/service worker candidates
- 1. ppkp2001 90cye01.PZU:0x758B score=66.591 confidence=medium role=dispatcher_or_router
- 2. ppkp2012 a01.PZU:0x5436 score=58.385 confidence=medium role=dispatcher_or_router
- 3. ppkp2001 90cye01.PZU:0x53E6 score=57.952 confidence=medium role=dispatcher_or_router
- 4. ppkp2012 a01.PZU:0x75F7 score=56.716 confidence=medium role=dispatcher_or_router
- 5. ppkp2019 a02.PZU:0x57DB score=46.534 confidence=medium role=dispatcher_or_router

### Top xdata writer candidates
- 1. ppkp2001 90cye01.PZU:0x758B score=68.787 confidence=medium role=dispatcher_or_router
- 2. ppkp2012 a01.PZU:0x5436 score=55.975 confidence=medium role=dispatcher_or_router
- 3. ppkp2001 90cye01.PZU:0x53E6 score=54.288 confidence=medium role=dispatcher_or_router
- 4. ppkp2012 a01.PZU:0x75F7 score=49.087 confidence=medium role=dispatcher_or_router
- 5. ppkp2019 a02.PZU:0x57DB score=39.662 confidence=medium role=dispatcher_or_router

### Top xdata reader candidates
- 1. ppkp2001 90cye01.PZU:0x53E6 score=122.763 confidence=medium role=dispatcher_or_router
- 2. ppkp2012 a01.PZU:0x5436 score=122.463 confidence=medium role=dispatcher_or_router
- 3. ppkp2001 90cye01.PZU:0x758B score=99.288 confidence=medium role=dispatcher_or_router
- 4. ppkp2019 a02.PZU:0x57DB score=98.825 confidence=medium role=dispatcher_or_router
- 5. ppkp2012 a01.PZU:0x75F7 score=98.388 confidence=medium role=dispatcher_or_router

### Top table/string/MOVC candidates
- 1. ppkp2001 90cye01.PZU:0x758B score=22.062 confidence=medium role=dispatcher_or_router
- 2. ppkp2012 a01.PZU:0xAB52 score=18.988 confidence=medium role=dispatcher_or_router
- 3. ppkp2012 a01.PZU:0x75F7 score=15.613 confidence=medium role=dispatcher_or_router
- 4. ppkp2001 90cye01.PZU:0xA3FD score=15.088 confidence=medium role=dispatcher_or_router
- 5. ppkp2019 a02.PZU:0xA9C5 score=12.237 confidence=medium role=dispatcher_or_router

### Top call hubs
- 1. ppkp2019 a02.PZU:0xAF92 score=21.263 confidence=medium role=dispatcher_or_router
- 2. ppkp2019 a02.PZU:0x92EF score=19.114 confidence=medium role=unknown
- 3. ppkp2012 a01.PZU:0xB606 score=19.087 confidence=medium role=dispatcher_or_router
- 4. ppkp2001 90cye01.PZU:0xAB62 score=16.575 confidence=medium role=dispatcher_or_router
- 5. ppkp2012 a01.PZU:0x95B0 score=14.820 confidence=medium role=unknown

### Top candidate chains (caller -> core -> callee)
- #1 ppkp2001 90cye01.PZU: 0xAB62 -> 0x758B -> 0x8FAF chain_score=32.690 confidence=medium
- #2 ppkp2012 a01.PZU: 0xB606 -> 0x75F7 -> 0x95D3 chain_score=30.012 confidence=medium
- #3 ppkp2001 90cye01.PZU: 0xAB62 -> 0xAB62 -> 0x758B chain_score=27.867 confidence=medium
- #4 ppkp2012 a01.PZU: 0x44FE -> 0x5436 -> 0x4A9E chain_score=27.036 confidence=medium
- #5 ppkp2001 90cye01.PZU: 0x44F1 -> 0x53E6 -> 0x4A3B chain_score=26.863 confidence=medium

## A03/A04 scoped notes
- A03/A04-specific address evidence is **scoped** and is not used as a global criterion for all branches.
- Known A04 packet-window direct writes (0x5003..0x5010 scope): 3 confirmed static rows (scoped evidence).
- A03 direct packet-window writes in same scoped dataset: 0 rows (currently none observed).

## RTOS_service scoped notes
- Branch remains promising because it has multi-file runtime/service footprint and high call density.
- However, checksum errors in part of RTOS_service files limit confidence for cross-file conclusions.
- Prioritized RTOS_service candidate functions: 0x758B, 0x5436, 0x53E6, 0x75F7, 0x57DB.
- Prioritized RTOS_service chains: 0xAB62->0x758B->0x8FAF; 0xB606->0x75F7->0x95D3; 0xAB62->0xAB62->0x758B.

## 90CYE_DKS runtime-cluster notes
- Runtime clusters from branch map: dks_runtime_block:0x30EA-0x30F9(confirmed); dks_snapshot_pair:0x3122-0x3125(likely); dks_service_window:0x360C-0x36D3(likely)
- Strong writer candidates: 90CYE03_19_DKS.PZU:0x497A, 90CYE04_19_DKS.PZU:0x497A, 90CYE03_19_DKS.PZU:0x613C
- Strong service/runtime candidates: 90CYE03_19_DKS.PZU:0x497A, 90CYE04_19_DKS.PZU:0x497A, 90CYE03_19_DKS.PZU:0x613C

## 90CYE_v2_1 runtime-cluster notes
- Runtime clusters from branch map: v2_state_block:0x315D-0x3195(confirmed); v2_object_window:0x3270-0x32D7(confirmed); v2_payload_window:0x449D-0x462D(likely); v2_upper_markers:0x740C-0x740F(likely)
- Strong writer candidates: 90CYE03_19_2 v2_1.PZU:0x497F, 90CYE04_19_2 v2_1.PZU:0x497F, 90CYE03_19_2 v2_1.PZU:0x90B6
- Strong service/runtime candidates: 90CYE03_19_2 v2_1.PZU:0x497F, 90CYE04_19_2 v2_1.PZU:0x497F, 90CYE03_19_2 v2_1.PZU:0x9F46

## Branch ranking for next deep reverse milestone
1. **RTOS_service**
   - reason: dispatcher_avg=30.82, chain_avg=28.89
   - risks: checksum_error files reduce confidence
   - recommended next concrete functions: 0x758B, 0x5436, 0x53E6, 0x75F7
2. **90CYE_v2_1**
   - reason: dispatcher_avg=15.51, chain_avg=12.81
   - risks: static-only evidence; runtime validation needed
   - recommended next concrete functions: 0x497F, 0x497F, 0x9F46, 0x9F46
3. **A03_A04**
   - reason: dispatcher_avg=13.20, chain_avg=14.89
   - risks: static-only evidence; runtime validation needed
   - recommended next concrete functions: 0x497A, 0x497A, 0x722E, 0xA900
4. **90CYE_DKS**
   - reason: dispatcher_avg=13.06, chain_avg=11.98
   - risks: static-only evidence; runtime validation needed
   - recommended next concrete functions: 0x497A, 0x497A, 0x613C, 0x613C
5. **90CYE_shifted_DKS**
   - reason: dispatcher_avg=8.99, chain_avg=11.99
   - risks: static-only evidence; runtime validation needed
   - recommended next concrete functions: 0x497F, 0x673C, 0x7E49, 0x774F
