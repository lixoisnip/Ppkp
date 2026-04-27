# 90CYE01 MDS water extinguishing discrete inputs

Evidence level: `project_documentation`

## Confirmed module
- MDS A1 еФ5.104.156 is present in 90CYE01 project documentation.

## Confirmed inputs
- 03SGC01CP051
- 03SGC01CF051
- 03SGC01CF052
- 03SGC01CF053
- 90CYE01CH001
- 90CYE01CH002
- 90CYE01CH003
- 90CYE01CH004

## Physical interpretation from project extraction
- CP051 = pressure switch PS10.
- CF051 = flow switch VSR.
- CF052/CF053 = VSR-6 sprinkler flow switches.
- CH001..CH004 = remote fire pump start devices.

## Terminal evidence
- X03:1 / XG01 + L+
- X03:3 / XG01 + L+
- X03:5 / XG01 + L+
- X03:7 / XG01 + L+
- X03:9..16 = CH001..CH004
- GH003 / BC-12-A terminal box used for CH lines.

## Firmware search implications
- discrete input scan routines for MDS-origin signals.
- bit masks / bitfield unpack paths for CP/CF/CH signals.
- edge vs level event generation around water signals.
- event terms tied to water pressure, flow, and remote pump start.

## Unknowns
- internal MDS address in runtime structures.
- protocol details between CPU and MDS.
- input word/byte layout.
- line break/short supervision behavior.
