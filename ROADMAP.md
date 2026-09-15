# NetReplay Roadmap

Status tracking: `[ ]` вЂ” not started, `[~]` вЂ” in progress, `[x]` вЂ” done.

## P0 вЂ” РєСЂРёС‚РёС‡РµСЃРєРёР№ С„СѓРЅРґР°РјРµРЅС‚

- [x] #1 РСЃРїСЂР°РІРёС‚СЊ scoping packet_id Рё flow_id РѕС‚РЅРѕСЃРёС‚РµР»СЊРЅРѕ session_id вЂ” РЅРёРєР°РєРёС… РєРѕР»Р»РёР·РёР№ РјРµР¶РґСѓ capture-СЃРµСЃСЃРёСЏРјРё
- [x] #2 Р”РѕР±Р°РІРёС‚СЊ session_id РІРѕ РІСЃРµ API routes РґР»СЏ packet/flow СЂРµСЃСѓСЂСЃРѕРІ вЂ” РѕРґРЅРѕР·РЅР°С‡РЅР°СЏ Р°РґСЂРµСЃР°С†РёСЏ РѕР±СЉРµРєС‚РѕРІ
- [x] #3 РџРµСЂРµР№С‚Рё РЅР° batch transactions РїСЂРё Р·Р°РїРёСЃРё packets вЂ” СЃСѓС‰РµСЃС‚РІРµРЅРЅРѕ РІС‹С€Рµ throughput capture
- [x] #4 Р”РѕР±Р°РІРёС‚СЊ configurable flush policy вЂ” flush РїРѕ N packets / РІСЂРµРјРµРЅРё / Р·Р°РІРµСЂС€РµРЅРёСЋ
- [x] #5 РЎС‡РёС‚Р°С‚СЊ dropped packets вЂ” РІ session РїРѕСЏРІР»СЏРµС‚СЃСЏ СЂРµР°Р»СЊРЅР°СЏ СЃС‚Р°С‚РёСЃС‚РёРєР° РїРѕС‚РµСЂСЊ
- [x] #6 Р”РѕР±Р°РІРёС‚СЊ capture_integrity metadata вЂ” РїРѕР»СЊР·РѕРІР°С‚РµР»СЊ РІРёРґРёС‚, Р±С‹Р» Р»Рё capture РїРѕР»РЅС‹Рј
- [ ] #7 Р”РѕР±Р°РІРёС‚СЊ PCAP link-layer/DLT metadata вЂ” РєРѕСЂСЂРµРєС‚РЅР°СЏ СЂР°Р±РѕС‚Р° РЅРµ С‚РѕР»СЊРєРѕ СЃ Ethernet
- [ ] #8 РЎРѕС…СЂР°РЅРёС‚СЊ captured_len Рё original_len вЂ” РїРѕРґРґРµСЂР¶РєР° truncated frames
- [ ] #9 РЎРґРµР»Р°С‚СЊ РїРѕР»РЅРѕС†РµРЅРЅС‹Р№ TCP sequence tracker вЂ” РїРѕРЅРёРјР°РЅРёРµ retransmission/out-of-order/gaps
- [ ] #10 РЎРґРµР»Р°С‚СЊ TCP stream reassembly engine вЂ” РµРґРёРЅС‹Р№ byte stream РґР»СЏ protocol analyzers
- [ ] #11 Р Р°Р·РґРµР»РёС‚СЊ packet parser Рё stream analyzer вЂ” С‡С‘С‚РєР°СЏ РіСЂР°РЅРёС†Р° L2/L3/L4 Рё application protocols
- [ ] #12 РџРµСЂРµРІРµСЃС‚Рё TLS analysis РЅР° reassembled streams вЂ” TLS record РЅРµ Р»РѕРјР°РµС‚СЃСЏ РЅР° РіСЂР°РЅРёС†Р°С… TCP packets
- [ ] #13 Р”РѕР±Р°РІРёС‚СЊ stream-gap/error model вЂ” Р°РЅР°Р»РёР·Р°С‚РѕСЂ Р·РЅР°РµС‚, С‡С‚Рѕ С‡Р°СЃС‚СЊ РґР°РЅРЅС‹С… РїРѕС‚РµСЂСЏРЅР°
- [ ] #14 РЎРґРµР»Р°С‚СЊ NRP schema migration framework вЂ” СЂРµР°Р»СЊРЅС‹Р№ v1 в†’ v2 в†’ v3
- [ ] #15 Р”РѕР±Р°РІРёС‚СЊ NRP integrity hash/manifest вЂ” РјРѕР¶РЅРѕ РґРѕРєР°Р·Р°С‚СЊ РЅРµРёР·РјРµРЅРЅРѕСЃС‚СЊ capture

## P1 вЂ” РЅРѕСЂРјР°Р»СЊРЅС‹Р№ forensic core

- [ ] #16 Р’РІРµСЃС‚Рё domain model Scenario вЂ” capture РјРѕР¶РЅРѕ РїСЂРµРІСЂР°С‰Р°С‚СЊ РІ РІРѕСЃРїСЂРѕРёР·РІРѕРґРёРјС‹Р№ РєРµР№СЃ
- [ ] #17 Р’РІРµСЃС‚Рё ScenarioRun вЂ” РѕРґРёРЅ СЃС†РµРЅР°СЂРёР№ РјРѕР¶РЅРѕ Р·Р°РїСѓСЃРєР°С‚СЊ РјРЅРѕРіРѕРєСЂР°С‚РЅРѕ
- [ ] #18 Р’РІРµСЃС‚Рё annotations РґР»СЏ packet/flow/event/time-range вЂ” Р°РЅР°Р»РёС‚РёРє РјРѕР¶РµС‚ РїРѕРјРµС‡Р°С‚СЊ РІР°Р¶РЅС‹Рµ РјРµСЃС‚Р°
- [ ] #19 Р”РѕР±Р°РІРёС‚СЊ event types РєР°Рє РѕС‚РґРµР»СЊРЅС‹Рµ domain objects вЂ” DNS/TLS/HTTP/errors СЃС‚Р°РЅРѕРІСЏС‚СЃСЏ РµРґРёРЅС‹Рј event graph
- [ ] #20 РџРµСЂРµРґРµР»Р°С‚СЊ Timeline РЅР° event graph вЂ” Timeline СЃС‚Р°РЅРѕРІРёС‚СЃСЏ СЏРґСЂРѕРј РїСЂРѕРґСѓРєС‚Р°
- [ ] #21 Р”РѕР±Р°РІРёС‚СЊ packet detail viewer вЂ” РїРѕР»РЅР°СЏ РёРЅСЃРїРµРєС†РёСЏ РѕС‚РґРµР»СЊРЅРѕРіРѕ packet
- [ ] #22 Р”РѕР±Р°РІРёС‚СЊ flow detail viewer вЂ” СЃРІРѕРґРєР° + packets + timing + metadata
- [ ] #23 Р”РѕР±Р°РІРёС‚СЊ raw/hex viewer вЂ” РјРѕР¶РЅРѕ СЃРјРѕС‚СЂРµС‚СЊ РЅРµРѕР±СЂР°Р±РѕС‚Р°РЅРЅС‹Рµ bytes
- [ ] #24 Р”РѕР±Р°РІРёС‚СЊ layer tree вЂ” Ethernet в†’ IP в†’ TCP в†’ TLS Рё С‚.Рґ.
- [ ] #25 Р”РѕР±Р°РІРёС‚СЊ display-filter language вЂ” Р°РЅР°Р»РёС‚РёРє С„РёР»СЊС‚СЂСѓРµС‚ capture РІС‹СЂР°Р¶РµРЅРёСЏРјРё
- [ ] #26 Р”РѕР±Р°РІРёС‚СЊ BPF/libpcap capture filters вЂ” Р»РёС€РЅРёР№ С‚СЂР°С„РёРє РЅРµ РїРѕРїР°РґР°РµС‚ РІ Python
- [ ] #27 РЎРґРµР»Р°С‚СЊ pagination/streaming РґР»СЏ packet API вЂ” Р±РѕР»СЊС€РёРµ captures РЅРµ РіСЂСѓР·СЏС‚СЃСЏ С†РµР»РёРєРѕРј РІ RAM
- [ ] #28 Р”РѕР±Р°РІРёС‚СЊ aggregate statistics вЂ” PPS, bytes, flows, resets, retransmissions
- [ ] #29 Р”РѕР±Р°РІРёС‚СЊ flow lifecycle events вЂ” OPEN / ACTIVE / HALF-CLOSED / CLOSED
- [ ] #30 Р”РѕР±Р°РІРёС‚СЊ packet-loss visualization вЂ” gaps СЃС‚Р°РЅРѕРІСЏС‚СЃСЏ РІРёРґРёРјС‹РјРё РЅР° timeline

## P1 вЂ” replay engine

- [ ] #31 Р Р°Р·РґРµР»РёС‚СЊ Story Replay Рё Faithful Replay вЂ” РїРѕРЅСЏС‚РЅР°СЏ СЃРµРјР°РЅС‚РёРєР° РІРѕСЃРїСЂРѕРёР·РІРµРґРµРЅРёСЏ
- [ ] #32 Р”РѕР±Р°РІРёС‚СЊ С‚РѕС‡РЅС‹Р№ timestamp replay вЂ” СЂРµР°Р»СЊРЅРѕРµ РІРѕСЃРїСЂРѕРёР·РІРµРґРµРЅРёРµ timing
- [ ] #33 Р”РѕР±Р°РІРёС‚СЊ replay speed multiplier вЂ” 0.1x / 1x / 2x / 10x / ...
- [ ] #34 Р”РѕР±Р°РІРёС‚СЊ packet/flow/time-range selection вЂ” РјРѕР¶РЅРѕ РІРѕСЃРїСЂРѕРёР·РІРѕРґРёС‚СЊ РЅРµ РІРµСЃСЊ capture
- [ ] #35 Р”РѕР±Р°РІРёС‚СЊ IP/MAC/port remapping вЂ” replay Р°РґР°РїС‚РёСЂСѓРµС‚СЃСЏ РїРѕРґ С‚РµСЃС‚РѕРІСѓСЋ СЃСЂРµРґСѓ
- [ ] #36 Р”РѕР±Р°РІРёС‚СЊ packet mutation pipeline вЂ” РїРµСЂРµРґ replay РјРѕР¶РЅРѕ РјРµРЅСЏС‚СЊ РґР°РЅРЅС‹Рµ
- [ ] #37 Р”РѕР±Р°РІРёС‚СЊ replay validation вЂ” РїСЂРѕРІРµСЂРєР° РѕС‚РїСЂР°РІР»РµРЅРЅС‹С… packets
- [ ] #38 Р”РѕР±Р°РІРёС‚СЊ replay statistics вЂ” sent / skipped / failed / timing drift
- [ ] #39 Р”РѕР±Р°РІРёС‚СЊ deterministic replay mode вЂ” РѕРґРёРЅ СЃС†РµРЅР°СЂРёР№ РґР°С‘С‚ РІРѕСЃРїСЂРѕРёР·РІРѕРґРёРјС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚
- [ ] #40 РЎРґРµР»Р°С‚СЊ replay scenario РєР°Рє СЃРѕС…СЂР°РЅСЏРµРјС‹Р№ artifact вЂ” Scenario в†’ Run в†’ Result

## P2 вЂ” killer features

- [ ] #41 РЎРґРµР»Р°С‚СЊ Capture A/B comparison вЂ” СЃСЂР°РІРЅРµРЅРёРµ РґРІСѓС… РёРЅС†РёРґРµРЅС‚РѕРІ
- [ ] #42 РЎРґРµР»Р°С‚СЊ flow-level diff вЂ” РєР°РєРёРµ flows РїРѕСЏРІРёР»РёСЃСЊ/РёСЃС‡РµР·Р»Рё/РёР·РјРµРЅРёР»РёСЃСЊ
- [ ] #43 РЎРґРµР»Р°С‚СЊ timing diff вЂ” latency/duration РґРѕ Рё РїРѕСЃР»Рµ
- [ ] #44 РЎРґРµР»Р°С‚СЊ protocol-event diff вЂ” РЅР°РїСЂРёРјРµСЂ TLS/HTTP/DNS РїРѕРІРµРґРµРЅРёРµ
- [ ] #45 РџРµСЂРµСЂР°Р±РѕС‚Р°С‚СЊ similarity fingerprint вЂ” СЃСЂР°РІРЅРµРЅРёРµ РїРѕ РїРѕРІРµРґРµРЅРёСЋ, Р° РЅРµ С‚РѕР»СЊРєРѕ IP/domain/port
- [ ] #46 РЎРґРµР»Р°С‚СЊ "Find similar incidents" вЂ” РїРѕРёСЃРє РёСЃС‚РѕСЂРёС‡РµСЃРєРё РїРѕС…РѕР¶РёС… РїСЂРѕР±Р»РµРј
- [ ] #47 Р”РѕР±Р°РІРёС‚СЊ capture sanitization/redaction вЂ” Р±РµР·РѕРїР°СЃРЅР°СЏ РїРµСЂРµРґР°С‡Р° .nrp С‚СЂРµС‚СЊРёРј СЃС‚РѕСЂРѕРЅР°Рј
- [ ] #48 Р”РѕР±Р°РІРёС‚СЊ export РІ PCAP/PCAPNG/JSON/NDJSON/CSV вЂ” РЅРѕСЂРјР°Р»СЊРЅР°СЏ РёРЅС‚РµРіСЂР°С†РёСЏ СЃ РІРЅРµС€РЅРёРјРё РёРЅСЃС‚СЂСѓРјРµРЅС‚Р°РјРё
- [ ] #49 Р”РѕР±Р°РІРёС‚СЊ HTTP/HTTP2/QUIC analyzers вЂ” РїРµСЂРµС…РѕРґ РѕС‚ packet analyzer Рє application forensics
- [ ] #50 РЎРґРµР»Р°С‚СЊ regression-test runner РёР· .nrp scenarios вЂ” NetReplay РјРѕР¶РЅРѕ РёСЃРїРѕР»СЊР·РѕРІР°С‚СЊ РІ CI РєР°Рє network regression platform