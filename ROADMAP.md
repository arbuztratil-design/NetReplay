# NetReplay — Roadmap

Цель: довести ядро до состояния **NetReplay Core 1.0** — единый, строго
типизированный движок, поверх которого Compare / Incidents / Regression / GUI
строятся как проекции. Пока ядро не зафиксировано, продуктовые фичи не
развиваются.

## Фаза 1 — Core и гигиена проекта

- [x] #1 Унифицировать версию проекта — один источник версии для `pyproject`, Python-пакета и API.
- [x] #2 Почистить корень репозитория — вынести экспериментальные `_*.py` в `tools/` или удалить.
- [x] #3 Зафиксировать публичные API core-моделей — `Packet`, `Flow`, `Event`, `Session`, `ReplayConfig`.
- [x] #4 Ввести строгий Session lifecycle — `created → capturing → ready → failed → archived`.
- [x] #5 Гарантировать `session_id` сразу после старта capture.
- [x] #6 Ввести единый `PacketId` / `FlowId` / `EventId` type layer.
- [x] #7 Зафиксировать UTC / monotonic / time-base правила для всех timestamp.
- [x] #8 Добавить schema version в `.nrp`.
- [x] #9 Сделать migration framework для `.nrp`.
- [x] #10 Написать architecture document с единственным canonical data flow.

## Фаза 2 — Storage и .nrp

- [x] #11 Переделать SQLite schema вокруг единой модели Session / Packet / Flow / Event.
- [x] #12 Добавить реальные foreign keys и каскадную семантику.
- [x] #13 Перенести `parent_id` Event Graph в storage.
- [x] #14 Добавить `packet_id` в Event там, где событие порождено пакетом.
- [x] #15 Сохранять `ParsedPacket.info` / normalized protocol facts, а не только summary.
- [x] #16 Добавить таблицу `streams` для TCP/UDP stream identity.
- [x] #17 Добавить таблицу `protocol_facts` для DNS/TLS/HTTP/QUIC metadata.
- [x] #18 Добавить capture-integrity metadata: drops, malformed packets, gaps.
- [x] #19 Перейти с commit-per-packet на batch writer.
- [x] #20 Добавить SQLite WAL + tuning + benchmark suite.

## Фаза 3 — Packet/Flow/Stream engine

- [x] #21 Сделать полноценный TCP stream assembler.
- [x] #22 Поддержать out-of-order segments.
- [x] #23 Поддержать retransmissions.
- [x] #24 Обработать overlapping segments.
- [x] #25 Детектировать sequence gaps.
- [x] #26 Добавить TCP RTT calculation.
- [x] #27 Добавить duplicate ACK / window analysis.
- [x] #28 Сделать настоящую TCP state machine, а не только flag heuristics.
- [x] #29 Сделать двунаправленный Conversation/Stream abstraction.
- [x] #30 Подготовить такую же stream-модель для UDP, где это применимо.

## Фаза 4 — Protocol intelligence

- [x] #31 Перенести TLS analysis с packet-level на reassembled stream.
- [x] #32 Сделать TLS ClientHello/ServerHello parser с нормальным state.
- [x] #33 Улучшить TLS 1.2/1.3 metadata extraction.
- [x] #34 Сделать HTTP/1 parser поверх reassembled stream.
- [x] #35 Сделать HTTP/2 frame/session parser, а не только preface detection.

## Фаза 5 — Replay Engine 1.0

- [x] #36 Собрать единый pipeline Select → Mutate → Remap → Validate → Schedule → Send.
- [x] #37 Подключить `ReplaySelection` реально к `ReplayOutService`.
- [x] #38 Подключить `MutationPipeline` реально к replay.
- [x] #39 Подключить `RemapConfig` реально к replay.
- [x] #40 Разделить Story Replay и Faithful Replay на две строгие семантики.
- [x] #41 Сделать deterministic scheduling через единый VirtualClock/clock abstraction.
- [x] #42 Добавить нормальную replay statistics model — sent/skipped/failed/modified.
- [x] #43 Сделать dry-run, который показывает конечные frames без отправки.
- [x] #44 Добавить replay validation перед отправкой.
- [x] #45 Сделать replay result artifact, связанный с исходным `.nrp`.

## Фаза 6 — Testing, API и продуктовая зрелость

- [ ] #46 Создать Golden PCAP/PCAPNG test corpus: TCP, retransmission, IPv4/IPv6, TLS, HTTP/2 и malformed traffic.
- [ ] #47 Создать end-to-end tests PCAP → NRP → replay → result.
- [ ] #48 Усилить CI: Linux + Windows, lint, type-check, coverage, wheel build/install, integration tests.
- [ ] #49 Перепроектировать API вокруг workspace/session/flow/packet/replay, включая session-scoped packet endpoints и нормальные async job/status semantics.
- [ ] #50 Сделать NetReplay Core 1.0 и только после этого развивать Compare / Incidents / Regression / GUI как проекции единого движка.
