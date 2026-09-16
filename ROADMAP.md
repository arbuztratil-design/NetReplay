# NetReplay — Roadmap

Цель: довести ядро до состояния **NetReplay Core 1.0** — единый, строго
типизированный движок, поверх которого Compare / Incidents / Regression / GUI
строятся как проекции. Пока ядро не зафиксировано, продуктовые фичи не
развиваются.

## Фаза 1 — Core и гигиена проекта

- [x] #1 Унифицировать версию проекта — один источник версии для `pyproject`, Python-пакета и API.
- [x] #2 Почистить корень репозитория — вынести экспериментальные `_*.py` в `tools/` или удалить.
- [ ] #3 Зафиксировать публичные API core-моделей — `Packet`, `Flow`, `Event`, `Session`, `ReplayConfig`.
- [ ] #4 Ввести строгий Session lifecycle — `created → capturing → ready → failed → archived`.
- [ ] #5 Гарантировать `session_id` сразу после старта capture.
- [ ] #6 Ввести единый `PacketId` / `FlowId` / `EventId` type layer.
- [ ] #7 Зафиксировать UTC / monotonic / time-base правила для всех timestamp.
- [ ] #8 Добавить schema version в `.nrp`.
- [ ] #9 Сделать migration framework для `.nrp`.
- [ ] #10 Написать architecture document с единственным canonical data flow.

## Фаза 2 — Storage и .nrp

- [ ] #11 Переделать SQLite schema вокруг единой модели Session / Packet / Flow / Event.
- [ ] #12 Добавить реальные foreign keys и каскадную семантику.
- [ ] #13 Перенести `parent_id` Event Graph в storage.
- [ ] #14 Добавить `packet_id` в Event там, где событие порождено пакетом.
- [ ] #15 Сохранять `ParsedPacket.info` / normalized protocol facts, а не только summary.
- [ ] #16 Добавить таблицу `streams` для TCP/UDP stream identity.
- [ ] #17 Добавить таблицу `protocol_facts` для DNS/TLS/HTTP/QUIC metadata.
- [ ] #18 Добавить capture-integrity metadata: drops, malformed packets, gaps.
- [ ] #19 Перейти с commit-per-packet на batch writer.
- [ ] #20 Добавить SQLite WAL + tuning + benchmark suite.

## Фаза 3 — Packet/Flow/Stream engine

- [ ] #21 Сделать полноценный TCP stream assembler.
- [ ] #22 Поддержать out-of-order segments.
- [ ] #23 Поддержать retransmissions.
- [ ] #24 Обработать overlapping segments.
- [ ] #25 Детектировать sequence gaps.
- [ ] #26 Добавить TCP RTT calculation.
- [ ] #27 Добавить duplicate ACK / window analysis.
- [ ] #28 Сделать настоящую TCP state machine, а не только flag heuristics.
- [ ] #29 Сделать двунаправленный Conversation/Stream abstraction.
- [ ] #30 Подготовить такую же stream-модель для UDP, где это применимо.

## Фаза 4 — Protocol intelligence

- [ ] #31 Перенести TLS analysis с packet-level на reassembled stream.
- [ ] #32 Сделать TLS ClientHello/ServerHello parser с нормальным state.
- [ ] #33 Улучшить TLS 1.2/1.3 metadata extraction.
- [ ] #34 Сделать HTTP/1 parser поверх reassembled stream.
- [ ] #35 Сделать HTTP/2 frame/session parser, а не только preface detection.

## Фаза 5 — Replay Engine 1.0

- [ ] #36 Собрать единый pipeline Select → Mutate → Remap → Validate → Schedule → Send.
- [ ] #37 Подключить `ReplaySelection` реально к `ReplayOutService`.
- [ ] #38 Подключить `MutationPipeline` реально к replay.
- [ ] #39 Подключить `RemapConfig` реально к replay.
- [ ] #40 Разделить Story Replay и Faithful Replay на две строгие семантики.
- [ ] #41 Сделать deterministic scheduling через единый VirtualClock/clock abstraction.
- [ ] #42 Добавить нормальную replay statistics model — sent/skipped/failed/modified.
- [ ] #43 Сделать dry-run, который показывает конечные frames без отправки.
- [ ] #44 Добавить replay validation перед отправкой.
- [ ] #45 Сделать replay result artifact, связанный с исходным `.nrp`.

## Фаза 6 — Testing, API и продуктовая зрелость

- [ ] #46 Создать Golden PCAP/PCAPNG test corpus: TCP, retransmission, IPv4/IPv6, TLS, HTTP/2 и malformed traffic.
- [ ] #47 Создать end-to-end tests PCAP → NRP → replay → result.
- [ ] #48 Усилить CI: Linux + Windows, lint, type-check, coverage, wheel build/install, integration tests.
- [ ] #49 Перепроектировать API вокруг workspace/session/flow/packet/replay, включая session-scoped packet endpoints и нормальные async job/status semantics.
- [ ] #50 Сделать NetReplay Core 1.0 и только после этого развивать Compare / Incidents / Regression / GUI как проекции единого движка.
