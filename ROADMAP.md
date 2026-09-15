# NetReplay Roadmap

Status tracking: `[ ]` — not started, `[~]` — in progress, `[x]` — done.

## P0 — критический фундамент

- [x] #1 Исправить scoping packet_id и flow_id относительно session_id — никаких коллизий между capture-сессиями
- [x] #2 Добавить session_id во все API routes для packet/flow ресурсов — однозначная адресация объектов
- [x] #3 Перейти на batch transactions при записи packets — существенно выше throughput capture
- [x] #4 Добавить configurable flush policy — flush по N packets / времени / завершению
- [x] #5 Считать dropped packets — в session появляется реальная статистика потерь
- [x] #6 Добавить capture_integrity metadata — пользователь видит, был ли capture полным
- [ ] #7 Добавить PCAP link-layer/DLT metadata — корректная работа не только с Ethernet
- [ ] #8 Сохранить captured_len и original_len — поддержка truncated frames
- [ ] #9 Сделать полноценный TCP sequence tracker — понимание retransmission/out-of-order/gaps
- [ ] #10 Сделать TCP stream reassembly engine — единый byte stream для protocol analyzers
- [ ] #11 Разделить packet parser и stream analyzer — чёткая граница L2/L3/L4 и application protocols
- [ ] #12 Перевести TLS analysis на reassembled streams — TLS record не ломается на границах TCP packets
- [ ] #13 Добавить stream-gap/error model — анализатор знает, что часть данных потеряна
- [ ] #14 Сделать NRP schema migration framework — реальный v1 → v2 → v3
- [ ] #15 Добавить NRP integrity hash/manifest — можно доказать неизменность capture

## P1 — нормальный forensic core

- [ ] #16 Ввести domain model Scenario — capture можно превращать в воспроизводимый кейс
- [ ] #17 Ввести ScenarioRun — один сценарий можно запускать многократно
- [ ] #18 Ввести annotations для packet/flow/event/time-range — аналитик может помечать важные места
- [ ] #19 Добавить event types как отдельные domain objects — DNS/TLS/HTTP/errors становятся единым event graph
- [ ] #20 Переделать Timeline на event graph — Timeline становится ядром продукта
- [ ] #21 Добавить packet detail viewer — полная инспекция отдельного packet
- [ ] #22 Добавить flow detail viewer — сводка + packets + timing + metadata
- [ ] #23 Добавить raw/hex viewer — можно смотреть необработанные bytes
- [ ] #24 Добавить layer tree — Ethernet → IP → TCP → TLS и т.д.
- [ ] #25 Добавить display-filter language — аналитик фильтрует capture выражениями
- [ ] #26 Добавить BPF/libpcap capture filters — лишний трафик не попадает в Python
- [ ] #27 Сделать pagination/streaming для packet API — большие captures не грузятся целиком в RAM
- [ ] #28 Добавить aggregate statistics — PPS, bytes, flows, resets, retransmissions
- [ ] #29 Добавить flow lifecycle events — OPEN / ACTIVE / HALF-CLOSED / CLOSED
- [ ] #30 Добавить packet-loss visualization — gaps становятся видимыми на timeline

## P1 — replay engine

- [ ] #31 Разделить Story Replay и Faithful Replay — понятная семантика воспроизведения
- [ ] #32 Добавить точный timestamp replay — реальное воспроизведение timing
- [ ] #33 Добавить replay speed multiplier — 0.1x / 1x / 2x / 10x / ...
- [ ] #34 Добавить packet/flow/time-range selection — можно воспроизводить не весь capture
- [ ] #35 Добавить IP/MAC/port remapping — replay адаптируется под тестовую среду
- [ ] #36 Добавить packet mutation pipeline — перед replay можно менять данные
- [ ] #37 Добавить replay validation — проверка отправленных packets
- [ ] #38 Добавить replay statistics — sent / skipped / failed / timing drift
- [ ] #39 Добавить deterministic replay mode — один сценарий даёт воспроизводимый результат
- [ ] #40 Сделать replay scenario как сохраняемый artifact — Scenario → Run → Result

## P2 — killer features

- [ ] #41 Сделать Capture A/B comparison — сравнение двух инцидентов
- [ ] #42 Сделать flow-level diff — какие flows появились/исчезли/изменились
- [ ] #43 Сделать timing diff — latency/duration до и после
- [ ] #44 Сделать protocol-event diff — например TLS/HTTP/DNS поведение
- [ ] #45 Переработать similarity fingerprint — сравнение по поведению, а не только IP/domain/port
- [ ] #46 Сделать "Find similar incidents" — поиск исторически похожих проблем
- [ ] #47 Добавить capture sanitization/redaction — безопасная передача .nrp третьим сторонам
- [ ] #48 Добавить export в PCAP/PCAPNG/JSON/NDJSON/CSV — нормальная интеграция с внешними инструментами
- [ ] #49 Добавить HTTP/HTTP2/QUIC analyzers — переход от packet analyzer к application forensics
- [ ] #50 Сделать regression-test runner из .nrp scenarios — NetReplay можно использовать в CI как network regression platform