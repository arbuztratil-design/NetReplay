# NetReplay Architecture

This document is the reference for the **canonical data flow** of NetReplay.
There is exactly one pipeline from wire to screen; every surface (CLI, REST
API, GUI, replay) is a projection of it. If a change introduces a second path
for the same data, that change is wrong by definition.

## 1. Canonical data flow

```
 raw frame (bytes + capture ts)
        │
        ▼
 ┌─────────────────┐   parse_packet()
 │  Packet parser   │   Scapy -> ParsedPacket (+ L7 info)
 └─────────────────┘
        │  ParsedPacket
        ▼
 ┌─────────────────┐   FlowTracker.feed()
 │  Flow tracker    │   normalize 5-tuple, TCP state machine
 └─────────────────┘
        │  Flow + ParsedPacket
        ▼
 ┌─────────────────┐   EventGenerator.feed()
 │  Event generator │   TimelineEvent (TCP/DNS/TLS/HTTP/DECRYPT/...)
 └─────────────────┘
        │  Packet / Flow / TimelineEvent
        ▼
 ┌─────────────────┐   SessionStorage (single writer, batched)
 │  .nrp storage    │   SQLite: sessions, packets, flows, events, raw_blocks
 └─────────────────┘
        │  rows
        ▼
 ┌─────────────────┐   read-only queries + projections
 │  Read layer      │   timeline, viewers, stats, compare, incidents, loss...
 └─────────────────┘
        │
        ├────────────► CLI  (netreplay.core.service / Typer)
        ├────────────► REST + WS  (netreplay.api, FastAPI)
        └────────────► GUI  (flet, HTTP client of the API only)
```

Replay is the **reverse arrow** of the same flow: stored `raw_blocks` →
selection/mutation/remap/validation → schedule → send.

```
 .nrp raw frames ──► ReplaySelection ──► MutationPipeline ──► RemapConfig
        ──► validate_frame ──► schedule (clock) ──► sender (Scapy)
```

The outcome is recorded as a `ReplayResultArtifact` (#45): a Scenario/Run
Result stored in the source `.nrp` and, optionally, as a portable `.nrr` JSON
that pins the result to the exact source capture (`session_id` +
`integrity_hash` + `packet_count`) so it can be verified later.

## 2. Layers and rules

| Layer       | Package            | May depend on            |
|-------------|--------------------|--------------------------|
| Core        | `netreplay.core`   | stdlib + scapy + cryptography |
| API         | `netreplay.api`    | core, FastAPI            |
| CLI         | `netreplay.cli`    | core, Typer              |
| GUI         | `gui`              | API over HTTP only       |

Rules (enforced by review):

1. **Core has no web/GUI dependencies.** No FastAPI, Typer or Flet imports.
2. **CLI does not reimplement core logic** — it only calls `netreplay.core`.
3. **GUI never touches capture/storage** — only the REST API.
4. **One writer.** All writes to a `.nrp` go through `SessionStorage` on the
   capture thread; readers use short-lived read connections (WAL).
5. **One time base.** See §4.

## 3. `.nrp` container

A `.nrp` file is a SQLite database with a NetReplay header:

- `nrp_header`: `magic = "NREP"`, `version` (container format, currently 1),
  `schema_version` (SQLite schema revision, currently 4).
- Tables: `sessions`, `packets`, `flows`, `events`, `streams`,
  `protocol_facts`, `raw_blocks`, `metadata`.
- Raw payloads are stored 64 KiB-chunked in `raw_blocks`; packet/flow/event
  rows carry metadata only. `packets.info` holds normalized protocol facts as
  JSON, mirrored into queryable `protocol_facts` rows.
- Events carry provenance: `packet_id` (the packet that produced the event) and
  `parent_id` (event-graph edge).
- Foreign keys are enforced (`PRAGMA foreign_keys=ON`): `packets`/`flows`/
  `events` cascade from `sessions`; `raw_blocks`/`events.packet_id`/
  `protocol_facts` cascade from `packets`; `streams`/`protocol_facts` cascade
  from `flows`/`streams`. `SessionStorage.delete_session()` cascades in one go.
- Capture integrity is recorded as metadata: `dropped_packets`,
  `malformed_packets`, `capture_gaps` (+ `integrity_hash`), exposed via
  `SessionStorage.integrity_report()`.
- Writes go through `SessionStorage.batch()` (one commit per batch); the writer
  uses WAL + `synchronous=NORMAL`.

Migrations (`_MIGRATION_STAGES` + `PRAGMA user_version`) bring older files up to
the current `schema_version`. New files are created at stage 0 and migrated
through the same path, so fresh and migrated captures always share one layout.
Opening a file written by a newer schema fails loudly.

## 4. Time base

| Purpose            | Clock                         | Storage form        |
|--------------------|-------------------------------|---------------------|
| Captured timestamps| wall-clock UTC epoch seconds  | integer microseconds|
| Durations / rates  | `time.monotonic()` seconds    | never stored        |

Helpers live in `netreplay.core.timebase` (`now_epoch`, `now_monotonic`,
`to_us`, `from_us`). Never mix the two clocks.

## 5. Session lifecycle

```
created ──► capturing ──► ready
                 │
                 └──────► failed
ready ──► archived
```

`SessionStatus` (in `netreplay.core.storage.database`) is the only source of
status values; legacy `complete`/`running`/`error` are normalized on read.
`session_id` is guaranteed available the moment `CaptureController.start()`
returns (the file is created synchronously).

## 6. Public core API

`netreplay.core.__all__` is the frozen surface other layers may import:

- models: `Packet`, `Flow`, `Event`, `Session` (+ `ParsedPacket`,
  `NetworkEvent`, `EventGraph`, `SessionInfo`)
- ids: `PacketId`, `FlowId`, `EventId`, `SessionId`
- replay: `ReplayConfig`, `ReplayMode`, `ReplaySpeed`
- time: `now_epoch`, `now_monotonic`, `to_us`, `from_us`, `utc_iso`
- service: `NetReplayService`

Anything not in `__all__` is internal and may change without notice.

## 7. Module map

```
netreplay/core/
  packets/parser.py        Scapy -> ParsedPacket
  protocols/{dns,tls,http}.py, decrypt.py, analyzer.py
  flows/{models,tracker,reassembly,lifecycle}.py
  flows/conversation.py    bidirectional TCP conversation + UDP datagram stream
  flows/tcp_metrics.py     RTT, duplicate ACKs, window analysis
  events/models.py         event graph (DNS/TLS/HTTP/errors)
  timeline/service.py      EventGenerator, TimelineService, ReplayService
  storage/{nrp,database,flush}.py
  replay/{config,timing,selection,remap,mutation,validate,stats,artifact,inject}.py
  viewers/, compare.py, incidents.py, loss.py, stats.py, sanitize.py,
  export.py, regression.py, scenario/, ids.py, timebase.py, service.py
netreplay/api/             FastAPI app + routes + schemas + websocket
netreplay/cli/main.py      Typer commands
gui/                       Flet client (API only), components/toolbox.py
```
