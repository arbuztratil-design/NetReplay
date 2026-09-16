# NetReplay

Машина времени для сетевого трафика. Захват → разбор → анализ потоков →
временная линия → «перемотка» событий обратно.

MVP: `netreplay capture` собирает трафик в файл `.nrp`, `netreplay timeline`
показывает его как читаемую историю, `netreplay replay` воспроизводит события
с реалистичными паузами, а `netreplay serve` + `netreplay gui` дают REST/WebSocket
API и оконный клиент.

## Возможности

- Захват пакетов через Scapy (на Windows требуется Npcap).
- Разбор Ethernet / IPv4 / IPv6 / TCP / UDP / ARP / DNS / TLS: SNI, версии TLS,
  DNS query/response.
- Офлайн-расшифровка TLS из внешнего SSLKEYLOGFILE: 1.2 AES-GCM/AES-CBC и 1.3
  AES-GCM/ChaCha20-Poly1305; расшифрованные прикладные данные попадают в
  таймлайн как события `DECRYPT`.
- Проверка Finished-сообщений (`verify_data`) TLS 1.2 и 1.3: корректность
  транскрипта подтверждается по реальным рукопожатиям OpenSSL, результат —
  события `TLS` в таймлайне (verified / MISMATCH).
- Обратная инъекция: `netreplay replay-out` отправляет сохранённые L2-кадры
  обратно в сеть с оригинальными межпакетными паузами (ускорение `--speed`,
  `--dry-run` для проверки без отправки).
- Живой L2-мост: `netreplay bridge -L "ETH" -R "WIFI"` ретранслирует кадры
  между двумя интерфейсами (двунаправленно, байт-в-байт); доступен через CLI,
  API (`/api/bridge/*`) и GUI (кнопка «Bridge»).
- Поиск и похожесть: `netreplay inspect -s "10.0.0.8"` находит потоки, пакеты
  и события по IP/домену (DNS-имена и TLS SNI, включая разрешённые адреса);
  `netreplay inspect --similar` ранжирует сессии в workspace по векторам
  похожести (взвешенный косинус над доменами/IP/портами). В GUI: поле
  «Find (IP / domain)» и кнопка «Similar».
- Модульные источники захвата: живой интерфейс (Scapy), офлайн PCAP/PCAPNG
  (`capture --source`) и синтетический демо-трафик (`capture --mock`) — по
  одному и тому же конвейеру, без изменений в ядре.
- Потоки: нормализованный 5-tuple, TCP state machine
  (SYN → SYN/ACK → ESTABLISHED → FIN → CLOSED, RST).
- Timeline-события: старт потока, переходы TCP, DNS, TLS, DECRYPT — с фильтрами
  по времени, типам и потоку.
- Собственный формат `.nrp` — versioned SQLite (magic `NREP`, v1), WAL,
  payload отдельными 64 КБ-чанками в `raw_blocks`.
- API: REST + WebSocket (live-события захвата), GUI как чистый клиент API.
  Replay-out доступен через API и GUI (кнопка «Replay Out»).
- Сценарии и аннотации: сохранение набора потоков/диапазона как `Scenario`,
  многократные `ScenarioRun` с `Result`, пометки packet/flow/event/time-range —
  в CLI/API и в GUI (вкладка «Scenarios»).
- Единый event graph: события DNS/TLS/HTTP/ошибок — узлы одного графа,
  связанные с потоком и пакетом; Timeline — проекция этого графа.
- Просмотрщики: детали пакета, детали потока (сводка + пакеты + timing +
  metadata), raw/hex и дерево слоёв Ethernet → IP → транспорт → приложение.
- Фильтры: display-filter язык (`protocol == tcp and port == 443`, `and/or/not`,
  скобки) и BPF-фильтры захвата (`tcp port 443`), не пропускающие лишний трафик
  в Python.
- Пагинация packet API и агрегатная статистика: PPS, bytes/s, flows, resets,
  retransmissions (`/api/sessions/{id}/stats`).
- Lifecycle потоков (OPEN / ACTIVE / HALF-CLOSED / CLOSED) и визуализация
  потерь: разрывы/ретраи/перекрытия как маркеры на временной линии.
- Replay-движок: режимы story/faithful, точный timestamp, скорость 0.1–10×,
  выбор packet/flow/time-range, IP/MAC/port remap, мутации пакетов,
  валидация, статистика (sent/skipped/failed/timing drift) и детерминированный
  режим; конфигурация сохраняется как artifact (Scenario → Run → Result).
- P2: сравнение двух захватов (flows/timing/protocol-events), поиск похожих
  инцидентов по поведенческому fingerprint, санитизация/редакция `.nrp`,
  экспорт в PCAP/PCAPNG/JSON/NDJSON/CSV, анализаторы HTTP/HTTP2/QUIC и
  regression-runner из `.nrp` для CI.
- GUI (`netreplay gui`) теперь покрывает все функции: вкладки Toolbox —
  Analysis (stats/filter/loss/layers), Scenarios, Compare/Incidents,
  Export/Sanitize, Regression и Replay.

## Установка

```powershell
pip install netreplay
```

Из исходников (для разработки):

```powershell
git clone https://github.com/arbuztratil-design/NetReplay.git
cd NetReplay
pip install -e .[dev]
```

На Windows для живого захвата установите [Npcap](https://npcap.com)
(с опцией «WinPcap API–compatible Mode»). Без него `netreplay capture`
завершится с понятной ошибкой.

## Использование

```powershell
# Список интерфейсов
netreplay interfaces

# Живой захват 10 секунд
netreplay capture -i "Ethernet" -o capture.nrp -d 10

# Захват из PCAP/PCAPNG-файла (обычный конвейер, без живого интерфейса)
netreplay capture --source dump.pcapng -o from_file.nrp

# Синтетический демо-трафик — без Npcap и без файлов (DNS/TCP/TLS/HTTP)
netreplay capture --mock --mock-packets 40 --mock-rate 2 -o demo.nrp

# Метаданные, потоки, временная линия и поиск
netreplay inspect capture.nrp
netreplay inspect capture.nrp -s "example.com"    # поиск по домену (DNS/TLS SNI)
netreplay inspect capture.nrp -s "192.168.1.10"   # поиск по IP (потоки/пакеты/события)
netreplay inspect capture.nrp --similar           # похожие сессии в workspace
netreplay flows capture.nrp
netreplay timeline capture.nrp
netreplay timeline capture.nrp --types TCP,TLS --limit 50

# То же самое доступно в GUI (netreplay gui): поле "Find (IP / domain)" + кнопки
# Find / Similar на панели инструментов — по открытой сессии.

# Исторический реплей с ускорением x50
netreplay replay capture.nrp --speed 50

# Отправить пакеты обратно в сеть с ускорением x10
netreplay replay-out capture.nrp -i "Ethernet" --speed 10
netreplay replay-out capture.nrp -i "Ethernet" --dry-run  # предпросмотр без отправки

# Живой L2-мост: перехват на одних интерфейсах и ретрансляция на других
netreplay bridge -L "Ethernet" -R "Wi-Fi"

# Список сессий в workspace (переменная окружения NETREPLAY_WORKSPACE,
# по умолчанию ./netreplay_data)
netreplay sessions

# Импорт и анализ существующего PCAP/PCAPNG без захвата
netreplay import-pcap dump.pcap -o dump.nrp

# REST + WebSocket API и GUI
netreplay serve            # http://127.0.0.1:8000, документация /docs
netreplay gui              # в отдельном терминале; подключится к API
```

Быстрая проверка без сети: в папке `examples/` лежит готовый `demo.nrp`
(11 пакетов: DNS, TCP handshake, TLS, завершение соединения).

```powershell
netreplay timeline examples/demo.nrp
```

Офлайн-импорт: `netreplay import-pcap` прогоняет `.pcap`/`.pcapng` через
тот же пайплайн (разбор → потоки → события → `.nrp`), что и живой захват.
Результат открывается любыми обычными командами: `flows`, `timeline`,
`replay`, `serve`/`gui`.

Расшифровка TLS в офлайн-режиме: если передан файл ключей SSLKEYLOGFILE,
TLS 1.2 (строки `CLIENT_RANDOM`; AES-128/256-GCM и AES-CBC,
SHA-256/SHA-384/SHA-1) и TLS 1.3 (строки `*_TRAFFIC_SECRET`; AES-GCM,
ChaCha20-Poly1305) соединения расшифровываются и публикуются в таймлайн как
события `DECRYPT` с
превью прикладных данных (например, начала HTTP-запроса/ответа). Такой
файл умеют отдавать curl, OpenSSL и браузеры через переменную окружения
`SSLKEYLOGFILE`.

```powershell
netreplay import-pcap dump.pcap -o dump.nrp --keylog keys.log
```

## Архитектура

```
netreplay/
  core/                     # вся логика, без наружных зависимостей
    packets/parser.py       # Scapy -> ParsedPacket
    protocols/dns.py, tls.py
    protocols/decrypt.py    # TLS 1.2 AEAD/CBC + TLS 1.3 AEAD (keylog, PRF/HKDF)
    protocols/decrypt_service.py  # пост-проход по .nrp -> события DECRYPT
    flows/tracker.py        # нормализация 5-tuple, TCP state machine
    storage/database.py     # SQLite-хранилище сессий
    storage/nrp.py          # формат .nrp: magic, версия, чанки
    timeline/service.py     # события + timeline + replay
    replay/inject.py        # replay-out: обратная инъекция кадров (Scapy)
    search.py               # поиск по IP/домену + векторы похожести сессий
    capture/scapy_backend.py
    capture/pcap_backend.py # офлайн-источник: PCAP/PCAPNG -> CapturedPacket
    service.py              # CaptureController, NetReplayService, import_pcap
  api/                      # FastAPI: REST + WebSocket, схемы
  cli/main.py               # Typer-команды (используют Core)
gui/                        # Flet-клиент, данные только через API
tests/                      # pytest (Windows: + реальный TLS 1.2/1.3 handshake
                            # через OpenSSL DLL и проверка расшифровки)
```

Правила разделения:
- GUI не трогает захват, хранилище и внутренние структуры — только API.
- CLI не дублирует логику Core (разбор, потоки, timeline) — только вызывает её.
- Core не зависит от FastAPI/Typer/Flet.
- `PcapBackend` реализует тот же `CaptureBackend`, что и `ScapyBackend`,
  поэтому офлайн-импорт переиспользует пайплайн без изменений.

## API

- `GET /sessions`, `GET /sessions/{id}`, `GET /sessions/{id}/timeline`,
  `GET /sessions/{id}/flows`
- `GET /flows/{id}`, `GET /packets/{id}` (с `?raw=true` — hex payload)
- `GET /sessions/{id}/packets` — пагинация (`limit`, `offset`, `total`)
- `GET /sessions/{id}/packets/{pid}/layers` — дерево слоёв + hex/ASCII
- `GET /sessions/{id}/stats` — агрегаты (PPS, bytes, flows, resets, retransmits)
- `GET /sessions/{id}/filter?expr=...&kind=flows|packets|events` — display-фильтр
- `GET /sessions/{id}/loss` — маркеры потерь/ретраев/перекрытий
- `/sessions/{id}/scenarios`, `/scenarios/{sid}/runs`, `/sessions/{id}/annotations` —
  сценарии, запуски и аннотации (CRUD)
- `GET /sessions/{id}/compare/{other}`, `GET /sessions/{id}/incidents` —
  сравнение захватов и поиск похожих инцидентов
- `GET /sessions/{id}/export?format=json|ndjson|csv`, `POST /sessions/{id}/sanitize`,
  `POST /regression/run`
- `POST /capture/start`, `POST /capture/stop`, `GET /capture/status`,
  `GET /interfaces`
- `POST /replay-out/{session_id}` — запуск replay (mode, speed, selection,
  remap, mutations, validate_frames, dry_run, offset, limit),
  `POST /replay-out/stop`, `GET /replay-out/status`
- `WS /ws` — пульс и live-события захвата:
  `{"type":"event","timestamp":...,"flow_id":...,"protocol":"TCP","summary":"..."}`

## Тестирование

```powershell
python -m pytest tests -q
```

## Roadmap (после MVP)

- ~~Офлайн-анализ существующих PCAP без захвата~~ — `netreplay import-pcap`.
- ~~Отложенная расшифровка TLS (внешний кейлог-файл)~~ — `--keylog`.
- ~~TLS 1.3 (AES-GCM, ChaCha20-Poly1305)~~ — traffic-secret lines в keylog.
- ~~TLS 1.2 CBC-сьюты (AES-128/256-CBC, SHA-1/SHA-256)~~.
- ~~Проверка Finished-сообщений (verify_data)~~.
- ~~Обратная инъекция пакетов (replay-out)~~ — `netreplay replay-out`, API, GUI (кнопка «Replay Out» + диалог speed/dry-run + прогресс).
- ~~Перехват/ретрансляция живого трафика между интерфейсами~~ — `netreplay bridge`, API, GUI (кнопка «Bridge»).
- ~~Векторы похожести/поиск по домену и IP в `inspect`~~ — `netreplay inspect -s <ip|domain>`, `netreplay inspect --similar`.
- ~~Модульный CLI-бэкенд (Mock/PCAP-файл) без изменения ядра~~ — `netreplay capture --source <file>` и `netreplay capture --mock` через общий бэкенд-абстракции.