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
- Офлайн-расшифровка TLS 1.2 (AES-128/256-GCM, PRF SHA-256/SHA-384) из
  внешнего SSLKEYLOGFILE: расшифрованные прикладные данные попадают в таймлайн
  как события `DECRYPT`.
- Потоки: нормализованный 5-tuple, TCP state machine
  (SYN → SYN/ACK → ESTABLISHED → FIN → CLOSED, RST).
- Timeline-события: старт потока, переходы TCP, DNS, TLS, DECRYPT — с фильтрами
  по времени, типам и потоку.
- Собственный формат `.nrp` — versioned SQLite (magic `NREP`, v1), WAL,
  payload отдельными 64 КБ-чанками в `raw_blocks`.
- API: REST + WebSocket (live-события захвата), GUI как чистый клиент API.

## Установка

```powershell
pip install -e .
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

# Метаданные, потоки и временная линия
netreplay inspect capture.nrp
netreplay flows capture.nrp
netreplay timeline capture.nrp
netreplay timeline capture.nrp --types TCP,TLS --limit 50

# Исторический реплей с ускорением x50
netreplay replay capture.nrp --speed 50

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

Расшифровка TLS в офлайн-режиме: если передан файл ключей SSLKEYLOGFILE
(строки `CLIENT_RANDOM`), TLS 1.2 соединения (AES-128/256-GCM, SHA-256/SHA-384)
расшифровываются и публикуются в таймлайн как события `DECRYPT` с
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
    protocols/decrypt.py    # TLS 1.2 AES-GCM расшифровка (keylog) + key-block PRF
    protocols/decrypt_service.py  # пост-проход по .nrp -> события DECRYPT
    flows/tracker.py        # нормализация 5-tuple, TCP state machine
    storage/database.py     # SQLite-хранилище сессий
    storage/nrp.py          # формат .nrp: magic, версия, чанки
    timeline/service.py     # события + timeline + replay
    capture/scapy_backend.py
    capture/pcap_backend.py # офлайн-источник: PCAP/PCAPNG -> CapturedPacket
    service.py              # CaptureController, NetReplayService, import_pcap
  api/                      # FastAPI: REST + WebSocket, схемы
  cli/main.py               # Typer-команды (используют Core)
gui/                        # Flet-клиент, данные только через API
tests/                      # pytest (Windows: + реальный TLS 1.2 handshake
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
- `POST /capture/start`, `POST /capture/stop`, `GET /capture/status`,
  `GET /interfaces`
- `WS /ws` — пульс и live-события захвата:
  `{"type":"event","timestamp":...,"flow_id":...,"protocol":"TCP","summary":"..."}`

## Тестирование

```powershell
python -m pytest tests -q
```

## Roadmap (после MVP)

- ~~Офлайн-анализ существующих PCAP без захвата~~ — `netreplay import-pcap`.
- ~~Отложенная расшифровка TLS (внешний кейлог-файл)~~ — `--keylog`.
- TLS 1.3, CBC/ChaCha20-сьюты, проверка Finished-сообщений.
- Перехват и обратная инъекция пакетов (replay-out).
- Векторы похожести/поиск по домену и IP в `inspect`.
- Модульный CLI-бэкенд (Mock/PCAP-файл) без изменения ядра.