# AGENTS.md — карта проекта vpn-relay

Этот файл предназначен для разработчиков и AI-агентов, работающих с репозиторием. Он описывает фактическую архитектуру, границы ответственности модулей, критические инварианты и безопасный порядок изменений. При расхождении этого документа с кодом источником истины является код и тесты; после изменения архитектуры обновляйте этот файл.

## 1. Назначение проекта

`vpn-relay` — Linux daemon на Rust для создания и управления несколькими WireGuard/AmneziaWG TUN-интерфейсами, маршрутизации IPv4-трафика между ними и внешними uplink, policy routing, nftables firewall и NAT.

Криптографическая реализация туннеля не находится в этом репозитории: используется закреплённый Git revision форка `lelikulibina/boringtun-awg`. В vpn-relay находятся orchestration, конфигурация, Linux networking и control plane.

Текущие поддерживаемые свойства:
- Только Linux и IPv4 datapath. IPv6 не является частично поддерживаемым dual-stack режимом: конфигурация IPv6 отклоняется, IPv6 через managed TUN блокируется nftables.
- WG и AWG реализованы одним BoringTun backend с разными параметрами протокола.
- Используются TUN-интерфейсы, создаваемые typed API BoringTun. UAPI для daemon-owned устройств отключён.
- Маршрутизация строится декларативно из routing rules, ingress/source/destination/egress, mark и NAT.
- nftables изолирует INPUT/OUTPUT/FORWARD для managed TUN и применяет fail-closed политику.
- Runtime поддерживает startup, graceful shutdown, конфигурационный reload, замену peer set, получение статистики по запросу и восстановление части системного состояния после аварийного завершения.
- Демон может работать в foreground (по умолчанию) или background (`--background` / `-b`). systemd unit и другие service units проектом пока не устанавливаются.
- Логирование выключено по умолчанию. `--log` включает файл `/var/log/vpn-relay.log`, `--log PATH` задаёт свой путь.
- Управление работающим экземпляром идёт через локальный Unix domain socket. Текущие операции: `--stats`, `--reload`, `--replace-peers`.

Не предполагайте поддержку IPv6, Windows, rootless Podman, host-network deployment, systemd installation, Web UI, REST API, отдельных web-пользователей, команды stop/status или автоматического failover между uplink, если соответствующая реализация явно не появилась в коде.

## 2. Технологии и сборка

- Rust 2021.
- Cargo; lockfile обязателен для воспроизводимых проверок.
- Tunnel engine: Git dependency `boringtun` из `https://github.com/lelikulibina/boringtun-awg`, revision зафиксирован в `Cargo.toml`.
- Linux integration: `libc`, системные `ip`/iproute2, `nft`, rtnetlink, `sysctl`, `/dev/net/tun`.
- TOML + Serde для конфигурации.
- `tracing` / `tracing-subscriber` для логов.
- `serde_json` используется для внутреннего control protocol и durable state; это не означает наличие JSON CLI-статистики.

Основные локальные проверки (в том же порядке, что quality job CI):

```sh
cargo fmt --all --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets
cargo test --locked --all-targets
```

Сборка и проверка примера:

```sh
cargo build --locked
cargo run --locked -- --config vpn-relay.example.toml --check
```

Интеграционные скрипты требуют Linux, root, network namespaces, TUN, nftables и iproute2. Полный набор приведён в разделе 9.

## 3. Карта репозитория

### Rust-код

- `src/main.rs` — CLI entry point, разбор аргументов вручную, режимы foreground/background, настройка файлового логирования, форматирование табличной статистики.
- `src/lib.rs` — публичная поверхность библиотеки и подключение модулей.
- `src/config.rs` — TOML-модель, serde-типы, defaults, валидация, правила совместимости reload, разбор endpoint/key/CIDR и конфигурационные unit tests.
- `src/import.rs` — импорт WG/AWG .conf, разбор секций и параметров, преобразование в текущую TOML-модель, проверка результата, атомарная запись и import tests.
- `src/routing.rs` — backend-independent routing plan: egress resources, routing decisions, marks, генерация nftables script и команд iproute2, unit tests.
- `src/linux.rs` — Linux adapter: запуск ip/nft, проверка владения ресурсами, установка/удаление nftables и policy routing, поиск/проверка interface identity, низкоуровневый rtnetlink для per-interface IPv4 forwarding, конфигурация TUN link, unit tests.
- `src/runtime.rs` — orchestration и lifecycle: instance lock, Unix control socket, startup/shutdown, reload/peer replacement transactions, snapshots/stats, signal handling, sysctl forwarding ownership, durable state/journal и runtime tests.
- `src/backend/mod.rs` — backend-neutral contracts, snapshots и registry.
- `src/backend/boringtun.rs` — реализация WG/AWG backend поверх BoringTun typed Device API, preflight DNS/peer preparation, peer conversion и snapshots.

### Документация, конфигурация, CI

- `README.md` — пользовательское описание, требования, CLI-примеры и тестовые команды.
- `docs/VPN_RELAY_NFTABLES.md` — подробное описание packet path, hooks, conntrack marks, firewall, routing и NAT.
- `vpn-relay.example.toml` — канонический полный пример конфигурации. Не создавать вторую копию в `examples/`.
- `CHANGELOG.md` — release notes.
- `.github/workflows/ci.yaml` — quality, kernel compatibility, network namespace integration, rootful Podman jobs.
- `.github/workflows/release.yaml` — сборка и draft GitHub Release по тегу `vpn-relay-v<version>`.
- `scripts/vpn-relay-netns-test.sh` — большой сценарий namespace-level startup/reload/rollback и системных ресурсов.
- `scripts/vpn-relay-peer-traffic-test.sh` — реальные WG и AWG handshake, traffic, firewall, reload и recovery сценарии; запускать отдельно с аргументами `wg` и `awg`.
- `scripts/vpn-relay-multi-uplink-test.sh` — end-to-end multi-uplink, routing selectors, priority, NAT и peer ownership.
- `scripts/vpn-relay-per-interface-forwarding-test.sh` — sysctl lifecycle, ACK/readback, recovery и failure injection.
- `scripts/vpn-relay-per-interface-forwarding-packet-test.sh` — фактическая передача IPv4 и IPv6 drop.
- `scripts/vpn-relay-podman.Containerfile` и `scripts/vpn-relay-podman-container-test.sh` — rootful Podman smoke test в отдельном network namespace.

## 4. Архитектура и поток данных

Высокоуровневое направление зависимостей:

```text
CLI (main.rs)
  ├── Config / Import
  └── Runtime
       ├── BackendRegistry
       │    └── BoringTunBackend -> boringtun-awg Device API
       ├── RoutingPlan
       └── Linux adapter
            ├── nftables
            ├── iproute2 policy routing
            ├── TUN link setup / identity
            ├── rtnetlink
            └── sysctl (через runtime)
```

Конфигурация преобразуется в `Config`, валидируется, затем backend делает preflight (включая разрешение peer endpoint DNS в IPv4 адреса). Runtime поднимает fail-closed bootstrap nft policy до создания TUN, создаёт и проверяет tunnel handles, настраивает link, заменяет bootstrap policy на numeric-ifindex policy, устанавливает policy routes и при необходимости управляет IPv4 forwarding. Только после успешного завершения стадий runtime становится рабочим.

BoringTun backend создаёт устройство с отключённым UAPI, задаёт private key/fwmark и полный peer set. `TunnelHandle` скрывает backend от orchestration; snapshots переводят данные движка в backend-neutral типы.

### Routing и packet path

`RoutingPlan::from_config` строит внутренний план:
- egress-таблицы и routing marks;
- отдельные socket fwmarks для внешних зашифрованных UDP sockets;
- conntrack decision IDs, сохраняющие точное решение для flow даже при перекрывающихся selectors;
- firewall allow exceptions для host INPUT/OUTPUT;
- nftables policy и iproute2 команды.

`routing.rs` генерирует правила, но не применяет их. Применение и ownership checks находятся в `linux.rs`. Документ с детальной семантикой — `docs/VPN_RELAY_NFTABLES.md`.

Ключевые правила:
- Новый транзитный flow классифицируется по ingress + source/destination selectors и получает routing mark и conntrack decision ID.
- Последующие пакеты используют сохранённый conntrack decision, а не повторную классификацию.
- Ответный поток возвращается через ingress/main table.
- NAT привязан к выбранному decision ID и паре ingress/egress; NAT сам по себе не разрешает FORWARD.
- INPUT и OUTPUT на managed TUN имеют explicit allow + deny-by-default. Обычный unmanaged host traffic не должен случайно попадать под эти ограничения.
- Socket fwmark внешнего WG/AWG UDP transport не должен направлять сам transport обратно в туннель.
- IPv6 через managed TUN блокируется; IPv6 не должен «случайно заработать» после рефакторинга.

## 5. Критические инварианты безопасности и корректности

Перед изменением networking/runtime обязательно прочитайте соответствующий раздел `docs/VPN_RELAY_NFTABLES.md` и существующие regression tests.

1. **Fail closed.** Bootstrap nft policy устанавливается до создания TUN. Не открывайте окно, в котором интерфейс уже принимает трафик, а firewall ещё не установлен.
2. **Identity, а не только имя.** Managed TUN проверяется по исходному descriptor и ifindex. Linux может переиспользовать имя или ifindex. Не ослабляйте `verify_identity`, nft numeric guards или порядок их установки.
3. **Ownership-safe cleanup.** Удалять можно только ресурсы, принадлежность которых vpn-relay доказана. Не удаляйте чужие nft tables, ip rules/routes, socket paths или sysctl values.
4. **Transactional startup/reload.** Изменение нескольких ресурсов должно иметь явный порядок, rollback и поведение при ошибке rollback. Если rollback не гарантирован, runtime должен завершиться fail-closed, а не продолжить работу в неопределённом состоянии.
5. **Peer updates.** Сначала подготовить/валидировать все изменённые peer sets, затем коммитить. При ошибке последующих стадий откатывать ранее применённые peer sets. Для rollback использовать ранее разрешённые endpoint values, не делать повторный DNS lookup.
6. **Stable conntrack marks.** Не переиспользовать decision ID, который может оставаться в conntrack. История marks хранится durable и должна оставаться совместимой с прежними версиями.
7. **Disjoint marks.** Внешние socket fwmarks и packet routing marks должны быть непересекающимися.
8. **Network namespace scope.** Instance lock, control socket и durable state paths привязаны к inode текущего network namespace. Не превращать их в глобальные без отдельного дизайна.
9. **Private state.** Lock/state/socket permissions, owner, file type, link count, symlink handling, maximum file size и atomic persistence — security properties, а не косметика.
10. **Forwarding ownership.** Восстанавливать только те sysctl значения, которые daemon изменил и чью link identity он повторно проверил. Не перезаписывать изменения оператора и не трогать daemon-owned TUN sysctls как обычные внешние интерфейсы.
11. **Control socket.** Unix socket должен быть приватным, защищённым от подмены пути и удаляться при shutdown только если путь всё ещё указывает на тот же socket inode/device.
12. **No implicit logging.** Без `--log` не создавать файл логов и не писать daemon logs в stdout/stderr. Background mode не должен обходить это правило.
13. **No periodic stats output.** Статистика получается по запросу через control socket и CLI `--stats`; не возвращайте периодический stdout/log spam.
14. **IPv4-only contract.** Не добавлять IPv6 selectors/addresses/endpoints или IPv6 routes/NAT без отдельного изменения архитектуры и security model.

## 6. Runtime lifecycle и control protocol

`Runtime::start` — критическая последовательность startup и rollback. `Runtime::run` обслуживает control socket и shutdown signals. `Drop`/cleanup восстанавливают принадлежащие daemon ресурсы, но не должны маскировать fatal transition.

Состояние экземпляра привязано к network namespace inode. Runtime использует:
- `/run/vpn-relay-netns-<inode>.lock` — flock instance lock;
- соответствующий `.sock` — Unix domain control socket;
- `.marks` — durable conntrack decision mark history;
- `.forwarding` — durable forwarding journal.

Control protocol — внутренние serde JSON messages поверх Unix stream, не публичный HTTP API. Текущие request operations:
- `get_stats`;
- `replace_peers`;
- `reload_config`.

Stats возвращают интерфейсы и peer metadata: public key, AllowedIPs/client IPs, endpoint, TX/RX bytes, возраст последнего handshake. Человеко-читаемая таблица формируется в `main.rs`. JSON не является пользовательским форматом CLI.

CLI аргументы сейчас разбираются вручную в `main.rs`; добавляя опцию, обновляйте usage/help, проверку взаимоисключающих операций и README. Не предполагайте, что используется clap.

Background mode реализован в `main.rs`: fork, setsid, chdir, umask, stdio -> /dev/null, закрытие лишних fd, startup pipe для передачи родителю результата инициализации. Не меняйте fork lifecycle без отдельного теста успешного/ошибочного старта. По умолчанию daemon остаётся foreground.

## 7. Config и importer

`Config::parse_toml/load/validate` — единственный основной путь разбора и проверки daemon config. Не дублируйте validation в CLI, importer или будущих API handlers: вынесите переиспользуемые правила в config/domain слой.

`Config::validate_reload_compatibility` отделяет параметры, изменяемые live reload, от тех, что требуют restart. Это контракт runtime, а не только валидация формы TOML. При добавлении поля явно решите: mutable или immutable during reload, и добавьте тесты на обе стороны.

`deny_unknown_fields` намеренно запрещает молча игнорировать опечатки. Вложенные AWG поля сейчас плоские в `[interfaces.<name>]`; не возвращайте legacy nested `[awg]` без миграционного решения.

Importer принимает WireGuard/AmneziaWG конфигурацию, не пытается угадывать router roles и не должен терять существующие interfaces/routing rules. Он строит TOML, валидирует итоговую конфигурацию и пишет файл атомарно. Неподдерживаемые/непереносимые параметры должны быть явно показаны как warnings, а не молча отбрасываться.

## 8. Как безопасно вносить изменения

- Сначала проследите полный путь данных от CLI/config до backend/Linux side effect и обратно.
- Для сетевого изменения сначала сформулируйте инварианты и failure modes; затем добавляйте unit tests на pure logic и fault-injection, после — namespace packet test.
- Не смешивайте архитектурный рефакторинг и изменение сетевой семантики в одном коммите.
- Сохраняйте публичные config keys и runtime reload compatibility, если задача явно не требует breaking change.
- Любой cleanup должен быть identity/ownership-aware и идемпотентным.
- Ошибки rollback/cleanup нельзя подавлять через `let _ = ...`, если это может оставить host networking в неопределённом состоянии. Уже существующие best-effort cleanup места требуют отдельного обоснования.
- Не делайте shelling out для операции, если существующий Linux adapter уже предоставляет typed rtnetlink путь. И наоборот, не переписывайте рабочую системную интеграцию без теста на реальном kernel behavior.
- Не добавляйте новые зависимости без необходимости; обновление BoringTun revision требует WG + AWG integration tests.
- После изменения Rust-кода запускайте четыре quality-команды. Для затронутого datapath запускайте подходящие namespace тесты. Для backend/crypto changes запускайте WG и AWG traffic tests. Для routing/NAT changes запускайте multi-uplink.
- Не объявляйте тест пройденным, если он не запускался в текущем commit/CI run.

## 9. Тестирование

### Unit / static checks

```sh
cargo fmt --all --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets
cargo test --locked --all-targets
```

Большая часть unit tests сейчас находится рядом с production code в `#[cfg(test)] mod tests`:
- `config.rs`: parsing, schema validation, reload compatibility, marks, CIDRs, firewall config;
- `routing.rs`: nft script, selectors, NAT, conntrack marks, routing plans;
- `linux.rs`: ownership detection, install/rollback failure matrices, rtnetlink parsing, identity checks;
- `runtime.rs`: lock/socket/state security, durable journal, forwarding restore, reload rollback;
- `import.rs`: WG/AWG parsing, warnings, atomic replacement;
- `backend/boringtun.rs`: endpoint preflight and peer parameter conversion;
- `main.rs`: formatting counters and handshake age.

### Linux integration

Запускать из корня репозитория после `cargo build --locked`, с root:

```sh
sudo bash scripts/vpn-relay-netns-test.sh
sudo bash scripts/vpn-relay-per-interface-forwarding-test.sh
sudo bash scripts/vpn-relay-per-interface-forwarding-packet-test.sh
sudo bash scripts/vpn-relay-peer-traffic-test.sh wg
sudo bash scripts/vpn-relay-peer-traffic-test.sh awg
sudo bash scripts/vpn-relay-multi-uplink-test.sh
```

Podman smoke test выполняется CI job `podman`; он намеренно rootful и использует bridge network, отдельный network namespace, `NET_ADMIN` и `/dev/net/tun`.

Тесты с именами `*-test.sh` — не просто unit tests: они создают сетевые namespace/veth, реальные туннели, nftables rules и генерируют traffic. Не удаляйте проверки только потому, что они длинные или дублируют соседние shell commands. Сначала установите, какой отдельный invariant/packet path проверяется, и заменяйте тест только эквивалентной или более сильной проверкой.

### CI

`.github/workflows/ci.yaml` содержит:
- quality: fmt, check, clippy, cargo test;
- kernel compatibility: Ubuntu 22.04 и 24.04, per-interface forwarding + packet/IPv6 drop tests;
- integration: namespace routing/firewall/NAT, config example, WG traffic, AWG traffic, multi-uplink;
- Podman: rootful container deployment smoke test.

Release workflow запускается по тегам `vpn-relay-v*`, сверяет tag с Cargo version и собирает linux x86_64 archive с бинарником, example config, changelog и nftables docs.

## 10. Текущие архитектурные узкие места (наблюдения аудита)

Это не список ошибок datapath, а точки, которые повышают стоимость сопровождения:
- `runtime.rs` (около 3.3k строк) смешивает runtime orchestration, control protocol, IPC socket lifecycle, instance locking, peer/reload transactions, durable conntrack state, forwarding journal/sysctl recovery и большое число тестов.
- `linux.rs` (около 2.5k строк) смешивает process execution, nftables ownership/transactions, iproute2 policy routing, link identity, rtnetlink wire encoding/parsing, forwarding sysctl adapter и тесты.
- `config.rs` (около 2k строк) объединяет schema, defaults, serde adapters, semantic validation, reload compatibility, endpoint/key/CIDR parsing и тесты.
- `routing.rs` (около 1.4k строк) содержит plan construction, conntrack mark history, nftables code generation, ip command generation и тесты.
- `import.rs` (около 700 строк) содержит importer parser, semantic mapping, TOML rendering/validation, atomic persistence и tests.
- Production code и tests находятся в тех же больших файлах; это удобно для локальных приватных helper tests, но ухудшает навигацию и делает файлы тяжёлыми для ревью.
- `main.rs` сам реализует CLI parsing, process daemonization, logging setup и presentation logic; эти обязанности можно разделить.
- Integration shell scripts крупные и сценарно насыщенные. Их размер частично оправдан end-to-end nature, но сценарии/fixtures/assertions можно лучше структурировать.
- Документация в целом уже содержит существенные детали, но критические invariants распределены между README, nftables doc, comments и tests; AGENTS.md должен служить картой, а не копией этих документов.

## 11. Правила изменения этого файла

Обновляйте AGENTS.md при:
- добавлении/удалении модулей или крупных архитектурных компонентов;
- изменении CLI/control protocol или runtime lifecycle;
- изменении поддерживаемых платформ/protocols/IP families;
- изменении CI/test matrix;
- изменении security invariants или durable state format.

Не превращайте AGENTS.md в changelog и не копируйте сюда большие фрагменты реализации. Он должен отвечать на вопросы: где искать код, как компоненты взаимодействуют, какие ограничения нельзя нарушать, какие проверки запускать.
