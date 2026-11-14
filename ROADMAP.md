# ROADMAP — архитектурный рефакторинг vpn-relay

> Рабочий план для ветки `refactor/modular-monolith`, созданной от `daemon-improvements`.
> Обновлять этот файл по мере выполнения: отмечать только фактически завершённые и проверенные пункты.

## Цель и ограничения

- [ ] Провести поэтапный рефакторинг существующего демона без переписывания с нуля.
- [ ] Сохранить внешнее поведение, конфигурационный формат, CLI и сетевую семантику, кроме явно согласованных изменений.
- [ ] Сохранить один Cargo crate и архитектуру модульного монолита.
- [ ] Не дробить код чрезмерно: модуль соответствует самостоятельной области ответственности; новые файлы и абстракции вводятся только при реальной необходимости.
- [ ] Не менять одновременно сетевую семантику и механизм её реализации.
- [ ] Сохранять рабочее состояние проекта после каждого логического этапа.

## Архитектурные решения (зафиксированы)

- Один crate; без разделения на workspace/crates.
- Умеренная декомпозиция: сначала разделение крупных зон ответственности, затем точечное выделение подмодулей только при необходимости.
- Control API независим от транспорта. Его операции: `reload_config`, `get_stats`, `import_config`.
- Unix Domain Socket — первый транспорт поверх Control API; CLI управляет работающим демоном через Unix Socket client.
- HTTP transport сейчас не реализовывать; архитектура должна позволять подключить его позднее без переноса бизнес-логики.
- NFTables: использовать типы crate `nftables` напрямую. Не создавать параллельные копии schema-типов. Допустимы предметные типы приложения и небольшие builders/helpers.
- Сохранить существующие сценарии тестирования и покрытие; переносить тесты вместе с ответственностью, не удалять их ради реорганизации.
- Не добавлять несогласованные функции (HTTP, Web UI, systemd integration, stop/status, автоматический failover, периодическую статистику).

## Этап 0. Baseline и аудит

- [x] Зафиксировать исходный commit и состояние рабочей ветки: `daemon-improvements` на `cff0e57747fc0d4238ecadb3519fe9f55ad41725`; рабочая ветка создана отдельно.
- [x] Изучить `AGENTS.md`, README и NFTables documentation; первично изучены основные исходники. Детальный аудит каждого затрагиваемого участка продолжается перед соответствующим этапом.
- [x] Составить первичную карту крупных модулей и зависимостей по `AGENTS.md` и дереву репозитория.
- [x] Инвентаризировать unit-, integration- и shell-тесты: 183 unit tests на последнем полностью зелёном branch-head CI; тесты размещены в отдельных child modules без удаления assertions и 6 shell integration scripts; подробная привязка каждого сценария к инвариантам продолжается.
- [x] Проверить CLI и control socket protocol: `ControlApi` имеет три операции (`get_stats`, `reload_config`, `import_config`); peer-only replacement — режим `reload_config`. CLI находится в `src/cli.rs`.
- [ ] Изучить текущий Cargo dependency graph и API выбранной версии `nftables`.
- [ ] Зафиксировать фактический набор nftables expressions/objects и способ применения правил (включая зависимость от системного `nft`, если она есть).
- [x] Проверить baseline CI: commit `cff0e57747fc0d4238ecadb3519fe9f55ad41725` прошёл GitHub Actions run `43540974390` (success). Локальный запуск из текущей среды пока не выполнен.
- [ ] Зафиксировать эталонную семантику firewall/routing и порядок startup/reload/rollback.

### Прогресс текущей ветки (2026-11-14)

- Linux adapter декомпозирован: `linux.rs` — общие команды, interface identity и rtnetlink; `linux/nftables.rs` — ownership-safe nft lifecycle; `linux/policy_routing.rs` — iproute2 policy routing. Семантика команд не менялась.

- Import parser отделён в `src/import/parser.rs`; `src/import.rs` оставлен orchestration/validation/atomic-write модулем. Конфигурационная валидация вынесена в `src/config/validation.rs`; TOML schema, parser и reload compatibility остались за прежним фасадом `config.rs`.

- `src/main.rs` преобразован в тонкий entrypoint; CLI живёт в `src/cli.rs`.
- Control API реализован с тремя операциями; Unix wire adapter вынесен в `src/control/unix.rs`. `replace_peers` не является четвёртой API-операцией: он выражен режимом `reload_config`.
- Импорт в работающий Runtime строит кандидат из содержимого профиля и применяет его через reload; исходный файл конфигурации не переписывается этим API. Существующий offline CLI import остаётся файловой операцией.
- CI run `43549664605` для commit `fcf97a8512adae8c6f02674a32caf28ce3ab6b1d` завершился success: format, check, clippy, 181 unit tests, kernel compatibility Ubuntu 22.04/24.04, Podman, netns routing/firewall/NAT, WG traffic, AWG traffic и multi-uplink.
- Локальные команды в среде разработки не выполнялись; проверки подтверждены GitHub Actions.
 
### Configuration and routing extraction progress

- `config/endpoint.rs` now owns endpoint parsing and DNS-name validation; `PeerEndpoint` and `EndpointHost` remain re-exported from `config` to preserve the public API.
- `routing/nft.rs` now owns nftables policy rendering and its selector helpers; `RoutingPlan::nft_script()` remains the public facade. Rule contents and ordering are intended to remain byte-for-byte equivalent.
- Branch-head CI run `43584126385` completed successfully for endpoint and nft renderer extraction: format, check, clippy, 183 unit tests, Ubuntu 22.04/24.04, Podman, routing/firewall/NAT, WG, AWG and multi-uplink all passed.
- Config validation is isolated in `config/validation.rs`; model/parser and reload compatibility remain behind the existing `config.rs` API.
- Conntrack ID allocation/history validation is isolated in `routing/conntrack.rs`; `RoutingPlan` retains its methods as a narrow facade.
- Config, routing, runtime, import, Linux adapter, BoringTun backend and Unix transport tests are moved into dedicated child test modules; all assertions are retained.
- Full verification of this extraction batch passed in branch-head CI run `43585876121`: 183 unit tests, format, check, clippy, Ubuntu 22.04/24.04, Podman, routing/firewall/NAT, WG, AWG and multi-uplink.

### Runtime extraction progress

- `runtime/forwarding.rs`: forwarding sysctl lifecycle, journal persistence, interface validation and recovery.
- `runtime/state.rs`: namespace-scoped instance lock plus durable conntrack mark history validation/load/atomic persistence.
- `runtime/peers.rs`: shared peer commit/rollback transaction helpers.
- `runtime/control_socket.rs`: Unix socket ownership-safe bind/drop and inode checks.
- `runtime/control_api.rs`: Runtime implementation of transport-independent Control API.
- Runtime orchestration remains in one parent module; regression tests live in `runtime/tests.rs` as a child module, preserving private access and all coverage.
- The complete runtime extraction batch is verified by branch-head CI run `43584126385`: 183 unit tests, both kernel compatibility jobs, Podman, routing/firewall/NAT, WG, AWG and multi-uplink all passed.

### Первичные результаты аудита

- В исходном `Cargo.toml` crate `nftables` отсутствует. Текущий генератор находится в `RoutingPlan::nft_script()`, применение — в Linux adapter через `nft -f -`.
- Ownership текущей nft table опирается на table-level comment `managed by vpn-relay`; это часть защитной модели и должно сохраниться.
- Изучена документация `nftables` 0.6.3: crate моделирует JSON API, а `apply_ruleset_raw` вызывает исполняемый `nft` с `-j -f -`; это не устраняет системную зависимость от бинарника.
- `schema::Table` не содержит table-level `comment`, используемый ownership marker `managed by vpn-relay`; `schema::SetType` также не содержит `iface_index`, который нужен для descriptor-verified interface sets. Для сохранения семантики потребуется точечно расширить сериализованный JSON этих двух полей, не создавать параллельные schema-типы и покрыть это тестами. См. [crate docs](https://docs.rs/nftables/latest/nftables/) и [apply_ruleset_raw](https://docs.rs/nftables/latest/nftables/helper/fn.apply_ruleset_raw.html).
- Исходный control protocol имел `get_stats`, `reload_config`, `replace_peers`. В текущей ветке transport API ограничен тремя согласованными операциями; peer-only replacement сохранён как `ReloadConfigMode::ReplacePeers` внутри `reload_config`.
- Первичная инвентаризация baseline: config — 59 tests, import — 6, routing — 25, linux — 37, runtime — 48, backend — 3, CLI — 2. Ветка завершает extraction с 183 unit tests; config/routing/runtime/import/Linux/backend/Unix transport tests находятся в отдельных child modules.


## Этап 1. Умеренная декомпозиция Configuration и Import

- [ ] Разделить ответственность config model, validation и reload compatibility только там, где это уменьшает связность.
- [ ] Сохранить TOML schema, defaults, endpoint/key/CIDR parsing и поведение ошибок.
- [x] Разделить importer на `import/parser.rs` (WG/AWG parsing/conversion) и `import.rs` (orchestration, validation и atomic write), не дробя его на мелкие файлы.
- [x] Сохранить преобразование и валидацию импортируемых конфигураций.
- [x] Сохранить существующую атомарную запись и поведение защиты от перезаписи; отдельный security audit пути записи остаётся частью финальной проверки.
- [x] Сохранить существующие WG/AWG importer tests в `import.rs` и добавить regression test для in-memory import; тесты пока inline, перенос в отдельные test modules остаётся в этапе 8.
- [ ] Выполнить format, check, clippy и относящиеся к этапу tests (CI для текущего изменения ожидается).

## Этап 2. Linux adapter

- [x] Разобрать ответственность `linux.rs`; выделены два самостоятельных адаптера `linux/nftables.rs` и `linux/policy_routing.rs`, без дальнейшего дробления интерфейсных/netlink helpers.
- [x] Сохранить единый общий исполнитель системных команд `run` и общую обработку `LinuxError`; специализированные nft/iproute2 операции вынесены в adapters.
- [x] Разделить policy routing и nftables на самостоятельные модули; interface identity и rtnetlink пока остаются вместе в `linux.rs`, поскольку тесно связаны с TUN/link lifecycle.
- [x] Сохранить проверки fd/ifindex и запрет доверять одному лишь имени интерфейса (перенос не затрагивал эти функции).
- [x] Сохранить ownership-safe checks и cleanup для nftables и iproute2; существующие проверки перенесены без изменения семантики.
- [x] Сохранить обработку ошибок, readback/verification и rollback; функциональность не менялась.
- [x] Существующие Linux tests сохранены и используют внутренние helpers через test-only imports; дополнительные failure-injection tests уже существуют в исходном модуле и остаются на месте.
- [ ] Выполнить относящиеся к этапу проверки после текущего набора изменений (CI ожидается).

## Этап 3. NFTables migration

- [ ] Проверить API и ограничения конкретной версии crate `nftables`.
- [ ] Сопоставить все используемые проектом объекты и выражения с типами библиотеки.
- [ ] Реализовать единый локальный адаптер построения/применения NFTables без дублирования schema.
- [ ] Сохранить точные chains, hooks, priorities, marks, conntrack, sets, verdicts и NAT (если используется).
- [ ] Сохранить fail-closed bootstrap policy и порядок её установки до создания TUN.
- [ ] Сохранить batch atomicity, ownership checks, rollback и безопасный cleanup.
- [ ] Установить фактический механизм применения правил; не заявлять об отказе от бинарника `nft`, если библиотека его использует.
- [ ] Добавить тесты сериализации/построения и сравнение нормализованного ruleset/его семантики.
- [ ] Проверить failure paths и поведение при частичной/неуспешной операции.
- [ ] Удалить старую реализацию только после прохождения эквивалентных тестов.
- [ ] Выполнить относящиеся к этапу проверки и доступные netns tests.

## Этап 4. Routing

- [ ] Отделить вычисление routing policy/plan от применения системных изменений.
- [ ] Сохранить правила приоритетов, selectors, исключения, несколько uplink и NAT semantics.
- [ ] Сохранить разделение socket fwmarks и routing marks.
- [ ] Сохранить стабильность conntrack decision IDs и durable history; не переиспользовать ID, пока conntrack entries могут существовать.
- [ ] Сохранить точную семантику ответного трафика и conntrack decisions.
- [ ] Проверить routing plan unit tests и multi-uplink integration tests.
- [ ] Выполнить относящиеся к этапу проверки.

## Этап 5. Runtime и lifecycle

- [ ] Завершить декомпозицию startup/shutdown, reload и statistics; текущие извлечения control socket, Control API adapter, forwarding recovery, durable state и peer transaction helpers проверены CI.
- [ ] Убедиться, что Runtime не зависит от CLI.
- [ ] Сохранить startup fail-closed порядок: защитная nft policy до создания/активации TUN.
- [ ] Сохранить транзакционность startup/reload и rollback.
- [ ] Сохранить prepare-before-commit для peer updates и rollback с ранее разрешёнными endpoints без повторного DNS lookup.
- [ ] Сохранить instance lock, signal handling, durable state, forwarding journal и sysctl recovery.
- [ ] Сохранить корректный shutdown и ownership-safe освобождение ресурсов.
- [ ] Перенести/адаптировать все runtime tests; добавить failure injection для стадий транзакций.
- [x] Выполнить относящиеся к этапу проверки для текущих извлечённых модулей: CI run 43582217143 для commit e491d3c прошёл все jobs, включая 183 unit tests, обе kernel compatibility jobs, Podman, routing/firewall/NAT, WG, AWG и multi-uplink. Последующие runtime module extractions ожидают отдельной полной CI проверки.

## Этап 6. Control API и Unix transport

- [x] Проверить все существующие socket operations и их потребителей до изменения протокола.
- [x] Определить транспортно-независимые request/error types и границы application API.
- [x] Реализовать ровно три согласованные операции: `reload_config`, `get_stats`, `import_config`.
- [x] Перенести общую логику операций в `ControlApi` implementation для Runtime; транспорт только вызывает API.
- [x] Сохранить Unix Domain Socket как транспорт поверх Control API.
- [x] Выделить Unix server/client в `src/control/unix.rs`; CLI использует client через Runtime.
- [ ] Проверить необходимость protocol versioning; сохранены tagged JSON requests, лимит 1 MiB, read/write timeout и ошибки malformed/unknown requests. Version field не вводился, чтобы не ломать существующий wire protocol.
- [x] Сохранить существующие socket ownership, permissions, anti-symlink/replacement safeguards и namespace isolation.
- [ ] Проверить конкурентные запросы, shutdown transport и ошибки отдельно на уровнях API и транспорта.
- [ ] Удалить/заменить старые операции (включая peer replacement) только после аудита потребителей и определения корректного способа сохранения нужной функциональности.
- [x] Не реализовывать HTTP; `ControlApi` и application DTO не зависят от Unix-specific типов.
- [x] Выполнить Control API unit и Unix socket integration tests: делегирование всех трёх операций и лимит 1 MiB прошли в CI run 43582217143 (commit e491d3c).

## Этап 7. CLI, logging и пользовательская совместимость

- [x] Вынести CLI parsing/dispatch/output в отдельный `src/cli.rs`; `src/main.rs` оставлен тонким entrypoint.
- [ ] Сохранить foreground по умолчанию и `--background`/`-b`.
- [ ] Сохранить logging disabled by default; `--log` без пути и `--log PATH` должны работать как прежде.
- [ ] Сохранить `--stats` через Control API и человекочитаемую таблицу; не добавлять JSON или периодический вывод.
- [ ] Сохранить отображение peer public key, client IP/AllowedIPs, endpoint, RX/TX, handshake age и totals в понятных единицах.
- [ ] Проверить CLI help, exit codes, сообщения об ошибках и config check mode.

## Этап 8. Тесты, документация и архитектурная проверка

- [ ] Сохранить все существующие уникальные тестовые сценарии; ни один тест не удалять без доказательства дублирования/устаревания и фиксации причины.
- [x] Разместить config/import/routing/Linux/backend/control/runtime tests в отдельных логических child modules; все 183 unit tests сохранены.
- [x] Проверить config/import/routing/firewall/backend/control/runtime/Linux adapters через unit и branch-head CI.
- [x] Проверить shell integration tests и сценарии WG, AWG и multi-uplink в CI run `43585876121`.
- [x] Обновить README и `docs/VPN_RELAY_NFTABLES.md` под текущие архитектурные границы; примеры конфигурации не менялись.
- [x] Обновить `AGENTS.md` по фактической архитектуре и тестовым модулям.
- [ ] Проверить отсутствие дублирующих реализаций, временных compatibility paths и неиспользуемого кода.
- [ ] Проверить Cargo dependency changes и отсутствие ненужных зависимостей.

## Этап 9. Финальная верификация

- [ ] `cargo fmt --all --check`
- [ ] `cargo check --locked --all-targets`
- [ ] `cargo clippy --locked --all-targets`
- [ ] `cargo test --locked --all-targets`
- [ ] `cargo build --locked --release`
- [ ] `cargo run --locked -- --config vpn-relay.example.toml --check`
- [ ] `sudo bash scripts/vpn-relay-netns-test.sh`
- [ ] `sudo bash scripts/vpn-relay-per-interface-forwarding-test.sh`
- [ ] `sudo bash scripts/vpn-relay-per-interface-forwarding-packet-test.sh`
- [ ] `sudo bash scripts/vpn-relay-peer-traffic-test.sh wg`
- [ ] `sudo bash scripts/vpn-relay-peer-traffic-test.sh awg`
- [ ] `sudo bash scripts/vpn-relay-multi-uplink-test.sh`
- [ ] `sudo bash scripts/vpn-relay-podman-container-test.sh` (если среда предоставляет Podman/rootful capabilities)
- [ ] Проверить полный GitHub Actions CI для итогового commit.
- [ ] Просмотреть итоговый diff, проверить чистоту ветки и отсутствие случайных изменений.
- [ ] Обновить этот ROADMAP: отметить только фактически выполненное; указать пропущенные проверки и причины.

## Критические инварианты — обязательны на каждом этапе

- [ ] Fail-closed: firewall protection устанавливается до создания/активации TUN.
- [ ] Interface identity: fd/ifindex checks; не полагаться только на interface name.
- [ ] Ownership-safe cleanup: не удалять чужие ресурсы.
- [ ] Startup/reload transactions: prepare, commit, rollback; при неуспешном rollback — безопасное fail-closed поведение.
- [ ] Peer updates: prepare-before-commit; rollback использует ранее разрешённые endpoint values.
- [ ] Conntrack decision IDs не переиспользуются преждевременно.
- [ ] Socket fwmarks отделены от routing marks.
- [ ] Lock/socket/state остаются namespace-scoped.
- [ ] Private state: permissions, symlink checks и atomic persistence сохранены.
- [ ] Forwarding/sysctl восстанавливается с учётом ownership.
- [ ] Control socket защищён от подмены.
- [ ] Сохранён IPv4-only контракт; IPv6 через managed TUN блокируется.

## Журнал выполнения

| Дата | Этап | Результат | Commit / CI |
|---|---|---|---|
| 2026-11-14 | Создание плана | ROADMAP добавлен в рабочую ветку | `57fd65f` |
| 2026-11-14 | Control protocol extraction | Вынесены wire DTO и типы статистики из `runtime.rs` в `control.rs`; формат существующего протокола сохранён | `794f4f7` |
| 2026-11-14 | CI setup | Push-проверки включены для рабочей ветки. Первый CI прошёл quality, kernel compatibility, Podman и netns routing/firewall/NAT; после CLI extraction следующий CI выявил только rustfmt-порядок imports/modules, исправленный в этом commit. | [run 43547350227](https://github.com/lelikulibina/vpn-relay/actions/runs/43547350227) |
| 2026-11-14 | CLI extraction | CLI вынесен из бинарного entrypoint в `cli.rs`; `main.rs` оставлен тонким запускателем | `ece223e` |
| 2026-11-14 | Formatting fix | Исправлен порядок imports/modules по замечанию `cargo fmt --all --check` | текущий commit |
| 2026-11-14 | Routing/config/runtime extraction | Выделены config validation и conntrack ID allocation; config/routing/runtime tests перемещены в отдельные child modules | [CI 43585876121](https://github.com/lelikulibina/vpn-relay/actions/runs/43585876121), success |
| 2026-11-14 | Test module extraction | Import, Linux adapter, BoringTun backend и Unix transport tests вынесены в dedicated child modules без удаления assertions | [CI 43585876121](https://github.com/lelikulibina/vpn-relay/actions/runs/43585876121), success |

