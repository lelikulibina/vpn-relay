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
- [ ] Инвентаризировать unit-, integration- и shell-тесты; связать тесты с проверяемыми инвариантами.
- [x] Проверить текущие CLI и control socket protocol: `get_stats`, `reload_config`, `replace_peers`; CLI-потребители найдены в `main.rs`. Решение по сохранению peer replacement ещё требует отдельного проектирования.
- [ ] Изучить текущий Cargo dependency graph и API выбранной версии `nftables`.
- [ ] Зафиксировать фактический набор nftables expressions/objects и способ применения правил (включая зависимость от системного `nft`, если она есть).
- [x] Проверить baseline CI: commit `cff0e57747fc0d4238ecadb3519fe9f55ad41725` прошёл GitHub Actions run `43540974390` (success). Локальный запуск из текущей среды пока не выполнен.
- [ ] Зафиксировать эталонную семантику firewall/routing и порядок startup/reload/rollback.

## Этап 1. Умеренная декомпозиция Configuration и Import

- [ ] Разделить ответственность config model, validation и reload compatibility только там, где это уменьшает связность.
- [ ] Сохранить TOML schema, defaults, endpoint/key/CIDR parsing и поведение ошибок.
- [ ] Разделить importer на логические части WG/AWG parsing и безопасной записи, не создавая мелких модулей без необходимости.
- [ ] Сохранить преобразование и валидацию импортируемых конфигураций.
- [ ] Сохранить атомарную запись и защиту от небезопасных путей/перезаписи.
- [ ] Перенести/адаптировать все существующие тесты; добавить недостающие regression tests.
- [ ] Выполнить format, check, clippy и относящиеся к этапу tests.

## Этап 2. Linux adapter

- [ ] Разобрать ответственность текущего `linux.rs` и определить минимально необходимую декомпозицию.
- [ ] Изолировать выполнение системных команд и обработку их результатов.
- [ ] Разделить interface lifecycle/identity, policy routing и rtnetlink только если границы получаются самостоятельными.
- [ ] Сохранить проверки fd/ifindex и запрет доверять одному лишь имени интерфейса.
- [ ] Сохранить ownership-safe проверки и cleanup; не удалять чужие ресурсы.
- [ ] Сохранить обработку ошибок, readback/verification и rollback.
- [ ] Перенести/адаптировать существующие Linux tests и добавить failure-injection cases.
- [ ] Выполнить относящиеся к этапу проверки.

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

- [ ] Разделить startup/shutdown, reload, peer management, statistics и state recovery по крупным ответственностям, избегая чрезмерного числа файлов.
- [ ] Убедиться, что Runtime не зависит от CLI.
- [ ] Сохранить startup fail-closed порядок: защитная nft policy до создания/активации TUN.
- [ ] Сохранить транзакционность startup/reload и rollback.
- [ ] Сохранить prepare-before-commit для peer updates и rollback с ранее разрешёнными endpoints без повторного DNS lookup.
- [ ] Сохранить instance lock, signal handling, durable state, forwarding journal и sysctl recovery.
- [ ] Сохранить корректный shutdown и ownership-safe освобождение ресурсов.
- [ ] Перенести/адаптировать все runtime tests; добавить failure injection для стадий транзакций.
- [ ] Выполнить относящиеся к этапу проверки.

## Этап 6. Control API и Unix transport

- [ ] Проверить все существующие socket operations и их потребителей до изменения протокола.
- [ ] Определить транспортно-независимые request/response/error types и границы application API.
- [ ] Реализовать ровно три согласованные операции: `reload_config`, `get_stats`, `import_config`.
- [ ] Перенести общую логику операций в Control API/application services; не дублировать её в транспорте.
- [ ] Сохранить Unix Domain Socket как транспорт поверх Control API.
- [ ] Реализовать/сохранить Unix server и client; CLI использует client для управления работающим демоном.
- [ ] Сохранить protocol versioning, безопасную сериализацию, обработку malformed/unknown requests и disconnects.
- [ ] Сохранить socket ownership, permissions, anti-symlink/replacement safeguards и namespace isolation.
- [ ] Проверить конкурентные запросы, shutdown transport и ошибки отдельно на уровнях API и транспорта.
- [ ] Удалить/заменить старые операции (включая peer replacement) только после аудита потребителей и определения корректного способа сохранения нужной функциональности.
- [ ] Не реализовывать HTTP сейчас; проверить, что API не зависит от Unix-specific типов.
- [ ] Выполнить Control API unit и Unix socket integration tests.

## Этап 7. CLI, logging и пользовательская совместимость

- [ ] Разделить CLI parsing/dispatch/output умеренно, без создания модулей ради отдельных функций.
- [ ] Сохранить foreground по умолчанию и `--background`/`-b`.
- [ ] Сохранить logging disabled by default; `--log` без пути и `--log PATH` должны работать как прежде.
- [ ] Сохранить `--stats` через Control API и человекочитаемую таблицу; не добавлять JSON или периодический вывод.
- [ ] Сохранить отображение peer public key, client IP/AllowedIPs, endpoint, RX/TX, handshake age и totals в понятных единицах.
- [ ] Проверить CLI help, exit codes, сообщения об ошибках и config check mode.

## Этап 8. Тесты, документация и архитектурная проверка

- [ ] Сохранить все существующие уникальные тестовые сценарии; ни один тест не удалять без доказательства дублирования/устаревания и фиксации причины.
- [ ] Разместить тесты в отдельных логических test modules; не создавать пустые/избыточные каталоги.
- [ ] Проверить config/import/routing/firewall/backend/control/runtime/Linux adapters.
- [ ] Проверить shell integration tests и сценарии WG и AWG.
- [ ] Обновить README, `docs/VPN_RELAY_NFTABLES.md`, примеры конфигурации при необходимости.
- [ ] Обновить `AGENTS.md` по фактической итоговой архитектуре и командам.
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
| 2026-11-14 | Создание плана | ROADMAP добавлен в рабочую ветку | `57fd65f` |\n| 2026-11-14 | Control protocol extraction | Вынесены wire DTO и типы статистики из `runtime.rs` в `control.rs`; формат существующего протокола сохранён | `794f4f7` |\n| 2026-11-14 | CI setup | Push-проверки включены для рабочей ветки | ожидается CI |
