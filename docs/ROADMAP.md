# Дорожная карта vpn-relay

Документ описывает запланированные архитектурные работы. Он не заменяет `AGENTS.md` (карта текущего кода и инварианты) и `CHANGELOG.md` (выпущенные изменения). При расхождении с кодом источником истины остаётся код и тесты; после завершения этапа обновляйте таблицу статуса и `AGENTS.md`.

## Статус

| Этап | Содержание | Статус |
|------|-----------|--------|
| R0 | Анализ проекта, этот план | выполнен |
| P0 | Переработка тестовой системы и CI | выполнен; baseline и все 9 CI jobs подтверждены |
| R1 | Модульное деление крупных файлов без изменения поведения | выполнен; CLI, config, Linux, routing и runtime разделены; control protocol/transport вынесены в R2 |
| R2 | Control API, независимый от транспорта; Unix socket как первый транспорт | выполняется; API/dispatch/Unix transport выделены; error mapping, legacy wire compatibility, лимиты, bounded serialization и edge cases (empty/malformed/truncated request/response, connect failure, read timeout) подтверждены полным CI 9/9 (run `43641558208`, HEAD `ed94bd8`); финальная сверка критериев и документации продолжается |
| R3 | Перенос nftables-логики на крейт `nftables` | запланирован |
| R4 | Дальнейшие улучшения (см. «Вне текущего рефакторинга») | идеи |

Ветка рефакторинга: `refactor/modular-control-api-nftables` (от `daemon-improvements`).


## Приоритет 0. Переработка тестовой системы и CI

Этот этап выполняется первым — до реализации R1, R2, R3 и любых остальных архитектурных задач. Его цель — установить надёжный baseline, убрать избыточные проверки и подготовить независимый параллельный запуск сетевых сценариев. Аудит не должен менять поведение демона.

### 0.1. Аудит существующих тестов

Провести инвентаризацию всех проверок:
- Rust unit- и integration-тестов;
- shell- и network namespace-сценариев;
- тестов WireGuard, AmneziaWG 3 и AmneziaWG 3.1;
- multi-uplink, per-interface forwarding и Podman.

Для каждого теста зафиксировать:
- проверяемый контракт, регрессионный риск или сценарий отказа;
- уровень проверки и уникальную ценность;
- длительность, привилегии, системные зависимости и требования к окружению;
- детерминированность, изоляцию ресурсов и возможность параллельного запуска;
- дублирование с другими тестами.

По результатам принять обоснованное решение: оставить, объединить, переписать, перенести в nightly/manual либо удалить. Удалять тест можно только если его уникальный сценарий надёжно покрыт другой проверкой либо соответствующий контракт больше не поддерживается. Причину каждого удаления зафиксировать.

### 0.2. Минимально достаточный набор

Сформировать тестовую пирамиду без дублирования:
- быстрые unit-тесты без root и внешней сети — чистая логика, преобразования, валидация и ошибки;
- component-тесты — взаимодействие модулей и системных адаптеров с контролируемыми зависимостями;
- network integration — только сценарии, для которых необходим реальный kernel/network namespace;
- ограниченный end-to-end/deployment набор для критичных пользовательских сценариев.

### 0.3. Независимый параллельный запуск протоколов

Сетевые тесты трафика WG, AWG 3 и AWG 3.1 должны выполняться параллельно в отдельных GitHub Actions jobs (или независимых элементах matrix). У каждого протокола должны быть собственные окружение, логи и timeout.

Перед включением параллелизма:
- исключить пересечение network namespace, интерфейсов, адресов, процессов и временных файлов;
- использовать уникальные имена ресурсов на job и на тест;
- гарантировать cleanup через trap/finally при успехе и ошибке;
- проверить повторные и конкурентные запуски;
- не запускать одновременно rootful-сценарии на одном runner, если они изменяют общие host-level ресурсы.

Общую сборку разрешается переиспользовать через Cargo cache или artifact, если это не создаёт общих изменяемых ресурсов между тестами.

### 0.4. Разделение длительных групп GitHub Actions

После аудита разделить длительные независимые проверки на отдельные jobs, чтобы они выполнялись одновременно. Целевая декомпозиция:
- `quality` — fmt, check, clippy и быстрые unit-тесты;
- `kernel-compatibility` — проверки поддерживаемых версий Ubuntu/kernel;
- `network-core` — базовые routing/firewall/NAT сценарии;
- `protocol-wg` — WG peer traffic;
- `protocol-awg3` — AWG 3 peer traffic;
- `protocol-awg31` — AWG 3.1 peer traffic;
- `multi-uplink` — отдельная проверка multi-uplink;
- `podman` — deployment smoke/integration.

Окончательное число jobs определить по результатам аудита и фактической длительности. Не дробить короткие тесты искусственно, если накладные расходы runner и повторная сборка увеличивают общее время CI.

Настроить `fail-fast: false` для независимых протокольных проверок, явные `timeout-minutes`, кеширование Cargo, сохранение логов при падении и понятные имена jobs. Обязательные для PR проверки не должны незаметно переезжать в nightly/manual.

### 0.5. Критерии завершения

- Зафиксирован baseline до архитектурных изменений.
- Для каждого оставшегося теста документирована проверяемая ценность.
- Удалённые или объединённые тесты имеют записанное обоснование.
- WG, AWG 3 и AWG 3.1 выполняются параллельно в независимых jobs.
- Длительные независимые группы не блокируют друг друга последовательным запуском в одном job.
- Нет зависимости от порядка выполнения; повторные и конкурентные запуски стабильны.
- В CI доступны длительность, логи и причина падения каждой группы.

## Результаты анализа

Исходная точка — около 10 тыс. строк Rust, из них примерно 40 % составляют тесты внутри тех же файлов.

| Файл | Строк | Смешанные ответственности |
|------|-------|---------------------------|
| `src/runtime.rs` | 3335 | lifecycle Runtime; transaction reload/peer replace; control protocol и Unix socket; instance lock; durable state conntrack marks; forwarding journal и sysctl; signal handlers; ~1400 строк тестов |
| `src/linux.rs` | 2519 | запуск `ip`/`nft`; ownership nft-таблицы; policy routing (iproute2); identity интерфейсов; wire-кодирование rtnetlink для per-interface forwarding; ~1140 строк тестов |
| `src/config.rs` | 2040 | serde-схема и defaults; семантическая валидация; reload compatibility; разбор endpoint/key/CIDR; ~1050 строк тестов |
| `src/routing.rs` | 1378 | построение плана; история conntrack marks; генерация текста nft-скрипта; генерация команд `ip`; тесты |
| `src/main.rs` | 455 | разбор CLI; daemonize/fork; настройка логов; форматирование статистики |
| `src/import.rs` | 690 | parser `.conf`; маппинг в TOML; атомарная запись |

Наблюдения, определяющие план:

1. Control protocol (`ControlRequest`, `ControlResponse`, `ControlSocket`, `handle_control_connection`, `send_control_request`) реализован внутри `runtime.rs` и прямо привязан к `UnixStream`. Подключить второй транспорт (HTTP) без дублирования логики нельзя.
2. Операции control-плоскости (`replace_peers`, `reload_config`, статистика) уже являются методами `Runtime`, то есть бизнес-логика отделима от транспорта — нужно лишь ввести явную границу.
3. nftables-политика строится как текст (`RoutingPlan::nft_script`, ~320 строк с `format!`), а переход на числовые ifindex выполняется последующими `String.replace`. Эта схема хрупка: правила проверяются только сравнением подстрок.
4. Проверка владения таблицей (`table-level comment`) использует JSON и текстовый fallback для nftables 1.0.2 (Ubuntu 22.04), где comment отсутствует в JSON.
5. Интеграционные скрипты подменяют `nft` shim-ами, которые выбирают поведение по argv (`delete table inet …`, `-f`). После перехода на JSON-batch через stdin эти shim-ы придётся переписать.
6. В `AGENTS.md` (раздел 10) те же узкие места названы как главные расходы на сопровождение.

## Общие правила для всех этапов

- Один этап — один или несколько коммитов; архитектурное перемещение кода не смешивается с изменением сетевой семантики (`AGENTS.md`, раздел 8).
- Публичный API библиотеки (`lib.rs`) и ключи конфигурации остаются совместимыми; публичные пути `vpn_relay::config::*`, `vpn_relay::linux::*`, `vpn_relay::routing::*` сохраняются через `pub use`.
- Формат wire-протокола control socket остаётся совместимым: новый CLI работает со старым daemon и наоборот, пока не объявлено обратное.
- Инварианты `AGENTS.md`, раздел 5, не ослабляются: fail-closed bootstrap, identity-проверки, ownership-safe cleanup, приватные state-файлы, привязка к network namespace.
- После каждого этапа выполняются все четыре quality-команды и, для затронутого datapath, соответствующие netns-сценарии (`AGENTS.md`, раздел 9).
- Модули остаются крупными единицами ответственности (не больше одного уровня вложенности каталогов); дробление «по одной функции на файл» не планируется.

## Целевая структура

```text
src/
├── main.rs                  # тонкий вход: vpn_relay::cli::main()
├── lib.rs
├── cli/                     # R1: разбор аргументов, daemonize, логирование, вывод
│   ├── mod.rs               #   dispatch команд
│   ├── args.rs              #   Command, разбор и проверка взаимоисключений
│   ├── daemon.rs            #   fork/setsid/startup pipe, init_logging
│   └── output.rs            #   таблица статистики, форматирование
├── config/                  # R1
│   ├── mod.rs               #   публичные re-export, load/parse
│   ├── schema.rs            #   serde-типы и defaults
│   ├── validate.rs          #   Config::validate, resolved marks
│   ├── reload.rs            #   validate_reload_compatibility
│   ├── parse.rs             #   endpoint/key/CIDR/имена
│   └── tests.rs
├── import.rs                # без изменений в R1 (может быть разделён позже)
├── routing/                 # R1; R3 заменяет nft_text.rs на typed firewall model
│   ├── mod.rs               #   RoutingPlan, from_config, bind_interface_indices
│   ├── marks.rs             #   стабильные conntrack decision marks
│   ├── nft_text.rs          #   текущий генератор nft-скрипта (удаляется в R3)
│   └── tests.rs
├── linux/                   # R1 (бывший linux.rs, публичные пути сохранены)
│   ├── mod.rs               #   LinuxError, re-export
│   ├── exec.rs              #   запуск процессов
│   ├── nft.rs               #   ownership + apply/remove таблицы (R3: nftables crate)
│   ├── policy.rs            #   iproute2 policy routing
│   ├── link.rs              #   interface identity, configure_interface
│   ├── netlink.rs           #   rtnetlink: per-interface IPv4 forwarding
│   └── tests.rs
├── runtime/                 # R1
│   ├── mod.rs               #   Runtime, start/run/drop, signal handling, RuntimeError
│   ├── reload.rs            #   reload_config, replace_peers, rollback
│   ├── lock.rs              #   InstanceLock и пути state/socket по netns inode
│   ├── state.rs             #   durable история conntrack marks
│   ├── forwarding.rs        #   forwarding journal и sysctl
│   └── tests.rs
├── control/                 # R2
│   ├── mod.rs
│   ├── api.rs               #   trait ControlApi, ControlRequest/Response, ControlError
│   ├── dispatch.rs          #   запрос → ControlApi → ответ (транспортно-независимо)
│   └── unix.rs              #   UnixTransport (сервер) и UnixClient
└── backend/                 # без изменений
```

Направление зависимостей:

```text
cli ──► control::client ──► (Unix socket) ──► control::unix ──► control::dispatch ──► ControlApi
                                                                                         ▲
runtime ───────────────────────────── реализует ControlApi ──────────────────────────────┘
runtime ──► linux (nft, policy, link, netlink) ──► routing (план, не применяет)
runtime ──► backend ──► boringtun-awg
config ◄── все слои (только типы и валидация)
```

Правило: `control` не знает про `linux` и `backend`; `runtime` не знает про конкретный транспорт; `routing` не выполняет побочных эффектов.

## R1. Модульное деление (без изменения поведения)

Цель: убрать смешение ответственностей и вынести тесты, не меняя ни одной строки логики.

| Исходный файл | Куда |
|---------------|------|
| `runtime.rs` | `runtime/mod.rs` (Runtime, start, run, Drop, signals, RuntimeError), `runtime/reload.rs`, `runtime/lock.rs`, `runtime/state.rs`, `runtime/forwarding.rs`, `runtime/tests.rs`; Control API и Unix transport вынесены в `control/` (R2) |
| `linux.rs` | `linux/{mod,exec,nft,policy,link,netlink}.rs`, `linux/tests.rs` |
| `config.rs` | `config/{mod,schema,validate,reload,parse}.rs`, `config/tests.rs` |
| `routing.rs` | `routing/{mod,marks,nft_text}.rs`, `routing/tests.rs` |
| `main.rs` | `cli/{mod,args,daemon,output}.rs`; `main.rs` остаётся точкой входа |

Технические решения:

- Код переносится механически (скрипт разбора top-level items с проверкой, что ни один item не потерян и не продублирован); логика не редактируется.
- Приватные функции, нужные соседним подмодулям и тестам, получают `pub(super)`; публичные пути сохраняются через `pub use` в `mod.rs`.
- Тесты переносятся целыми блоками в `tests.rs` соответствующего модуля, чтобы не нарушить общие helper-ы; разнесение тестов по подмодулям — отдельная последующая задача.

Критерии готовности:

- `cargo fmt --all --check`, `cargo check --locked --all-targets`, `cargo clippy --locked --all-targets`, `cargo test --locked --all-targets` проходят;
- число и имена тестов совпадают с состоянием до этапа;
- `git diff -M --stat` показывает перемещения, а не переписывание;
- `AGENTS.md` обновлён (карта репозитория и раздел узких мест).

## R2. Control API поверх Unix socket

Цель: отделить операции управления от транспорта, чтобы позже добавить HTTP API без правки runtime.

Проект:

1. `control::api::ControlApi` — трейт операций daemon:
   - `get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError>`;
   - `replace_peers(&mut self, interface: &str, peers: Vec<PeerConfig>) -> Result<(), ControlError>`;
   - `reload_config(&mut self, toml: &str) -> Result<(), ControlError>`;
   - `is_fatal(&self) -> bool` (после fatal-перехода транспорт прекращает принимать запросы).
2. `ControlRequest` / `ControlResponse` — те же serde-типы и тот же JSON (`operation` в snake_case; `ok`, `error`, `stats`). Добавляется только необязательное поле `error_kind` (`invalid_request`, `configuration`, `conflict`, `unavailable`, `fatal`, `internal`) с `skip_serializing_if`, чтобы старые клиенты продолжали работать, а будущий HTTP транспорт мог выбирать статус-коды.
3. `control::dispatch::handle(api, request) -> ControlResponse` — единственное место, где запрос превращается в вызов `ControlApi` и результат — в ответ.
4. `ControlTransport` — трейт `poll(&mut self, api: &mut dyn ControlApi)`; Runtime хранит список транспортов и в `run()` временно забирает их (`mem::take`) для опроса, чтобы не конфликтовал заём `self`.
5. `control::unix` — `UnixTransport` (приватные права, защита от подмены пути, удаление только своего inode, лимит запроса 1 MiB, лимит ответа 4 MiB, таймауты чтения/записи по 5 секунд) и `UnixClient` (лимит запроса 1 MiB до connect, лимит ответа 4 MiB, таймаут записи 5 секунд и чтения 300 секунд). Ответ сериализуется через ограниченный writer, не выделяющий буфер сверх лимита. `Runtime::request_*` остаются тонкими обёртками для совместимости библиотеки.
6. `RuntimeError` → `ControlError` через явное отображение, без потери текста ошибки.

Будущий HTTP транспорт (вне R2, но проект учитывает):

- реализует `ControlTransport`, маппит маршруты на `ControlRequest`, а `error_kind` на HTTP status;
- включается отдельным cargo feature и отдельной секцией конфигурации (bind-адрес, аутентификация, TLS); по умолчанию выключен, daemon остаётся доступен только локально;
- обязательные меры перед выпуском: аутентификация, лимиты размера/времени, запрет привязки к публичному адресу без явного подтверждения. Эти требования нужно оформить отдельным документом безопасности.

Критерии готовности:

- существующие unit-тесты control socket (права 0600, удаление при drop, защита от подмены, stale socket, lifecycle) проходят без ослабления проверок;
- добавлены тесты на `dispatch` с мок-`ControlApi` (каждая операция, ошибка, fatal, слишком большой запрос) и на совместимость JSON со старым форматом (десериализация фиксированных строк);
- netns-сценарии `--stats`, `--reload`, `--replace-peers` проходят без изменений.

## R3. Полный перенос nftables-логики на крейт `nftables`

Цель: заменить текстовую генерацию скрипта и разбор вывода `nft` на типизированную модель и крейт [`nftables`](https://crates.io/crates/nftables).

Важное свойство крейта: он управляет правилами через процесс `nft` в JSON-режиме (`nft -j`), то есть зависимость от бинарника `nft` сохраняется, а нетипизированные строки исчезают.

Шаги:

- **R3.0 Spike покрытия.** Проверить, что крейт выражает все используемые конструкции: set `ifname`/`iface_index` с elements, `iif`/`iifname` по набору и числу, `meta nfproto`, `ct state`, `ct direction`, `ct mark` с побитовыми операциями (маска/or), `meta mark set`, `counter`, `drop`/`accept`/`return`, `masquerade`, `snat ip to`, table-level `comment`, цепочки с hook/priority/policy. Если конструкция не поддерживается — зафиксировать решение (вклад в крейт, либо изолированный raw-fallback с тестом).
- **R3.1 Шов.** В `linux::nft` ввести трейт применения (`NftApplier`) и переключаемую реализацию; текущая реализация (скрипт + `nft`) остаётся эталоном. Поведение не меняется.
- **R3.2 Typed model.** Новый модуль `routing/firewall.rs`: промежуточная модель правил (`Chain`, `Rule`, `Match`, `Action`) строится из `RoutingPlan`; индексы интерфейсов подставляются при построении, а не заменой подстрок. Модель переводится в объекты крейта.
- **R3.3 Эквивалентность.** Интеграционный сценарий применяет обе реализации в отдельных netns и сравнивает нормализованный `nft list table` — вывод должен совпасть для bootstrap-политики, индексной политики, multi-uplink, NAT (none/masquerade/snat) и firewall INPUT/OUTPUT.
- **R3.4 Ownership.** Проверка владения через `get_current_ruleset` крейта сохраняет строгие условия: точные family/name и table-level comment. Для nftables 1.0.2, где JSON не содержит comment, сохраняется текстовый fallback (отдельный маленький адаптер с тестами) либо вводится эквивалентный маркер владения; решение принимается по результатам kernel-compatibility CI на Ubuntu 22.04 и 24.04.
- **R3.5 Переключение и удаление.** Крейт становится единственной реализацией; `nft_text.rs`, `String::replace`-подстановки индексов и дублирующий разбор вывода удаляются. Shim-ы в `scripts/vpn-relay-netns-test.sh` (строки с `$1 = delete`, `$1 = -f`) переписываются под JSON-batch через stdin и новые аргументы вызова.
- **R3.6 Документация.** Обновить `docs/VPN_RELAY_NFTABLES.md` (разделы «Владение ресурсами» и «Проверки»), `AGENTS.md`, README и CHANGELOG.

Риски и контроль:

- Нарушение fail-closed окна: bootstrap и индексная политика применяются тем же одиночным атомарным batch (delete+add), порядок и рекурсия rollback не меняются.
- Дрейф правил: golden-тесты на JSON модели и интеграционная эквивалентность (R3.3) обязательны до удаления старого генератора.
- Зависимости: добавление крейта обновляет `Cargo.lock`; CI использует `--locked`, поэтому lock-файл коммитится вместе с изменением `Cargo.toml`. Новая зависимость должна пройти проверку лицензии (проект — BSD-3-Clause).
- Совместимость `nft`: JSON-режим требует сборки nftables с jansson (уже требуется текущим кодом `nft -j list table`); проверить образ Podman и обе версии Ubuntu.

Критерии готовности: все netns-сценарии (`netns`, `multi-uplink`, `peer-traffic wg/awg`, оба per-interface) и Podman smoke test проходят; в коде нет форматирования nft-текста; ownership-проверки покрыты тестами не слабее текущих.

## Вне текущего рефакторинга

- HTTP/REST API транспорт и модель аутентификации (см. R2, «Будущий HTTP транспорт»).
- Замена вызовов `ip rule`/`ip route` typed rtnetlink-реализацией (по правилам `AGENTS.md` — только с тестами на реальном kernel behavior).
- Разнесение тестов по подмодулям вместо одного `tests.rs` на модуль; разделение `import.rs`.
- Структурирование shell-сценариев (общие fixtures и assertions).
- Переход CLI на `clap` и JSON-вывод статистики (потребует явного решения по контракту CLI).
- Остальные пункты из раздела «Не предполагайте» в `AGENTS.md`: systemd unit, команды stop/status, автоматический failover, IPv6.
