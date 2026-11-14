# Аудит тестовой системы vpn-relay

Ветка: `refactor/modular-control-api-nftables`

Аудит исходного состояния выполнен по commit `ecb7959ea7c912cc91d69b00c341c5404d6bf334`. Реализация первой итерации тестового этапа добавлена в последующих коммитах этой ветки. Время выполнения и повторяемость требуют подтверждения по результатам GitHub Actions; значения заранее не предполагаются.

## 1. Текущее состояние CI

В `.github/workflows/ci.yaml` определены четыре jobs:

| Job | Содержание | Особенности |
|---|---|---|
| `quality` | fmt, check, clippy, `cargo test --locked --all-targets` | быстрый набор; unit-тесты находятся в том же job |
| `kernel-compatibility` | Ubuntu 22.04/24.04; оба per-interface forwarding сценария | matrix уже выполняется параллельно |
| `integration` | config check, netns, WG traffic, AWG traffic, multi-uplink | все проверки последовательно в одном job; timeout 45 минут |
| `podman` | сборка rootful Podman image и запуск deployment smoke test | отдельный job |

Важное ограничение исходного workflow: push-триггер был включён только для `main` и `daemon-improvements`; push в refactor-ветки не запускал workflow. Это исправлено: push в `refactor/**` теперь запускает CI. PR workflow по-прежнему запускается для PR в `main`.

## 2. Rust-тесты

Обнаружено 180 тестов с атрибутом `#[test]` в исходниках:

| Файл | Количество | Проверяемая область |
|---|---:|---|
| `src/config.rs` | 59 | TOML schema, defaults, валидация, reload compatibility, CIDR/marks, AWG-параметры |
| `src/import.rs` | 6 | импорт WG/AWG конфигураций, замена интерфейса, сохранение остальных данных |
| `src/linux.rs` | 37 | rollback policy routing, nft ownership/apply/remove, rtnetlink ACK/readback, interface identity |
| `src/routing.rs` | 25 | построение routing/firewall/NAT policy, marks и стабильность conntrack decisions |
| `src/runtime.rs` | 48 | lifecycle/control socket, транзакции peer/reload, private state, lock, forwarding journal/recovery |
| `src/backend/boringtun.rs` | 3 | peer keepalive, IPv4 DNS preflight, подготовка endpoint до изменения runtime |
| `src/main.rs` | 2 | форматирование байтов и возраста handshake |

Оценка: сохранять все эти тесты на первом проходе. В основном они проверяют разные инварианты и отказные границы; явного доказательства дублирования по одному только исходному коду нет. Отдельный перенос тестов из production-файлов в `tests.rs` относится к R1 и не является основанием менять их семантику сейчас.

## 3. Shell и системные интеграционные тесты

| Сценарий | Объём | Уникальная ценность | Решение аудита |
|---|---:|---|---|
| `vpn-relay-netns-test.sh` | 1158 строк | startup/shutdown, ownership конфликтов, fail-closed bootstrap, rollback/failure injection, reload/peer replacement, crash recovery, background mode, silence без logging, TUN identity | оставить; критичный lifecycle/transaction regression suite |
| `vpn-relay-peer-traffic-test.sh` | 863 строки | реальный handshake и зашифрованный двусторонний ICMP/TCP/UDP traffic, firewall INPUT/OUTPUT, socket fwmark, forged reply, peer reload/recovery | оставить; выделить отдельные протокольные jobs и добавить AWG 3.1 профиль |
| `vpn-relay-multi-uplink-test.sh` | 1075 строк | многосетевой topology, два клиента, несколько uplink, routing selectors/priority, NAT, peer ownership и reload под реальным трафиком | оставить; отдельный длительный job |
| `vpn-relay-per-interface-forwarding-test.sh` | 182 строки | forwarding sysctl ownership, ACK/readback, recovery, failure injection и сохранение чужих значений | оставить; запускать в kernel compatibility matrix |
| `vpn-relay-per-interface-forwarding-packet-test.sh` | 202 строки | фактическая IPv4 forwarding-передача, deny для неразрешённого ingress, IPv6 drop на managed TUN в OUTPUT и FORWARD | оставить; не эквивалентен sysctl lifecycle тесту |
| `vpn-relay-podman-container-test.sh` + Containerfile | 111 строк + образ | реальный контейнер с private netns, NET_ADMIN, /dev/net/tun, nftables, rtnetlink и sysctl lifecycle | оставить; отдельный deployment job |

### 3.1. Выводы о дублировании

- Netns suite и peer traffic suite используют namespaces, но проверяют разные уровни: первая — lifecycle, resource ownership и транзакции; вторая — реальный зашифрованный datapath и сетевые политики. Не объединять.
- Два per-interface теста не дублируют друг друга: первый проверяет владение sysctl и восстановление состояния, второй — пакетное поведение в реальном topology.
- Multi-uplink не заменяет peer traffic: он проверяет выбор egress и policy routing на многоканальной схеме.
- Podman smoke test проверяет deployment boundary и capabilities, которых нет в обычном netns тесте.
- Rust unit-тесты пересекаются с shell сценариями по некоторым отказным случаям, но shell-тесты подтверждают фактическое поведение ядра/процессов. Удалять их только на основании похожего названия нельзя.

На текущем этапе нет тестов, удаление которых можно обосновать безопасно. Рекомендация: сохранить весь набор, сначала разделить его в CI, затем измерить длительность и стабильность; объединение/удаление возможно только при обнаружении конкретного дублирования после повторных запусков.

## 4. Изоляция и возможность параллельного запуска

Наблюдения по shell-сценариям:

- Netns, peer traffic и multi-uplink используют суффикс PID для имён namespaces, veth и/или nft table; временные файлы создаются через `mktemp -d`.
- Per-interface forwarding сценарии также используют PID в namespace/table names; packet test создаёт несколько namespaces и veth-пары.
- Все основные сценарии устанавливают `trap cleanup EXIT`, останавливают daemon-процессы, удаляют namespaces и временные каталоги.
- Peer traffic и multi-uplink удаляют namespace-scoped conntrack marks state files по inode. Per-interface тесты удаляют относящиеся к ним state/lock/control paths.
- Podman использует фиксированные имена таблиц/образа и host Podman network. Поэтому его следует держать в отдельном job/runner, а не запускать совместно с другими rootful сценариями на одном runner.
- Тесты создают root-level veth в packet test, затем перемещают концы в namespaces. Это безопасно при текущей модели GitHub-hosted jobs (отдельная VM на job), но не является основанием запускать несколько rootful jobs на одном self-hosted runner без дополнительной изоляции.

Итог: текущие сетевые сценарии в целом спроектированы как самостоятельные процессы с PID-scoped ресурсами и cleanup. Перед параллельным запуском нужно проверить их повторные запуски и устранить найденные утечки; не следует вводить параллельные shell-процессы внутри одного runner без отдельного анализа host-level ресурсов.

## 5. Протокольное покрытие: обнаруженный пробел

Исходный `vpn-relay-peer-traffic-test.sh` принимал только `wg` и `awg`; AWG 3.1 extension fields не задавались. Harness расширен до трёх режимов `wg`, `awg3`, `awg31`. В режиме `awg3` на обеих сторонах задаются AWG 3.0-параметры; `awg31` дополнительно включает поля `i1..i5`, header protection key, padding и rekey/keepalive ranges. Набор значений взят из конфигурационного теста `parses_awg_30_and_31_extension_parameters`.

Оба AWG-профиля используют тот же реальный handshake и двусторонний ICMP/TCP/UDP сценарий, что и WG; перед запуском daemon обе конфигурации проходят `--check`. Результат live traffic пока считается неподтверждённым до успешного выполнения новых CI matrix entries.

## 6. Целевая декомпозиция CI

Протокольный harness и CI уже разделены в `.github/workflows/ci.yaml`:

| Job | Набор |
|---|---|
| `quality` | fmt, check, clippy, Rust unit tests |
| `kernel-compatibility` | matrix Ubuntu 22.04/24.04, два per-interface сценария |
| `network-core` | config check + `vpn-relay-netns-test.sh` |
| `protocol-traffic` matrix / `WireGuard` | peer traffic `wg` |
| `protocol-traffic` matrix / `AmneziaWG 3` | peer traffic `awg3` |
| `protocol-traffic` matrix / `AmneziaWG 3.1` | peer traffic `awg31` |
| `multi-uplink` | `vpn-relay-multi-uplink-test.sh` |
| `podman` | существующий rootful deployment smoke test |

Jobs/matrix entries используют отдельные GitHub-hosted runners, имеют явные timeout; протокольная matrix настроена с `fail-fast: false` и `max-parallel: 3`. Добавлен Cargo cache. Общий build job не является обязательным предшественником сетевых jobs, поэтому они могут стартовать параллельно.

## 7. Порядок реализации

1. Выполнено: аудит добавлен, тестовый набор сохранён без удаления.
2. Выполнено: peer traffic harness расширен до WG/AWG 3/AWG 3.1.
3. Выполнено: CI разделён на независимые jobs/matrix entries, push trigger для `refactor/**` включён.
4. Ожидает CI: проверить результаты, длительность и логи; выполнить повторные запуски для подтверждения изоляции.
5. После получения фактических результатов пересмотреть кандидатов на объединение/nightly/manual/удаление.

## 8. Состояние первой реализации

Реализовано в ветке:
- добавлен `docs/TEST_AUDIT.md` с инвентаризацией и решением сохранить все текущие проверки;
- peer traffic harness принимает `wg`, `awg3`, `awg31`;
- CI разделён на `quality`, `kernel-compatibility`, `network-core`, протокольную matrix, `multi-uplink` и `podman`;
- три протокольных сценария могут исполняться одновременно на отдельных runners;
- push trigger включает `refactor/**`, добавлены Cargo cache и явные timeouts.

Не подтверждено до получения CI результатов: успешность реального AWG 3/AWG 3.1 handshake, фактическое wall-clock ускорение и стабильность повторных конкурентных запусков. Никакие существующие тесты не удалялись и не переводились в nightly/manual.
