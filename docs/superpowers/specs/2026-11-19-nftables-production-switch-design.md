# R3.5 — production nftables JSON applier

## Цель

Переключить production `SystemNftApplier` с текстового `RoutingPlan::nft_script()` на typed `RoutingPlan::firewall_ruleset()` и JSON batch API `nftables = 0.6.3`. После подтверждённой эквивалентности удалить legacy string generator, не меняя firewall semantics, Runtime lifecycle, публичные API или ownership contract.

## Подтверждённая база

- R3.2 предоставляет ordered AST и `FirewallRuleset::to_json_value()`. JSON сохраняет table-level ownership comment и `iface_index`, отсутствующие в upstream schema.
- R3.3 kernel parity test `typed_firewall_matches_legacy_kernel_rulesets` сравнил реальные kernel rulesets в отдельных network namespaces для bootstrap, name-based multi-uplink, NAT none/masquerade/SNAT, INPUT/OUTPUT и numeric-ifindex.
- R3.4 ownership inspection использует `get_current_ruleset_raw`, проверяет exact family/name/table-level comment, поддерживает nftables 1.0.2 text fallback и fail-closed error mapping.
- `nftables::helper::apply_ruleset_raw(payload, Some("nft"), args)` принимает raw JSON и добавляет собственные `-j -f -` параметры. Вызов без дополнительных аргументов сохраняет JSON mode и передаёт весь payload одним nft batch.

## Выбранный дизайн

1. `SystemNftApplier::apply` продолжает сначала вызывать `inspect_nft_table`. Чужая/непроверяемая таблица блокирует изменение; отсутствие таблицы не требует delete.
2. Построить `RoutingPlan::firewall_ruleset()`; любая ошибка модели преобразуется в диагностический `LinuxError` и прекращает операцию до вызова nft.
3. Получить JSON через `to_json_value()`. Если ownership inspection вернул `true`, вставить `{"delete":{"table":{"family":...,"name":...}}}` первым объектом массива `nftables`. Затем добавить все typed objects в исходном детерминированном порядке.
4. Отправить полный JSON ровно одним вызовом `nftables::helper::apply_ruleset_raw`. Не делать отдельный delete и add: одна JSON batch транзакция сохраняет атомарную замену таблицы.
5. Повторно использовать `map_nftables_error` для сохранения текущего `LinuxError` контракта. Stdout helper не считать подтверждением частичного успеха; helper возвращает только после завершения nft.
6. `remove` оставить ownership-gated: только после успешного `inspect_nft_table == true` удалить таблицу через crate raw helper либо совместимый узкий command adapter. Выбрать тот же JSON batch API, если он покрывает delete; не ослаблять текстовый fallback для Ubuntu 22.04.
7. Сохранить публичные `apply_nft/remove_nft`, trait `NftApplier`, injection point Runtime и порядок startup/bootstrap/reload/rollback/shutdown/Drop.
8. Перевести test shims в `scripts/vpn-relay-netns-test.sh` на фактическую командную форму crate helper: JSON flag, `-f -`, stdin payload. Не допускать, чтобы shim принимал старый текстовый batch и тем самым маскировал production regression.
9. После полного CI и review удалить `RoutingPlan::nft_script()`, `src/routing/nft_text.rs`, string-based tests и все неиспользуемые imports. Не удалять legacy generator до прохождения всех gates.

## Инварианты безопасности и поведения

- Ownership проверяется до любого изменения; exact family/name/table comment обязательны.
- Для nftables 1.0.2 сохраняется text fallback, включая top-level-only comment matching.
- Owned-table replacement — один атомарный JSON batch: delete первым, затем create table, sets, chains, rules.
- Missing table — только create batch; чужая таблица никогда не удаляется.
- Helper spawn/command/UTF-8/JSON ошибки fail closed и сохраняют диагностику.
- Numeric ifindex map остаётся полным, one-to-one, ненулевым; обе стороны identity guards остаются до policy rules.
- Порядок objects/rules, conntrack mark masks/IDs, NAT pairing, priorities, hooks, IPv4-only policy, bootstrap drop-only semantics и INPUT/OUTPUT deny-by-default неизменны.
- Reload failure не оставляет пустую/частично созданную таблицу: nft transaction должна отклониться целиком и сохранить прежний ruleset.
- Remove и rollback по-прежнему выполняются тем же injected applier.
- Не менять config schema, control API, wire format или публичные сигнатуры.

## Вне объёма

- Обновление версии nftables crate.
- Переписывание ownership inspection на typed deserialization.
- Изменение firewall policy или routing behavior.
- Изменение Runtime orchestration или Linux routing transaction.
- Удаление compatibility adapter для table comment / iface_index без отдельного upstream support audit.

## Критерии приёмки

- Unit tests доказывают JSON payload shape/order и точный состав batch при missing/owned/foreign table.
- Unit tests доказывают, что inspection/model/helper failure не вызывает apply; helper failure возвращается через ожидаемый LinuxError mapping.
- Owned replacement содержит один delete + полный add в одном payload; missing-table batch не содержит delete.
- Remove использует ownership guard и crate JSON API; отсутствующая таблица — no-op.
- Netns parity test запускается на production applier и подтверждает нормализованное равенство с зафиксированным legacy baseline до его удаления.
- Namespace lifecycle test подтверждает reload, rollback, cleanup, foreign-table preservation и Ubuntu 22.04 text fallback.
- Все test shims проверяют новую JSON CLI форму.
- После удаления legacy generator нет ссылок на `nft_script`, `nft_text.rs` и legacy shell assertions.
- Полный CI 9/9 успешен на implementation HEAD и отдельном docs HEAD.

## План исполнения

### Задача 1 — JSON batch builder и тестируемый crate apply seam

- [ ] Добавить функцию построения JSON batch из `FirewallRuleset`, с optional delete object первым.
- [ ] Добавить unit tests для stable object order, owned/missing table payload, comment и iface_index compatibility fields.
- [ ] Добавить injectable apply closure вокруг `apply_ruleset_raw`; тестировать один вызов на весь payload.
- [ ] Проверить model errors и helper errors: ни один из них не должен приводить к запуску/повторному применению.
- [ ] CI quality + полный 9-job gate.

### Задача 2 — production SystemNftApplier switch

- [ ] Переключить `apply` на ownership inspection → typed model → один JSON batch.
- [ ] Переключить `remove` на ownership-gated JSON delete batch через crate helper.
- [ ] Сохранить `NftApplier` injection и публичные wrappers.
- [ ] Добавить/обновить failure-injection tests на apply/remove helper boundaries и error mapping.
- [ ] CI quality + полный 9-job gate.

### Задача 3 — kernel parity и namespace lifecycle на production path

- [ ] Переподключить parity test так, чтобы typed ruleset применялся тем же production JSON helper path, а не отдельным самописным способом.
- [ ] Проверить bootstrap, name-based, numeric-ifindex, multi-uplink, NAT none/masquerade/SNAT, INPUT/OUTPUT.
- [ ] Проверить owned reload, missing-table startup, foreign-table rejection, failed atomic replacement, rollback и cleanup.
- [ ] Обновить shell shims и обе kernel compatibility версии.
- [ ] Полный CI 9/9; при несовпадении не удалять legacy generator.

### Задача 4 — удаление legacy backend

- [ ] Только после успешного production parity удалить `nft_script()`, `src/routing/nft_text.rs`, string-only unit tests и ссылки.
- [ ] Проверить, что все kernel parity и lifecycle tests используют только production JSON applier.
- [ ] Полный CI 9/9 на implementation HEAD.

### Задача 5 — документация и закрытие R3

- [ ] Обновить ROADMAP, DEVELOPMENT_LOG, AGENTS, VPN_RELAY_NFTABLES, README/CHANGELOG по фактическому результату.
- [ ] Отразить crate version, raw compatibility fields, atomic JSON batch, ownership fallback и удаление legacy generator.
- [ ] Полный CI 9/9 на documentation HEAD.
- [ ] Закрыть R3 только после успешных implementation и documentation gates.

## Ограничение рабочего процесса

Локальное окружение отсутствует; изменения выполняются через GitHub API, проверки — GitHub Actions. Не изменять ветку, пока все 9 jobs текущего HEAD не завершились. При любом CI failure сначала получить job logs, исправить первопричину отдельным коммитом и снова дождаться полного CI.