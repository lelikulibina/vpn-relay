# R3.2 Типизированная модель nftables — план реализации

> **Для исполнителей:** используйте `superpowers:executing-plans` и выполняйте задачи по одной. Каждый шаг начинается с теста RED и заканчивается проверкой GREEN.

**Цель:** построить из `RoutingPlan` детерминированную typed firewall model и сериализовать её через `nftables` v0.6.3, не переключая production backend.

**Архитектура:** `src/routing/firewall.rs` содержит независимый AST объектов, selectors, expressions и actions. Adapter преобразует AST в schema crate; узкий raw JSON слой дополняет table comment и `iface_index`.

**Стек:** Rust 2021, `nftables = 0.6.3`, существующие `serde`/`serde_json`; production script generator остаётся эталоном.

**Спецификация:** `docs/superpowers/specs/2026-11-17-typed-firewall-model-design.md`.

## Глобальные ограничения

- Не менять публичный API, wire format, config schema и поведение datapath.
- Сохранять атомарный nft batch и ownership checks.
- Сохранять fail-closed startup/reload/shutdown и исходный порядок runtime lifecycle.
- Не использовать массовые строковые замены для name→ifindex conversion.
- Не переключать production backend до parity tests R3.3.
- Сохранять IPv4-only contract, conntrack marks, NAT scope и INPUT/OUTPUT deny-by-default.
- Не ослаблять identity guards и table ownership marker.

## Review Focus

1. Bootstrap без allow rules должен оставаться drop-only, включая IPv6 guards.
2. Numeric ifindex mode должен сохранять обе стороны identity mismatch guards и размещать их до policy rules.
3. Пустые selectors и multiple CIDRs должны давать ту же IPv4 match semantics, что и legacy generator.
4. Перекрывающиеся routing decisions должны сохранять отдельный conntrack decision ID и exact NAT pairing.
5. Пустой набор managed interfaces и отсутствующий/неполный index map не должны приводить к молчаливому ослаблению firewall.

---

### Задача 1. Модель объектов, sets и chains

**Файлы:**
- Создать: `src/routing/firewall.rs`
- Изменить: `src/routing.rs`
- Тесты: `src/routing/tests.rs`

**Интерфейсы:**
- Создать `pub(crate) struct FirewallRuleset`, `FirewallSet`, `FirewallChain`.
- Создать `pub(crate) enum InterfaceSelector { Name(String), Index(u32) }`.
- Добавить `pub(crate) enum FirewallModelError` и `RoutingPlan::firewall_ruleset(&self) -> Result<FirewallRuleset, FirewallModelError>`.
- В numeric mode валидировать полный one-to-one map: все managed interfaces присутствуют, индексы ненулевые и уникальные; `None` означает штатный name-based mode.
- Сохранять ordered `Vec` для объектов и chain rules.

- [ ] RED: добавить `firewall_model_preserves_table_chain_and_set_identity`; проверить family/table/comment, порядок пяти base chains, managed interface set и IPv6 selector set в name/index modes.
- [ ] RED: добавить `firewall_model_rejects_incomplete_interface_index_map`; проверить, что missing/zero/duplicate ifindex возвращает ошибку, а не молча исключает интерфейс из set.
- [ ] Проверить ожидаемое отсутствие `firewall_ruleset`/модели до реализации.
- [ ] GREEN: реализовать объекты, sets и base chains, включая корректный fail-closed bootstrap variant.
- [ ] Запустить `cargo fmt --all --check`, `cargo check --locked --all-targets`, `cargo test --locked --all-targets`.
- [ ] Commit: `feat(routing): add typed firewall object model`.

### Задача 2. Typed rules, matches и actions

**Файлы:**
- Изменить: `src/routing/firewall.rs`
- Тесты: `src/routing/tests.rs`

**Интерфейсы:**
- Добавить typed `FirewallRule`, `FirewallMatch`, `FirewallExpression`, `FirewallAction`.
- Представить meta/ct/payload expressions, comparisons, bitwise AND/OR, mangle, counter, verdict, masquerade и SNAT без nft syntax strings.
- Добавить построение prerouting, IPv6 guards, INPUT/OUTPUT, FORWARD и POSTROUTING rules в том же порядке, что legacy generator.

- [ ] RED: добавить тесты `firewall_model_preserves_managed_host_policy_order`, `firewall_model_preserves_conntrack_decision_and_nat_pairing` и `firewall_model_preserves_numeric_identity_guards`.
- [ ] Проверить RED по отсутствующим typed rules/expressions и assertions на порядок.
- [ ] GREEN: построить все typed rules из `RoutingPlan`, включая пустые/multiple CIDR, protocol/ports, bootstrap и numeric-ifindex cases.
- [ ] Запустить полный Rust quality набор и проверить существующие nft script assertions без изменений.
- [ ] Commit: `feat(routing): model nft firewall rules and actions`.

### Задача 3. Adapter к nftables crate и raw compatibility fields

**Файлы:**
- Изменить: `Cargo.toml`, `Cargo.lock`, `src/routing/firewall.rs`
- Тесты: `src/routing/tests.rs`

**Интерфейсы:**
- Зафиксировать `nftables = 0.6.3`.
- Добавить `FirewallRuleset::to_nftables()` для преобразования в crate schema.
- Добавить `FirewallRuleset::to_json_value()` (или эквивалентный serializer), который получает JSON из typed schema и добавляет только table-level `comment` и `iface_index` compatibility fields.
- Не менять `SystemNftApplier` и `Runtime`.

- [ ] RED: добавить `firewall_model_serializes_typed_nftables_schema` и `firewall_model_preserves_raw_compatibility_fields`; assertions проверяют command/object ordering, expression shape, ownership comment и ifindex datatype.
- [ ] Убедиться, что тесты падают до adapter implementation.
- [ ] GREEN: реализовать schema conversion и минимальный raw JSON adapter только для двух неподдерживаемых полей.
- [ ] Обновить lockfile и запустить `cargo fmt --all --check`, `cargo check --locked --all-targets`, `cargo clippy --locked --all-targets`, `cargo test --locked --all-targets`.
- [ ] Commit: `feat(routing): serialize firewall model with nftables schema`.

### Задача 4. Документация и граница production backend

**Файлы:**
- Изменить: `docs/ROADMAP.md`, `docs/DEVELOPMENT_LOG.md`, `AGENTS.md`, `docs/VPN_RELAY_NFTABLES.md`
- Тесты: существующие tests остаются без удаления/переименования.

- [ ] Обновить документацию: зафиксировать typed model, adapter и два raw compatibility исключения; явно сохранить script backend как production source of truth до parity/production switch.
- [ ] Запустить полный CI (9 jobs) и проверить актуальный HEAD.
- [ ] Commit: `docs(nftables): document typed firewall model`.

## Проверка перед следующим этапом

R3.2 считается завершённым только после успешного полного CI на HEAD последнего commit. R3.3 должен сравнить нормализованные rulesets в отдельных netns для bootstrap, numeric-ifindex, multi-uplink, NAT none/masquerade/SNAT и INPUT/OUTPUT. До этого production продолжает применять `RoutingPlan::nft_script()`.
