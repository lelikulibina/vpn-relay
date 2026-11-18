# R3.5 Production switch — план реализации

> Выполнять по задачам; перед изменениями прочитать R3.5 design. Каждый commit проходит полный CI 9/9 до следующего изменения ветки.

**Цель:** перевести production nftables apply/remove на JSON API `nftables 0.6.3`, используя существующую typed AST и сохранив ownership/lifecycle/atomicity.

**Спецификация:** `docs/superpowers/specs/2026-11-19-nftables-production-switch-design.md`.

**Базовый HEAD:** `425f6d099066219717038d229adb33851afa7ba7`, docs CI run `44399369322`, success 9/9.

## Предварительные ограничения

- Не менять публичные `apply_nft/remove_nft`, `NftApplier`, Runtime API, config или control wire format.
- До отдельного commit на удаление legacy generator он остаётся доступным как parity oracle.
- Никаких двухшаговых delete/add команд: replacement должен быть одним JSON batch.
- Ownership inspection и Ubuntu 22.04 fallback остаются неизменными.
- Один коммит — один полный 9/9 CI gate. Не коммитить на незавершённом CI.

## Task 1 — JSON batch builder + injectable helper boundary

- [x] Прочитать helper API v0.6.3 и проверить фактическую командную форму `apply_ruleset_raw`.
- [ ] Добавить JSON batch builder: optional delete object, затем typed model objects.
- [ ] Проверить deterministic object order и exact compatibility fields.
- [ ] Добавить injectable apply function, которая получает один payload и вызывает crate helper ровно один раз.
- [ ] Unit tests: missing table, owned table, helper/model failure, delete-first order, table comment, iface_index.
- [ ] Quality + full CI 9/9; исправить любые ошибки до Task 2.

## Task 2 — production apply/remove switch

- [ ] `SystemNftApplier::apply`: ownership inspection → `firewall_ruleset` → JSON payload → один `apply_ruleset_raw`.
- [ ] `SystemNftApplier::remove`: ownership inspection → crate raw JSON delete batch; absent table remains no-op.
- [ ] Map crate helper errors через существующий mapper.
- [ ] Preserve public wrappers and same applier lifecycle injection.
- [ ] Failure tests: no apply after failed ownership/model build; failed JSON transaction surfaces original diagnostics; foreign table never mutated; remove helper called only for owned table.
- [ ] Quality + full CI 9/9.

## Task 3 — production kernel parity and lifecycle

- [ ] Reuse production JSON apply path from root-only parity test.
- [ ] Keep legacy generator as expected-result oracle temporarily.
- [ ] Confirm bootstrap, name/index selectors, multi-uplink, NAT modes, INPUT/OUTPUT and identity guards in actual kernel rulesets.
- [ ] Confirm atomic owned replacement and previous ruleset retention on invalid batch.
- [ ] Confirm startup, reload, rollback, shutdown, Drop and foreign-table handling.
- [ ] Update shell test shims for `nft -j -f -` stdin contract (verify exact helper args first).
- [ ] Ubuntu 22.04/24.04 kernel jobs and full CI 9/9.

## Task 4 — remove legacy generator only after parity

- [ ] Delete `RoutingPlan::nft_script()`, `src/routing/nft_text.rs` and obsolete text-only tests.
- [ ] Remove legacy shim branches and references.
- [ ] Ensure all integration tests exercise production JSON path.
- [ ] Search repository for `nft_script`, `nft_text`, `nft -f -` assumptions; retain only justified compatibility references.
- [ ] Quality + full CI 9/9.

## Task 5 — documentation closure

- [ ] Update ROADMAP, DEVELOPMENT_LOG, AGENTS, VPN_RELAY_NFTABLES and user-facing docs as appropriate.
- [ ] Document actual production path, crate version, two schema compatibility fields, ownership fallback, JSON transaction atomicity and removed legacy generator.
- [ ] Commit documentation and wait for full CI 9/9.
- [ ] Close R3 only after implementation and documentation HEADs pass.

## Execution ledger

- [ ] Implementation commits and CI run IDs to be appended as work proceeds.
