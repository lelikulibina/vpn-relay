# R3.4 nftables ownership inspection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перевести JSON ownership inspection на `nftables 0.6.3` helper API без изменения строгих правил владения nftables-таблицей.

**Architecture:** JSON snapshot читается через `nftables::helper::get_current_ruleset_raw`, поскольку typed `schema::Table` не сохраняет table-level comment. Существующий JSON parser остаётся источником проверки exact family/name/comment, а текстовый fallback сохраняет совместимость с nftables 1.0.2. Ошибки helper API преобразуются в существующий `LinuxError` контракт.

**Tech Stack:** Rust 2021, `nftables = 0.6.3`, `serde_json`, GitHub Actions network namespaces.

**Spec:** `docs/superpowers/specs/2026-11-18-nftables-ownership-design.md`

## Execution Notes

- Ruling: локального рабочего окружения нет; выполнение и проверки проводятся через GitHub API и GitHub Actions. Коммиты и обновлённые чекбоксы плана служат журналом выполнения вместо локального worktree ledger.
- Ruling: R3.4 — семантически сохраняющий рефакторинг ownership inspection. Существующие characterization tests должны проходить на baseline; новые assertions добавляются до переключения helper path. Не создавать искусственные failing stubs только ради RED-прогона.

## Global Constraints

- Ownership marker остаётся точной строкой `managed by vpn-relay`.
- Принимать таблицу можно только при точном совпадении family, name и table-level comment.
- Отсутствующая таблица возвращает `Ok(false)`; прочие ошибки не должны маскироваться под отсутствие.
- Текстовый fallback для nftables 1.0.2 (Ubuntu 22.04) сохраняется.
- Не менять публичный API, `NftApplier` contract, apply/remove transaction order или production script backend.
- Чужая таблица никогда не заменяется и не удаляется.

## Review Focus

- Таблица отсутствует: только ожидаемые nft not-found сообщения дают `Ok(false)`.
- Таблица с тем же именем, но другой family или чужим comment: ownership отклоняется.
- Маркер только внутри chain/rule: ownership отклоняется.
- JSON не содержит comment (Ubuntu 22.04): текстовый fallback принимает только top-level table comment.
- Spawn/UTF-8/прочие nft errors: диагностика сохраняется, операция fail-closed.

---

### Task 1: Crate helper integration and error mapping

**Files:**
- Modify: `src/linux/nft.rs`
- Test: `src/linux/tests.rs`

**Interfaces:**
- Add `get_current_ruleset_json(plan: &RoutingPlan) -> Result<String, nftables::helper::NftablesError>`, using `get_current_ruleset_raw(Some("nft"), ["list", "table", family, name])`.
- Add `map_nftables_error(error: NftablesError) -> LinuxError`.
- Add a predicate for the two existing not-found stderr forms; do not classify other failures as missing tables.

- [x] **Step 1: Add characterization tests** named `nftables_helper_errors_preserve_spawn_and_command_details` and `nftables_not_found_detection_is_narrow`. Assert spawn maps to `LinuxError::Spawn`, command errors preserve stderr, and only `No such file or directory` / `does not exist` are treated as missing.
- [x] **Step 2: Run the targeted Linux unit tests** through the GitHub Actions quality job and verify they fail for missing mapping/predicate.
- [x] **Step 3: Implement the raw helper wrapper and error mapping** in `src/linux/nft.rs`. Map UTF-8/JSON helper errors to a diagnostic `LinuxError::Command`; preserve program and stderr details where available.
- [x] **Step 4: Run targeted tests and all quality checks**; confirm all mapping tests pass.
- [x] **Step 5: Commit** the helper integration.

### Task 2: Fail-closed ownership inspection and compatibility fallback

**Files:**
- Modify: `src/linux/nft.rs`
- Test: `src/linux/tests.rs`

**Interfaces:**
- Keep `inspect_nft_table(plan: &RoutingPlan) -> Result<bool, LinuxError>` as the production entry point.
- Add an injectable internal `inspect_nft_table_with` accepting JSON and text readers, so ownership decisions are tested without executing nft.
- JSON reader returns `Result<String, NftablesError>`; text reader returns `Result<String, LinuxError>`.

- [x] **Step 1: Add characterization tests** named `inspect_nft_table_accepts_only_exact_json_ownership`, `inspect_nft_table_uses_text_fallback_for_missing_json_comment`, `inspect_nft_table_rejects_nested_or_foreign_markers`, and `inspect_nft_table_returns_false_only_for_missing_table`.
- [x] **Step 2: Run targeted tests** and verify the new inspection cases fail before implementation.
- [x] **Step 3: Refactor `inspect_nft_table`** to use the crate raw helper, preserve `table_is_owned` and `table_is_owned_text`, and invoke text fallback when JSON does not prove ownership. Propagate all non-not-found JSON and text errors.
- [x] **Step 4: Run targeted tests** and verify exact JSON/text ownership behavior, including foreign table rejection.
- [x] **Step 5: Commit** the fail-closed inspection refactor.

### Task 3: Kernel ownership regression coverage and documentation

**Files:**
- Modify: `scripts/vpn-relay-netns-test.sh` only if an uncovered kernel-level ownership case is found.
- Modify: `docs/ROADMAP.md`, `docs/DEVELOPMENT_LOG.md`, `docs/VPN_RELAY_NFTABLES.md`, `AGENTS.md`.

- [x] **Step 1: Review existing namespace coverage** for foreign same-name table rejection, owned-table reload/cleanup and text fallback on Ubuntu 22.04. Add a nested-comment foreign-table case only if existing coverage does not prove it.
- [x] **Step 2: Run the full 9-job CI** on Ubuntu 22.04 and 24.04; require namespace lifecycle, protocol, multi-uplink and Podman jobs to pass.
- [x] **Step 3: Document R3.4 completion** with exact commit and successful CI run. State explicitly that production still uses the legacy generator until R3.5.
- [ ] **Step 4: Commit documentation** and wait for a second full 9-job CI on the documentation HEAD.

## Execution result

- Implementation commit: `4f84688d01c4172a64e706abf7226b5d90b17b8d`.
- Implementation CI: run `44397837114`, success 9/9.
- Namespace regression covers a same-name foreign table with the ownership marker nested in a chain; startup rejects it, preserves the foreign table and rolls back routing/TUN resources.
- Documentation closure is committed separately; its own full 9/9 CI remains the final completion gate.

## Completion Gate

R3.4 is complete only when the helper-backed inspection preserves all ownership invariants and the full 9/9 CI passes on both implementation and documentation HEADs. R3.5 production switch is a separate plan and must not be started as part of this one.
