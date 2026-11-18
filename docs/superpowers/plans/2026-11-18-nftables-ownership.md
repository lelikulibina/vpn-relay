# R3.4 nftables ownership inspection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перевести JSON ownership inspection на `nftables 0.6.3` helper API без изменения строгих правил владения nftables-таблицей.

**Architecture:** JSON snapshot читается через `nftables::helper::get_current_ruleset_raw`, поскольку typed `schema::Table` не сохраняет table-level comment. Существующий JSON parser остаётся источником проверки exact family/name/comment, а текстовый fallback сохраняет совместимость с nftables 1.0.2. Ошибки helper API преобразуются в существующий `LinuxError` контракт.

**Tech Stack:** Rust 2021, `nftables = 0.6.3`, `serde_json`, GitHub Actions network namespaces.

**Spec:** `docs/superpowers/specs/2026-11-18-nftables-ownership-design.md`

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

- [ ] **Step 1: Write failing tests** named `nftables_helper_errors_preserve_spawn_and_command_details` and `nftables_not_found_detection_is_narrow`. Assert spawn maps to `LinuxError::Spawn`, command errors preserve stderr, and only `No such file or directory` / `does not exist` are treated as missing.
- [ ] **Step 2: Run the targeted Linux unit tests** through the GitHub Actions quality job and verify they fail for missing mapping/predicate.
- [ ] **Step 3: Implement the raw helper wrapper and error mapping** in `src/linux/nft.rs`. Map UTF-8/JSON helper errors to a diagnostic `LinuxError::Command`; preserve program and stderr details where available.
- [ ] **Step 4: Run targeted tests and all quality checks**; confirm all mapping tests pass.
- [ ] **Step 5: Commit** the helper integration.

### Task 2: Fail-closed ownership inspection and compatibility fallback

**Files:**
- Modify: `src/linux/nft.rs`
- Test: `src/linux/tests.rs`

**Interfaces:**
- Keep `inspect_nft_table(plan: &RoutingPlan) -> Result<bool, LinuxError>` as the production entry point.
- Add an injectable internal `inspect_nft_table_with` accepting JSON and text readers, so ownership decisions are tested without executing nft.
- JSON reader returns `Result<String, NftablesError>`; text reader returns `Result<String, LinuxError>`.

- [ ] **Step 1: Write failing tests** named `inspect_nft_table_accepts_only_exact_json_ownership`, `inspect_nft_table_uses_text_fallback_for_missing_json_comment`, `inspect_nft_table_rejects_nested_or_foreign_markers`, and `inspect_nft_table_returns_false_only_for_missing_table`.
- [ ] **Step 2: Run targeted tests** and verify the new inspection cases fail before implementation.
- [ ] **Step 3: Refactor `inspect_nft_table`** to use the crate raw helper, preserve `table_is_owned` and `table_is_owned_text`, and invoke text fallback when JSON does not prove ownership. Propagate all non-not-found JSON and text errors.
- [ ] **Step 4: Run targeted tests** and verify exact JSON/text ownership behavior, including foreign table rejection.
- [ ] **Step 5: Commit** the fail-closed inspection refactor.

### Task 3: Kernel ownership regression coverage and documentation

**Files:**
- Modify: `scripts/vpn-relay-netns-test.sh` only if an uncovered kernel-level ownership case is found.
- Modify: `docs/ROADMAP.md`, `docs/DEVELOPMENT_LOG.md`, `docs/VPN_RELAY_NFTABLES.md`, `AGENTS.md`.

- [ ] **Step 1: Review existing namespace coverage** for foreign same-name table rejection, owned-table reload/cleanup and text fallback on Ubuntu 22.04. Add a nested-comment foreign-table case only if existing coverage does not prove it.
- [ ] **Step 2: Run the full 9-job CI** on Ubuntu 22.04 and 24.04; require namespace lifecycle, protocol, multi-uplink and Podman jobs to pass.
- [ ] **Step 3: Document R3.4 completion** with exact commit and successful CI run. State explicitly that production still uses the legacy generator until R3.5.
- [ ] **Step 4: Commit documentation** and wait for a second full 9-job CI on the documentation HEAD.

## Completion Gate

R3.4 is complete only when the helper-backed inspection preserves all ownership invariants and the full 9/9 CI passes on the implementation HEAD and documentation HEAD. R3.5 production switch is a separate plan and must not be started as part of this one.
