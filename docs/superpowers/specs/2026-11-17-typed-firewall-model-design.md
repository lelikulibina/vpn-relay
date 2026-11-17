# Дизайн R3.2: типизированная модель nftables firewall

## Цель

Заменить внутреннюю строковую композицию nftables policy на детерминированную типизированную модель, построенную из `RoutingPlan`, и подготовить безопасный адаптер к `nftables` crate v0.6.3. Этот этап не переключает production backend: `RoutingPlan::nft_script()` и текущий `SystemNftApplier` остаются эталонной реализацией до отдельного parity этапа.

## Текущее состояние

`src/routing/nft_text.rs` генерирует весь ruleset строками. В нём создаются table, sets, base chains, IPv6 drops, INPUT/OUTPUT allow/deny, conntrack decision classification, FORWARD allow/deny, NAT и дополнительные identity guards. При наличии `interface_indices` в конце выполняются массовые строковые замены `String::replace`, которые переводят name selectors в numeric selectors.

`RoutingPlan` уже содержит все необходимые domain inputs: managed interfaces, IPv6 drop interfaces, routing decisions, INPUT/OUTPUT rules и optional name→ifindex mapping. Runtime проверяет identity исходных TUN descriptors до привязки indices; этот порядок и его fail-closed guards должны остаться неизменными.

Аудит `nftables` v0.6.3 показал, что crate типизирует нужные объекты, expressions и statements, но не моделирует set type `iface_index` и table-level `comment`. Для этих двух полей нужен ограниченный raw JSON adapter. Ownership inspection не переводится на десериализацию полного ruleset в typed schema.

## Подходы

1. **Прямое построение crate schema из RoutingPlan.** Минимум промежуточных типов, но domain policy, детали crate и специальные raw JSON исключения окажутся смешаны в одном builder.
2. **Отдельный typed firewall AST и adapter к crate — выбранный подход.** RoutingPlan преобразуется в собственную модель `Table/Set/Chain/Rule/Match/Action`; отдельный adapter переводит её в `nftables` schema. Только `iface_index` и table comment добавляются узким raw JSON compatibility слоем. Это отделяет семантику firewall от представления конкретного crate.
3. **Разбор существующего nft script в AST.** Отклонён: сохраняет строковую генерацию как источник истины и добавляет второй хрупкий parser, вместо устранения stringly-typed слоя.

## Архитектура

- Новый `src/routing/firewall.rs` содержит типы модели, построение из `RoutingPlan` и адаптер сериализации.
- `RoutingPlan::firewall_ruleset()` строит полный ruleset; `fail_closed_bootstrap()` должен давать ту же drop-only семантику, что и текущий `nft_script()`.
- Списки chain rules и expressions остаются `Vec`: порядок правил является частью firewall semantics и не должен зависеть от hash iteration.
- Interface selectors представлены явно: имя либо numeric ifindex. Подстановка индексов происходит при построении model nodes, а не после сериализации/рендеринга.
- `RoutingPlan::firewall_ruleset()` возвращает `Result` и отклоняет неполный, нулевой или дублирующийся ifindex map; отсутствие map означает штатный name-based режим. Это исключает тихое удаление элементов set при неполной привязке.
- Identity guards представляются обычными typed rules и сохраняют обе проверки: configured name→expected index и expected index→configured name.
- Crate adapter строит `nftables::schema::Nftables` / `NfObject` / `Rule` и использует crate expressions/statements. Raw JSON adapter добавляет только table-level ownership comment и `iface_index` set datatype, отсутствующие в crate schema.
- Старый string generator остаётся доступным и не меняется в этом этапе. Production apply/remove, ownership inspection, atomic batch, startup/reload/shutdown и runtime behavior не переключаются.

## Инварианты

- Не менять семейство `inet`, table name, table-level ownership marker и порядок объектов/rules.
- Сохранять bootstrap drop-only policy до создания и проверки TUN descriptors.
- Сохранять name-based selectors до успешной проверки descriptor identity и привязки ifindex.
- При numeric selectors сохранить все двунаправленные identity mismatch guards и их порядок до allow/drop rules.
- Сохранять INPUT/OUTPUT explicit allow + deny-by-default, conntrack host-flow tag и invalid-state drops.
- Сохранять routing decision marks, original/reply direction, ingress/egress pairing, NAT scope и порядок классификации.
- Сохранять IPv6 drop guards и IPv4-only contract.
- Не ослаблять nft table ownership checks и fail-closed cleanup.
- Не менять public API, JSON/control protocol, config schema или production nft backend.

## Вне объёма

- Переключение production на crate.
- Удаление `nft_text.rs`.
- Изменение правил, NAT semantics, priorities, marks или hook ordering.
- Переписывание ownership inspection через crate typed deserialization.
- Изменение runtime lifecycle или Linux apply/remove transaction.

## Критерии приёмки

- Typed model покрывает все объекты и правила, которые сейчас выдаёт `RoutingPlan::nft_script()`, включая bootstrap и numeric-ifindex variants.
- Сериализация строится из crate typed schema; raw JSON compatibility слой ограничен двумя подтверждёнными пробелами.
- Unit tests проверяют structure и порядок rules, а не только текстовые фрагменты.
- Все существующие routing/nft tests остаются неизменными и проходят.
- Production продолжает использовать старый script backend; parity и переключение остаются отдельными этапами R3.3+.
