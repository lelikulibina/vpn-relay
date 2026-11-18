# R3.4 Ownership inspection — design

## Intent

Перевести JSON-чтение существующей nftables-таблицы в `nftables = 0.6.3` helper API, сохранив без ослабления текущую гарантию: vpn-relay заменяет и удаляет только таблицу с точными `family`, `name` и table-level comment `managed by vpn-relay`.

Это отдельный ownership этап после завершённого R3.3 parity. Production всё ещё использует legacy script generator; R3.4 не переключает backend и не меняет правила.

## Current behavior

`src/linux/nft.rs::inspect_nft_table` напрямую запускает `nft -j list table <family> <name>`, разбирает JSON через `serde_json::Value` и принимает таблицу только при совпадении family/name и table-level comment. Если JSON не подтверждает ownership, выполняется текстовый `nft list table` fallback. Fallback принимает только точный table header и comment на уровне таблицы; вложенный chain/rule comment не подходит. Отсутствующая таблица трактуется как `Ok(false)`; прочие ошибки команды передаются вызывающему коду.

## Approaches

1. **Использовать только `helper::get_current_ruleset()` (typed schema). Не подходит:** `nftables 0.6.3` schema `Table` не содержит table-level `comment`; typed deserialization не может подтвердить основной ownership marker.
2. **Вызвать typed и raw helper последовательно. Не рекомендуется:** дублирует запуск `nft`, создаёт лишнее окно между двумя snapshots и не добавляет доказательств сверх raw JSON.
3. **Использовать `helper::get_current_ruleset_raw` для JSON и сохранить строгий JSON/text ownership parser. Выбранный вариант:** crate helper выполняет `nft -j list table` и возвращает исходный JSON со всеми полями. Это один JSON запрос, сохраняет table comment и позволяет оставить текстовый fallback для старых nftables.
4. **Оставить прямой `Command` без crate helper. Не подходит для R3.4:** сохраняет поведение, но не переводит ownership inspection на выбранный crate API.

## Design

- Получать JSON через `nftables::helper::get_current_ruleset_raw(Some("nft"), ["list", "table", family, name])`. Helper сам добавляет `-j`.
- Не использовать typed `get_current_ruleset()` как источник ownership: схема `Table` не содержит comment.
- Сохранять точную проверку JSON table object: family, name и comment должны совпадать.
- Если JSON не подтверждает ownership, сохранить текстовый fallback. Он должен принимать только точный заголовок таблицы и точный table-level comment; nested comment остаётся недостаточным.
- Только известные ошибки отсутствующей таблицы (`No such file or directory` / `does not exist`) дают `Ok(false)`. Spawn, invalid UTF-8 и остальные ошибки nft должны стать `LinuxError` с диагностикой и не трактоваться как отсутствие таблицы.
- Текстовый fallback остаётся прямым вызовом `nft list table`: helper raw API всегда формирует JSON invocation.
- Не менять ownership marker, атомарный apply batch, cleanup ordering, публичные функции, `NftApplier` contract или production backend.

## Compatibility and safety

- Ubuntu 22.04 / nftables 1.0.2: JSON может не содержать table comment; точный текстовый fallback обязателен.
- Ubuntu 24.04: JSON ownership marker проверяется напрямую; fallback остаётся защитой для версий с отсутствующим полем.
- Отсутствующая таблица разрешает создание новой.
- Существующая чужая таблица с тем же именем, другой family или отсутствующим/вложенным comment должна приводить к conflict; её нельзя удалять или заменять.
- Ошибка чтения ownership не должна трактоваться как разрешение на изменение ресурса.

## Acceptance

- Unit tests покрывают точную JSON identity, table-level-only text marker, missing table, foreign table, nested marker и все варианты error mapping.
- Namespace integration проверяет отказ при foreign table и сохранение её содержимого, а также обычный lifecycle уже owned таблицы.
- Полный GitHub Actions CI проходит 9/9 на актуальном HEAD, включая Ubuntu 22.04 и 24.04 kernel compatibility.
- Production продолжает использовать legacy `RoutingPlan::nft_script()`; переключение относится только к R3.5.
