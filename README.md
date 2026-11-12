# vpn-relay

**vpn-relay** — Linux daemon для маршрутизации IPv4-трафика между несколькими WireGuard и AmneziaWG туннелями на базе форка [BoringTun](https://github.com/lelikulibina/boringtun-awg).

Проект вынесен в отдельный репозиторий. Реализация протокола WireGuard/AmneziaWG остаётся в `boringtun-awg`; этот репозиторий отвечает за управление туннелями, маршрутизацию, firewall и NAT.

## Возможности

- Создание WG/AWG TUN-интерфейсов через типизированный API BoringTun (без UAPI-сокетов для управляемых daemon устройств).
- IPv4 policy routing с приоритетами, source/destination CIDR selectors и multi-uplink.
- nftables INPUT/OUTPUT/FORWARD isolation с fail-closed поведением и защитой от подмены managed-интерфейсов.
- NAT: без трансляции, masquerade и статический SNAT.
- Conntrack decision tracking, socket fwmarks для внешнего UDP-трафика WG/AWG.
- Runtime reload firewall, routing, NAT и peer configuration.
- Peer lifecycle, AllowedIPs ownership/handoff, durable forwarding journal и recovery.
- IPv4 per-interface forwarding через rtnetlink с проверками identity интерфейса.
- Rootful Podman deployment в отдельном network namespace.

## Поддержка IP и требования

**Только IPv4.** `vpn-relay` не настраивает IPv6 transport, адреса, маршруты, NAT, forwarding или sysctl. IPv6-пакеты блокируются на управляемых TUN через nftables. Это не означает отключение IPv6 на всём хосте.

Требуется Linux, root или эквивалентные `CAP_NET_ADMIN`, `/dev/net/tun`, `nftables` и `iproute2`. Windows, rootless Podman и host-network deployment не поддерживаются.

## Сборка

```sh
cargo build --release
```

Проверка примера конфигурации:

```sh
sudo install -d -m 0750 /etc/vpn-relay
sudo install -m 0600 vpn-relay.example.toml /etc/vpn-relay/config.toml
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml --check
```

Замените примерные ключи и endpoint перед запуском:

```sh
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml
```

Импорт существующего WireGuard/AmneziaWG профиля:

```sh
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml --import wg0.conf wg-primary
```

Подробное описание reload, routing, NAT, forwarding и firewall находится в [документации nftables](docs/VPN_RELAY_NFTABLES.md).

## Тестирование

Unit-тесты:

```sh
cargo test
```

Интеграционные проверки требуют Linux, root, network namespaces, TUN, nftables и iproute2:

```sh
sudo bash scripts/vpn-relay-netns-test.sh
sudo bash scripts/vpn-relay-per-interface-forwarding-test.sh
sudo bash scripts/vpn-relay-per-interface-forwarding-packet-test.sh
sudo bash scripts/vpn-relay-peer-traffic-test.sh wg
sudo bash scripts/vpn-relay-peer-traffic-test.sh awg
sudo bash scripts/vpn-relay-multi-uplink-test.sh
```

Для контейнерного smoke test используется rootful Podman:

```sh
cargo build
sudo podman build -f scripts/vpn-relay-podman.Containerfile -t vpn-relay-podman-test .
```

## Зависимость BoringTun

`boringtun` подключается напрямую из [lelikulibina/boringtun-awg](https://github.com/lelikulibina/boringtun-awg) по зафиксированному Git commit. Это важно: проект использует AWG-расширения и typed device API форка, которых может не быть в опубликованной версии crates.io.

## Лицензия

BSD 3-Clause. См. [LICENSE.md](LICENSE.md).
