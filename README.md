# vpn-relay

**vpn-relay** — Linux daemon для маршрутизации IPv4-трафика между несколькими WireGuard и AmneziaWG туннелями на базе форка [BoringTun](https://github.com/lelikulibina/boringtun-awg).

Репозиторий отвечает за управление TUN-интерфейсами, peer lifecycle, policy routing, nftables, NAT и forwarding. Реализация криптографического протокола находится в отдельном форке BoringTun.

## Возможности

- Создание WG/AWG TUN-интерфейсов через typed API BoringTun; UAPI-сокеты для управляемых daemon устройств не используются.
- IPv4 policy routing: приоритеты, source/destination CIDR selectors и несколько uplink.
- nftables INPUT/OUTPUT/FORWARD isolation с fail-closed поведением и привязкой правил к identity управляемых интерфейсов.
- NAT: без трансляции, masquerade и статический SNAT.
- Conntrack decision tracking и отдельные socket fwmarks для внешнего UDP-трафика WG/AWG.
- Runtime reload routing, firewall, NAT и peer configuration; отдельная операция замены peer set.
- Peer lifecycle, AllowedIPs ownership/handoff, durable forwarding journal и восстановление после SIGKILL.
- Управление IPv4 forwarding отдельных интерфейсов через rtnetlink с проверкой ifindex.
- Rootful Podman deployment в отдельном network namespace.

## Поддержка IP и требования

**Поддерживается только IPv4.** Проект не настраивает IPv6 transport, адреса, маршруты, NAT, forwarding или sysctl. IPv6-пакеты блокируются на управляемых TUN через nftables; это не отключает IPv6 на хосте и не является поддержкой IPv6-туннелей.

Требуется Linux, root или эквивалентные capabilities (в частности CAP_NET_ADMIN), /dev/net/tun, nftables и iproute2. Windows, rootless Podman и deployment с host network не поддерживаются.

## Сборка и запуск

~~~sh
cargo build --release
sudo install -d -m 0750 /etc/vpn-relay
sudo install -m 0600 vpn-relay.example.toml /etc/vpn-relay/config.toml
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml --check
~~~

Пример содержит демонстрационные ключи и адреса. Перед запуском замените их на собственные значения:

~~~sh
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml
~~~

Файл конфигурации содержит приватные ключи — храните его с ограниченными правами доступа.

## Управление работающим daemon

Команды управления обращаются к уже запущенному экземпляру в том же network namespace:

~~~sh
# Применить полный конфигурационный файл без перезапуска daemon
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml --reload

# Заменить peer set указанного интерфейса значениями из конфигурации
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml --replace-peers wg-server
~~~

Импорт существующего WireGuard/AmneziaWG профиля:

~~~sh
sudo target/release/vpn-relay --config /etc/vpn-relay/config.toml --import wg0.conf wg-primary
~~~

Для автоматической замены уже существующего интерфейса без интерактивного подтверждения добавьте --yes.

## Конфигурация и архитектура

Полный пример поддерживаемой конфигурации — [vpn-relay.example.toml](vpn-relay.example.toml). Отдельная копия в examples/ удалена, чтобы не поддерживать два расходящихся источника истины.

Подробное описание packet path, nftables hooks, policy routing, NAT, conntrack marks, IPv6 isolation, peer identity и lifecycle ресурсов находится в [документации nftables](docs/VPN_RELAY_NFTABLES.md).

## Проверки

Базовые проверки качества:

~~~sh
cargo fmt --all --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets
cargo test --locked --all-targets
~~~

Интеграционные сценарии требуют Linux, root, network namespaces, TUN, nftables и iproute2. Запускать из корня репозитория после cargo build:

~~~sh
sudo bash scripts/vpn-relay-netns-test.sh
sudo bash scripts/vpn-relay-per-interface-forwarding-test.sh
sudo bash scripts/vpn-relay-per-interface-forwarding-packet-test.sh
sudo bash scripts/vpn-relay-peer-traffic-test.sh wg
sudo bash scripts/vpn-relay-peer-traffic-test.sh awg
sudo bash scripts/vpn-relay-multi-uplink-test.sh
~~~

Сценарии проверяют разные уровни системы: namespace-тест охватывает startup/reload/rollback и владение системными ресурсами; два per-interface теста отдельно проверяют lifecycle/sysctl recovery и реальную передачу пакетов; peer traffic запускается для WG и AWG; multi-uplink проверяет выбор uplink, selectors и NAT.

Для контейнерного smoke test используется rootful Podman. Команды соответствуют CI и требуют bridge network:

~~~sh
cargo build
sudo podman build -f scripts/vpn-relay-podman.Containerfile -t vpn-relay-podman-test .
host_netns_inode="$(stat -Lc '%i' /proc/self/ns/net)"
sudo podman run --rm --network bridge --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.lo.forwarding=0 \
  --sysctl net.ipv4.conf.eth0.forwarding=0 \
  --env HOST_NETNS_INODE="$host_netns_inode" \
  vpn-relay-podman-test
~~~

CI дополнительно проверяет совместимость per-interface forwarding на Ubuntu 22.04 и 24.04. Полный набор CI job описан в [ci.yaml](.github/workflows/ci.yaml).

## Зависимость BoringTun

boringtun подключается напрямую из [lelikulibina/boringtun-awg](https://github.com/lelikulibina/boringtun-awg) по зафиксированному Git commit. Это необходимо для AWG-расширений и typed device API форка, которых может не быть в опубликованной версии crates.io.

## Лицензия

BSD 3-Clause. См. [LICENSE.md](LICENSE.md).
