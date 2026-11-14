use super::*;

#[test]
fn unmanaged_forwarding_treats_any_nonzero_value_as_enabled() {
    let allowed = std::collections::BTreeSet::new();
    validate_unmanaged_forwarding_with(&allowed, &["eth0".to_owned()], |_| {
        Ok(Some("2".to_owned()))
    })
    .unwrap_err();
}

#[test]
fn recovery_rejects_unsupported_legacy_journal_version() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-legacy-journal-{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let document = serde_json::json!({
        "version": 2,
        "namespace_inode": 4242,
        "state": {}
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();

    let error = recover_forwarding_state(&path, 4242).unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported forwarding state version 2"));
    assert!(
        path.exists(),
        "unsupported recovery journal must be retained"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn unmanaged_forwarding_validation_ignores_allowlisted_links() {
    let allowed = std::collections::BTreeSet::from(["wg0".to_owned()]);
    validate_unmanaged_forwarding_with(&allowed, &["wg0".to_owned()], |_| {
        Ok(Some("1".to_owned()))
    })
    .unwrap();
}

#[test]
fn forwarding_state_file_round_trips_with_private_permissions() {
    let path = forwarding_state_test_path("round-trip");
    persist_forwarding_state(&path, 1234, &sample_forwarding_state()).unwrap();

    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        load_forwarding_state(&path, 1234).unwrap(),
        Some(sample_forwarding_state())
    );

    std::fs::remove_file(path).unwrap();
}

#[test]
fn forwarding_state_file_rejects_a_different_network_namespace() {
    let path = forwarding_state_test_path("namespace");
    persist_forwarding_state(&path, 1234, &sample_forwarding_state()).unwrap();

    assert!(matches!(
        load_forwarding_state(&path, 5678),
        Err(RuntimeError::Forwarding(message))
            if message.contains("belongs to network namespace 1234")
    ));

    std::fs::remove_file(path).unwrap();
}

#[test]
fn forwarding_state_file_rejects_corrupt_json() {
    let path = forwarding_state_test_path("corrupt");
    std::fs::write(&path, b"{").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(matches!(
        load_forwarding_state(&path, 1234),
        Err(RuntimeError::Forwarding(_))
    ));

    std::fs::remove_file(path).unwrap();
}

#[test]
fn forwarding_state_persistence_does_not_follow_a_dangling_symlink() {
    use std::os::unix::fs::symlink;

    let path = forwarding_state_test_path("symlink");
    let target = forwarding_state_test_path("missing-target");
    symlink(&target, &path).unwrap();

    assert!(matches!(
        persist_forwarding_state(&path, 1234, &sample_forwarding_state()),
        Err(RuntimeError::Forwarding(_))
    ));
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!target.exists());

    std::fs::remove_file(path).unwrap();
}

#[test]
fn instance_lock_rejects_a_second_process_and_releases_on_drop() {
    let path =
        std::env::temp_dir().join(format!("vpn-relay-lock-test-{}.lock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let first = InstanceLock::acquire(&path).unwrap();
    assert!(matches!(
        InstanceLock::acquire(&path),
        Err(RuntimeError::AlreadyRunning(_))
    ));
    drop(first);
    assert!(InstanceLock::acquire(&path).is_ok());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn control_request_protocol_exposes_only_three_application_operations() {
    let requests = [
        ControlRequest::GetStats,
        ControlRequest::ReloadConfig {
            toml: "[interfaces.wg0]".to_owned(),
            mode: ReloadConfigMode::Full,
        },
        ControlRequest::ImportConfig {
            source: "[Interface]\nPrivateKey = test\nAddress = 10.0.0.1/24".to_owned(),
            interface: "wg0".to_owned(),
            replace: true,
        },
    ];
    let operations = ["get_stats", "reload_config", "import_config"];
    for (request, operation) in requests.iter().zip(operations) {
        let encoded = serde_json::to_vec(request).unwrap();
        assert!(String::from_utf8_lossy(&encoded)
            .contains(&format!("\"operation\":\"{operation}\"")));
        assert_eq!(
            serde_json::from_slice::<ControlRequest>(&encoded).unwrap(),
            *request
        );
    }
    assert!(
        serde_json::from_slice::<ControlRequest>(br#"{"operation":"replace_peers"}"#).is_err()
    );
    assert!(serde_json::from_slice::<ControlRequest>(br#"{"operation":"unknown"}"#).is_err());
}

#[test]
fn control_socket_is_private_and_removed_on_drop() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-control-{}-{}.sock",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_file(&path);
    let socket = ControlSocket::bind(path.clone()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(UnixStream::connect(&path).is_ok());
    drop(socket);
    assert!(!path.exists());
}

#[test]
fn control_socket_bind_failure_removes_incompletely_configured_path() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-control-bind-failure-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let result = ControlSocket::bind_with(path.clone(), |_, _| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected socket configuration failure",
        ))
    });
    assert!(
        matches!(result, Err(RuntimeError::Control(message)) if message.contains("injected socket configuration failure"))
    );
    assert!(!path.exists());
}

#[test]
fn control_socket_bind_rejects_replaced_path_without_unlinking_it() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-control-bind-replaced-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let result = ControlSocket::bind_with(path.clone(), |path, _| {
        std::fs::remove_file(path)?;
        std::fs::write(path, b"external replacement")?;
        Ok(())
    });
    assert!(matches!(
        result,
        Err(RuntimeError::Control(message)) if message.contains("path changed while being configured")
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"external replacement");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn control_socket_drop_does_not_remove_replaced_path() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-control-replaced-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let socket = ControlSocket::bind(path.clone()).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"administrator-owned replacement").unwrap();
    drop(socket);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"administrator-owned replacement"
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn control_socket_refuses_to_replace_regular_files() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-control-file-{}.sock",
        std::process::id()
    ));
    std::fs::write(&path, b"do not replace").unwrap();
    assert!(matches!(
        ControlSocket::bind(path.clone()),
        Err(RuntimeError::Control(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"do not replace");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn multi_device_peer_commit_failure_rolls_back_previously_committed_device() {
    let previous = peer_test_config("old-a", "old-b");
    let candidate = peer_test_config("new-a", "new-b");
    let prepared = peer_test_prepared();
    let mut devices: Vec<Box<dyn TunnelHandle>> = vec![
        Box::new(FaultInjectingTunnel {
            name: "wg0".to_owned(),
            peers: vec!["old-a".to_owned()],
            calls: 0,
            fail_calls: std::collections::HashSet::new(),
        }),
        Box::new(FaultInjectingTunnel {
            name: "wg1".to_owned(),
            peers: vec!["old-b".to_owned()],
            calls: 0,
            fail_calls: [1].into_iter().collect(),
        }),
    ];
    let changed = vec![(0, "wg0".to_owned()), (1, "wg1".to_owned())];

    let (committed, error) =
        commit_peer_replacements(&mut devices, &changed, &candidate, &prepared)
            .expect_err("second device must fail");
    assert_eq!(committed, vec![0]);
    assert!(error
        .to_string()
        .contains("injected peer replacement failure"));

    let failures = rollback_peer_replacements(&mut devices, &committed, &previous, &prepared);
    assert!(failures.is_empty(), "rollback failed: {failures:?}");

    let restored_first = devices[0].snapshot().unwrap();
    assert_eq!(restored_first.peers.len(), 1);
    assert_eq!(restored_first.peers[0].public_key[0], b'o');
    let unchanged_second = devices[1].snapshot().unwrap();
    assert_eq!(unchanged_second.peers.len(), 1);
    assert_eq!(unchanged_second.peers[0].public_key[0], b'o');
}

#[test]
fn multi_device_peer_rollback_continues_after_one_device_fails() {
    let previous = peer_test_config("old-a", "old-b");
    let candidate = peer_test_config("new-a", "new-b");
    let prepared = peer_test_prepared();
    let mut devices: Vec<Box<dyn TunnelHandle>> = vec![
        Box::new(FaultInjectingTunnel {
            name: "wg0".to_owned(),
            peers: vec!["old-a".to_owned()],
            calls: 0,
            fail_calls: std::collections::HashSet::new(),
        }),
        Box::new(FaultInjectingTunnel {
            name: "wg1".to_owned(),
            peers: vec!["old-b".to_owned()],
            calls: 0,
            fail_calls: [2].into_iter().collect(),
        }),
    ];
    let changed = vec![(0, "wg0".to_owned()), (1, "wg1".to_owned())];

    let committed = commit_peer_replacements(&mut devices, &changed, &candidate, &prepared)
        .expect("both peer sets must commit before rollback is exercised");
    assert_eq!(committed, vec![0, 1]);

    // Rollback runs in reverse order. wg1 fails on its restore call, but
    // wg0 must still be restored instead of being skipped by early return.
    let failures = rollback_peer_replacements(&mut devices, &committed, &previous, &prepared);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("wg1"));

    let restored_first = devices[0].snapshot().unwrap();
    assert_eq!(restored_first.peers[0].public_key[0], b'o');
    let failed_restore_second = devices[1].snapshot().unwrap();
    assert_eq!(failed_restore_second.peers[0].public_key[0], b'n');
}

#[test]
fn conntrack_mark_state_is_persisted_with_private_permissions() {
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("namespace.marks");
    let history = vec![sample_conntrack_decision()];

    persist_conntrack_mark_history(&path, &history).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(load_conntrack_mark_history(&path).unwrap(), history);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conntrack_mark_state_rejects_symlinks_and_non_private_files() {
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-safety-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let target = directory.join("target");
    let path = directory.join("namespace.marks");

    fs::write(&target, b"{}").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(matches!(
        load_conntrack_mark_history(&path),
        Err(RuntimeError::ConntrackMarkState(_))
    ));
    fs::remove_file(&path).unwrap();

    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        load_conntrack_mark_history(&path),
        Err(RuntimeError::ConntrackMarkState(_))
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conntrack_mark_state_rejects_oversized_files_before_deserializing() {
    const MAX_STATE_FILE_SIZE: usize = 4 * 1024 * 1024;
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-oversized-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("namespace.marks");
    fs::write(&path, vec![b'x'; MAX_STATE_FILE_SIZE + 1]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(matches!(
        load_conntrack_mark_history(&path),
        Err(RuntimeError::ConntrackMarkState(message))
            if message.contains("exceeds 4 MiB")
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conntrack_mark_state_rejects_malformed_json_and_unsupported_versions() {
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-format-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("namespace.marks");

    fs::write(&path, b"{not-json").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        load_conntrack_mark_history(&path),
        Err(RuntimeError::ConntrackMarkState(_))
    ));

    fs::write(&path, br#"{"version":2,"decisions":[]}"#).unwrap();
    assert!(matches!(
        load_conntrack_mark_history(&path),
        Err(RuntimeError::ConntrackMarkState(message))
            if message.contains("unsupported state file version 2")
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conntrack_mark_state_rejects_hard_links() {
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-hardlink-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("namespace.marks");
    let linked_path = directory.join("linked.marks");
    persist_conntrack_mark_history(&path, &[sample_conntrack_decision()]).unwrap();
    fs::hard_link(&path, &linked_path).unwrap();

    assert!(matches!(
        load_conntrack_mark_history(&path),
        Err(RuntimeError::ConntrackMarkState(_))
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conntrack_mark_state_persistence_refuses_unsafe_existing_files() {
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-persist-safety-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("namespace.marks");
    let linked_path = directory.join("linked.marks");
    fs::write(&path, b"untrusted").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, &linked_path).unwrap();

    assert!(matches!(
        persist_conntrack_mark_history(&path, &[sample_conntrack_decision()]),
        Err(RuntimeError::ConntrackMarkState(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"untrusted");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conntrack_mark_state_persistence_refuses_unsafe_temporary_symlinks() {
    let directory = std::env::temp_dir().join(format!(
        "vpn-relay-marks-temp-symlink-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("namespace.marks");
    let target = directory.join("target");
    let temporary_path = path.with_extension(format!("marks.tmp-{}", std::process::id()));
    fs::write(&target, b"do not modify").unwrap();
    std::os::unix::fs::symlink(&target, &temporary_path).unwrap();

    assert!(matches!(
        persist_conntrack_mark_history(&path, &[sample_conntrack_decision()]),
        Err(RuntimeError::ConntrackMarkState(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"do not modify");
    assert!(fs::symlink_metadata(&temporary_path)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn network_namespace_lock_paths_are_keyed_by_namespace_inode() {
    assert_ne!(
        InstanceLock::path_for_netns_inode(100),
        InstanceLock::path_for_netns_inode(200)
    );
    assert_eq!(
        InstanceLock::current_netns_path().unwrap(),
        InstanceLock::current_netns_path().unwrap()
    );
}

#[test]
fn unmanaged_forwarding_interfaces_must_remain_disabled() {
    let allowed = std::collections::BTreeSet::from(["wg0".to_owned()]);
    let interfaces = vec!["eth0".to_owned(), "wg0".to_owned()];
    validate_unmanaged_forwarding_with(&allowed, &interfaces, |key| {
        if key == "net.ipv4.conf.eth0.forwarding" {
            Ok(Some("1".to_owned()))
        } else {
            Ok(Some("0".to_owned()))
        }
    })
    .unwrap_err();
}

fn test_forwarding_entry(name: &str, ifindex: u32) -> InterfaceForwardingState {
    InterfaceForwardingState {
        name: name.to_owned(),
        ifindex,
        daemon_owned: false,
        ipv4: "0".to_owned(),
        ipv4_changed: true,
    }
}

#[test]
fn interface_forwarding_enable_failure_matrix_restores_every_interface() {
    // Exercise every identity-check and write boundary. A failed write may
    // have changed the kernel value before reporting an error, so rollback
    // must inspect and restore every managed interface, not only writes
    // which returned success.
    for failure_kind in ["verify", "write"] {
        for failure_position in 0..3 {
            let state = ForwardingState {
                ipv4: "1".to_owned(),
                ipv4_changed: false,
                interfaces: vec![
                    test_forwarding_entry("eth0", 7),
                    test_forwarding_entry("eth1", 8),
                    test_forwarding_entry("eth2", 9),
                ],
            };
            let values = std::cell::RefCell::new(std::collections::BTreeMap::from([
                ("net.ipv4.conf.eth0.forwarding".to_owned(), "0".to_owned()),
                ("net.ipv4.conf.eth1.forwarding".to_owned(), "0".to_owned()),
                ("net.ipv4.conf.eth2.forwarding".to_owned(), "0".to_owned()),
            ]));
            let mut verify_position = 0usize;
            let mut write_position = 0usize;
            let injected = std::cell::Cell::new(false);

            let result = enable_interface_forwarding_entries_with(
                &state,
                |key| Ok(values.borrow().get(key).cloned().unwrap()),
                |key, value| {
                    if value == "1" {
                        let position = write_position;
                        write_position += 1;
                        // Model an ambiguous sysctl result: the kernel
                        // accepted the write, but the command failed.
                        values.borrow_mut().insert(key.to_owned(), value.to_owned());
                        if failure_kind == "write"
                            && position == failure_position
                            && !injected.get()
                        {
                            injected.set(true);
                            return Err(RuntimeError::Forwarding(format!(
                                "injected write failure at interface {position}"
                            )));
                        }
                    } else {
                        values.borrow_mut().insert(key.to_owned(), value.to_owned());
                    }
                    Ok(())
                },
                |name, _| {
                    let position = verify_position;
                    verify_position += 1;
                    if failure_kind == "verify"
                        && position == failure_position
                        && !injected.get()
                    {
                        injected.set(true);
                        return Err(RuntimeError::Forwarding(format!(
                            "injected identity failure at {name}"
                        )));
                    }
                    Ok(())
                },
            );

            assert!(
                injected.get(),
                "{failure_kind} failure point {failure_position} was not reached"
            );
            assert!(
                matches!(result, Err(RuntimeError::Forwarding(_))),
                "{failure_kind} failure point {failure_position} returned an unexpected result: {result:?}"
            );
            let values = values.into_inner();
            for name in ["eth0", "eth1", "eth2"] {
                assert_eq!(
                    values[&format!("net.ipv4.conf.{name}.forwarding")],
                    "0",
                    "{failure_kind} failure at position {failure_position} did not restore {name}"
                );
            }
        }
    }
}

#[test]
fn interface_forwarding_enable_reports_fatal_when_rollback_fails() {
    let state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: vec![test_forwarding_entry("eth0", 7)],
    };
    let current = std::cell::RefCell::new("0".to_owned());
    let result = enable_interface_forwarding_entries_with(
        &state,
        |_| Ok(current.borrow().clone()),
        |_, value| {
            if value == "1" {
                *current.borrow_mut() = "1".to_owned();
                return Err(RuntimeError::Forwarding(
                    "injected setup failure".to_owned(),
                ));
            }
            Err(RuntimeError::Forwarding(
                "injected rollback failure".to_owned(),
            ))
        },
        |_, _| Ok(()),
    );
    assert!(matches!(result, Err(RuntimeError::FatalTransition(message))
        if message.contains("injected setup failure")
            && message.contains("injected rollback failure")));
}

#[test]
fn interface_forwarding_enable_fails_closed_if_identity_is_lost() {
    let state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: vec![test_forwarding_entry("eth0", 7)],
    };
    let mut writes = 0;
    let result = enable_interface_forwarding_entries_with(
        &state,
        |_| Ok("0".to_owned()),
        |_, _| {
            writes += 1;
            Ok(())
        },
        |_, _| Err(RuntimeError::Forwarding("identity changed".to_owned())),
    );
    assert!(matches!(result, Err(RuntimeError::FatalTransition(_))));
    assert_eq!(writes, 0);
}

#[test]
fn daemon_owned_tun_sysctls_are_never_restored_by_saved_identity() {
    let mut entry = test_forwarding_entry("wg0", 17);
    entry.daemon_owned = true;
    let state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: vec![entry],
    };
    let mut reads = 0;
    let mut writes = 0;
    restore_interface_forwarding_entries_with(
        &state,
        |_| {
            reads += 1;
            Ok("1".to_owned())
        },
        |_, _| {
            writes += 1;
            Ok(())
        },
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(reads, 0);
    assert_eq!(writes, 0);
}

#[test]
fn interface_forwarding_restore_checks_identity_and_daemon_value() {
    let entry = test_forwarding_entry("eth0", 7);
    let calls = std::cell::RefCell::new(Vec::new());
    restore_interface_forwarding_entry_with(
        &entry,
        "0",
        true,
        |key| {
            calls.borrow_mut().push(format!("read:{key}"));
            Ok("1".to_owned())
        },
        |key, value| {
            calls.borrow_mut().push(format!("write:{key}={value}"));
            Ok(())
        },
        |name, index| {
            calls.borrow_mut().push(format!("verify:{name}:{index}"));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        calls.into_inner(),
        vec![
            "verify:eth0:7",
            "read:net.ipv4.conf.eth0.forwarding",
            "verify:eth0:7",
            "write:net.ipv4.conf.eth0.forwarding=0",
        ]
    );
}

#[test]
fn interface_forwarding_restore_never_writes_after_identity_mismatch() {
    let entry = test_forwarding_entry("eth0", 7);
    let mut reads = 0;
    let mut writes = 0;
    let result = restore_interface_forwarding_entry_with(
        &entry,
        "0",
        true,
        |_| {
            reads += 1;
            Ok("1".to_owned())
        },
        |_, _| {
            writes += 1;
            Ok(())
        },
        |_, _| Err(RuntimeError::Forwarding("identity changed".to_owned())),
    );
    assert!(result.is_err());
    assert_eq!(reads, 0);
    assert_eq!(writes, 0);
}

#[test]
fn interface_forwarding_restore_preserves_operator_value() {
    let entry = test_forwarding_entry("eth0", 7);
    let mut writes = 0;
    restore_interface_forwarding_entry_with(
        &entry,
        "0",
        true,
        |_| Ok("2".to_owned()),
        |_, _| {
            writes += 1;
            Ok(())
        },
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(writes, 0);
}

#[test]
fn forwarding_journal_accepts_legacy_namespace_only_state() {
    let legacy = r#"{"ipv4":"0","ipv4_changed":true,"interfaces":[]}"#;
    let state: ForwardingState = serde_json::from_str(legacy).unwrap();
    assert!(state.interfaces.is_empty());
    validate_forwarding_state(&state).unwrap();
}

#[test]
fn forwarding_journal_validates_link_identity_and_values() {
    let mut state = sample_forwarding_state();
    state.interfaces.push(test_forwarding_entry("awg0", 17));
    validate_forwarding_state(&state).unwrap();

    state.interfaces[0].ifindex = 0;
    assert!(validate_forwarding_state(&state).is_err());
    state.interfaces[0].ifindex = 17;
    state.interfaces[0].name = "../net/eth0".to_owned();
    assert!(validate_forwarding_state(&state).is_err());
    state.interfaces[0].name = "awg0".to_owned();
    state.interfaces[0].ipv4 = "2".to_owned();
    assert!(validate_forwarding_state(&state).is_err());
}

#[test]
fn forwarding_journal_rejects_duplicate_link_identity() {
    let mut state = sample_forwarding_state();
    let entry = test_forwarding_entry("awg0", 17);
    state.interfaces = vec![entry.clone(), entry];
    assert!(validate_forwarding_state(&state).is_err());
}

#[test]
fn forwarding_enable_does_not_rewrite_already_enabled_ipv4() {
    let state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: Vec::new(),
    };
    let enabled = enable_forwarding_state_with(state.clone(), |_, _| {
        panic!("already-enabled IPv4 forwarding must not be rewritten")
    })
    .unwrap();
    assert_eq!(enabled, state);
}

#[test]
fn forwarding_enable_changes_and_restores_ipv4_state() {
    let state = ForwardingState {
        ipv4: "0".to_owned(),
        ipv4_changed: false,
        interfaces: Vec::new(),
    };
    let mut writes = Vec::new();
    let enabled = enable_forwarding_state_with(state, |key, value| {
        writes.push((key.to_owned(), value.to_owned()));
        Ok(())
    })
    .unwrap();
    assert!(enabled.ipv4_changed);
    assert_eq!(
        writes,
        vec![("net.ipv4.ip_forward".to_owned(), "1".to_owned())]
    );

    restore_forwarding_with(&enabled, |key, value| {
        writes.push((key.to_owned(), value.to_owned()));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        writes.last(),
        Some(&("net.ipv4.ip_forward".to_owned(), "0".to_owned()))
    );
}

#[test]
fn forwarding_enable_keeps_fail_closed_policy_when_restore_fails() {
    let state = ForwardingState {
        ipv4: "0".to_owned(),
        ipv4_changed: false,
        interfaces: Vec::new(),
    };
    let result = enable_forwarding_state_with(state, |_, value| {
        if value == "1" {
            Err(RuntimeError::Forwarding(
                "injected enable failure".to_owned(),
            ))
        } else {
            Err(RuntimeError::Forwarding(
                "injected restore failure".to_owned(),
            ))
        }
    });
    assert!(matches!(result, Err(RuntimeError::FatalTransition(message))
        if message.contains("injected enable failure")
            && message.contains("injected restore failure")));
}

#[test]
fn per_interface_restore_attempts_every_entry_after_failures() {
    let state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: vec![
            test_forwarding_entry("eth0", 7),
            test_forwarding_entry("eth1", 8),
        ],
    };
    let mut writes = Vec::new();
    let result = restore_interface_forwarding_entries_with(
        &state,
        |_| Ok("1".to_owned()),
        |key, value| {
            writes.push((key.to_owned(), value.to_owned()));
            Ok(())
        },
        |name, _| {
            if name == "eth0" {
                Err(RuntimeError::Forwarding("identity changed".to_owned()))
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(result, Err(RuntimeError::FatalTransition(_))));
    assert_eq!(
        writes,
        vec![("net.ipv4.conf.eth1.forwarding".to_owned(), "0".to_owned())]
    );
}

#[test]
fn forwarding_journal_persistence_failure_matrix_preserves_atomicity() {
    let namespace_inode = 1234;
    let state = sample_forwarding_state();

    for stage in ["create", "write", "file_sync", "rename", "directory_sync"] {
        let path = forwarding_state_test_path(&format!("persist-{stage}"));
        let temporary_path =
            path.with_extension(format!("forwarding.tmp-{}", std::process::id()));
        let mut io = FaultInjectingForwardingJournalIo { fail_at: stage };

        let result = persist_forwarding_state_with(&path, namespace_inode, &state, &mut io);
        assert!(
            matches!(result, Err(RuntimeError::Forwarding(ref message))
                if message.contains(&format!("injected {stage} failure"))),
            "failure at {stage} returned an unexpected result: {result:?}"
        );
        assert!(
            !temporary_path.exists(),
            "temporary journal remained after {stage} failure"
        );

        if stage == "directory_sync" {
            // Rename already committed the new journal. A failed parent
            // fsync must report uncertainty but must not discard recovery data.
            assert!(
                path.exists(),
                "renamed journal was lost after directory fsync failure"
            );
            assert!(load_forwarding_state(&path, namespace_inode)
                .unwrap()
                .is_some());
            fs::remove_file(&path).unwrap();
        } else {
            assert!(
                !path.exists(),
                "final journal appeared after pre-rename {stage} failure"
            );
        }
    }
}

#[test]
fn forwarding_journal_remove_failure_matrix_reports_unlink_and_directory_sync() {
    let path = forwarding_state_test_path("remove-failure-matrix");
    persist_forwarding_state(&path, 4321, &sample_forwarding_state()).unwrap();

    let mut unlink_io = FaultInjectingForwardingJournalIo { fail_at: "remove" };
    assert!(matches!(
        remove_forwarding_state_file_with(&path, &mut unlink_io),
        Err(RuntimeError::Forwarding(message)) if message.contains("injected remove failure")
    ));
    assert!(
        path.exists(),
        "failed unlink must retain the recovery journal"
    );

    let mut directory_sync_io = FaultInjectingForwardingJournalIo {
        fail_at: "directory_sync",
    };
    assert!(matches!(
        remove_forwarding_state_file_with(&path, &mut directory_sync_io),
        Err(RuntimeError::Forwarding(message))
            if message.contains("injected directory_sync failure")
    ));
    assert!(
        !path.exists(),
        "directory fsync failure occurs after unlink; the journal must remain removed"
    );
}

#[test]
fn interface_forwarding_restore_failure_matrix_stops_at_failed_boundary() {
    for stage in ["read", "second_verify", "write"] {
        let entry = test_forwarding_entry("eth0", 7);
        let mut verify_calls = 0usize;
        let mut write_calls = 0usize;
        let result = restore_interface_forwarding_entry_with(
            &entry,
            "0",
            true,
            |_| {
                if stage == "read" {
                    Err(RuntimeError::Forwarding("injected read failure".to_owned()))
                } else {
                    Ok("1".to_owned())
                }
            },
            |_, _| {
                write_calls += 1;
                if stage == "write" {
                    Err(RuntimeError::Forwarding(
                        "injected write failure".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            },
            |_, _| {
                verify_calls += 1;
                if stage == "second_verify" && verify_calls == 2 {
                    Err(RuntimeError::Forwarding(
                        "injected second identity failure".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            },
        );

        assert!(result.is_err(), "{stage} failure was not propagated");
        assert_eq!(
            verify_calls,
            if stage == "read" { 1 } else { 2 },
            "unexpected identity verification count for {stage}"
        );
        assert_eq!(
            write_calls,
            if stage == "write" { 1 } else { 0 },
            "unsafe write attempt count for {stage}"
        );
    }
}

#[test]
fn namespace_restore_failures_do_not_skip_per_interface_recovery() {
    for stage in ["namespace_read", "namespace_write"] {
        let state = ForwardingState {
            ipv4: "0".to_owned(),
            ipv4_changed: true,
            interfaces: vec![
                test_forwarding_entry("eth0", 7),
                test_forwarding_entry("eth1", 8),
            ],
        };
        let mut interface_writes = Vec::new();
        let result = restore_forwarding_state_with_mode_and_verify(
            &state,
            |key| {
                if key == "net.ipv4.ip_forward" && stage == "namespace_read" {
                    Err(RuntimeError::Forwarding(
                        "injected namespace read failure".to_owned(),
                    ))
                } else {
                    Ok("1".to_owned())
                }
            },
            |key, value| {
                if key == "net.ipv4.ip_forward" && stage == "namespace_write" {
                    return Err(RuntimeError::Forwarding(
                        "injected namespace write failure".to_owned(),
                    ));
                }
                interface_writes.push((key.to_owned(), value.to_owned()));
                Ok(())
            },
            |_, _| Ok(()),
        );

        let expected_failure = if stage == "namespace_read" {
            "injected namespace read failure"
        } else {
            "injected namespace write failure"
        };
        assert!(matches!(result, Err(RuntimeError::FatalTransition(message))
            if message.contains(expected_failure)));
        assert_eq!(
            interface_writes,
            vec![
                ("net.ipv4.conf.eth0.forwarding".to_owned(), "0".to_owned()),
                ("net.ipv4.conf.eth1.forwarding".to_owned(), "0".to_owned()),
            ],
            "namespace {stage} failure skipped an interface restore"
        );
    }
}

#[test]
fn forwarding_state_recovery_restores_and_is_idempotent() {
    let state = ForwardingState {
        ipv4: "0".to_owned(),
        ipv4_changed: true,
        interfaces: Vec::new(),
    };
    let mut writes = Vec::new();
    restore_forwarding_state_with_mode(
        &state,
        |_| Ok("1".to_owned()),
        |key, value| {
            writes.push((key.to_owned(), value.to_owned()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        writes,
        vec![("net.ipv4.ip_forward".to_owned(), "0".to_owned())]
    );

    writes.clear();
    restore_forwarding_state_with_mode(
        &state,
        |_| Ok("0".to_owned()),
        |key, value| {
            writes.push((key.to_owned(), value.to_owned()));
            Ok(())
        },
    )
    .unwrap();
    assert!(writes.is_empty());
}

#[test]
fn multi_device_peer_rollback_failure_is_reported_for_fatal_shutdown() {
    let previous = peer_test_config("old-a", "old-b");
    let candidate = peer_test_config("new-a", "new-b");
    let prepared = peer_test_prepared();
    let mut devices: Vec<Box<dyn TunnelHandle>> = vec![
        Box::new(FaultInjectingTunnel {
            name: "wg0".to_owned(),
            peers: vec!["old-a".to_owned()],
            calls: 0,
            fail_calls: [2].into_iter().collect(),
        }),
        Box::new(FaultInjectingTunnel {
            name: "wg1".to_owned(),
            peers: vec!["old-b".to_owned()],
            calls: 0,
            fail_calls: [1].into_iter().collect(),
        }),
    ];
    let changed = vec![(0, "wg0".to_owned()), (1, "wg1".to_owned())];

    let (committed, _) =
        commit_peer_replacements(&mut devices, &changed, &candidate, &prepared)
            .expect_err("second device must fail");
    assert_eq!(committed, vec![0]);
    let failures = rollback_peer_replacements(&mut devices, &committed, &previous, &prepared);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("wg0"));
    assert!(failures[0].contains("injected peer replacement failure"));

    let partially_committed = devices[0].snapshot().unwrap();
    assert_eq!(partially_committed.peers[0].public_key[0], b'n');
    let never_committed = devices[1].snapshot().unwrap();
    assert_eq!(never_committed.peers[0].public_key[0], b'o');
}

fn forwarding_state_test_path(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vpn-relay-forwarding-{label}-{}-{nonce}.json",
        std::process::id()
    ))
}

struct FaultInjectingForwardingJournalIo {
    fail_at: &'static str,
}

impl FaultInjectingForwardingJournalIo {
    fn error(stage: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("injected {stage} failure"),
        )
    }
}

impl ForwardingJournalIo for FaultInjectingForwardingJournalIo {
    fn create_new_file(&mut self, path: &Path) -> std::io::Result<File> {
        if self.fail_at == "create" {
            return Err(Self::error("create"));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    fn write_state(
        &mut self,
        file: &mut File,
        saved: &ForwardingStateFile,
    ) -> std::io::Result<()> {
        if self.fail_at == "write" {
            file.write_all(b"{")?;
            return Err(Self::error("write"));
        }
        serde_json::to_writer(file, saved).map_err(std::io::Error::other)
    }

    fn sync_file(&mut self, file: &File) -> std::io::Result<()> {
        if self.fail_at == "file_sync" {
            return Err(Self::error("file_sync"));
        }
        file.sync_all()
    }

    fn rename(&mut self, source: &Path, destination: &Path) -> std::io::Result<()> {
        if self.fail_at == "rename" {
            return Err(Self::error("rename"));
        }
        fs::rename(source, destination)
    }

    fn remove_file(&mut self, path: &Path) -> std::io::Result<()> {
        if self.fail_at == "remove" {
            return Err(Self::error("remove"));
        }
        fs::remove_file(path)
    }

    fn sync_directory(&mut self, path: &Path) -> std::io::Result<()> {
        if self.fail_at == "directory_sync" {
            return Err(Self::error("directory_sync"));
        }
        File::open(path).and_then(|directory| directory.sync_all())
    }
}

fn sample_forwarding_state() -> ForwardingState {
    ForwardingState {
        ipv4: "0".to_owned(),
        ipv4_changed: true,
        interfaces: Vec::new(),
    }
}

struct FaultInjectingTunnel {
    name: String,
    peers: Vec<String>,
    calls: usize,
    fail_calls: std::collections::HashSet<usize>,
}

impl TunnelHandle for FaultInjectingTunnel {
    fn snapshot(&self) -> Result<TunnelSnapshot, BackendError> {
        Ok(TunnelSnapshot {
            name: self.name.clone(),
            peers: self
                .peers
                .iter()
                .map(|key| {
                    let mut public_key = [0u8; 32];
                    public_key[0] = key.as_bytes().first().copied().unwrap_or_default();
                    crate::backend::TunnelPeerSnapshot {
                        public_key,
                        allowed_ips: vec!["10.0.0.2/32".to_owned()],
                        endpoint: None,
                        tx_bytes: 0,
                        rx_bytes: 0,
                        time_since_last_handshake: None,
                    }
                })
                .collect(),
        })
    }

    fn replace_peers(
        &mut self,
        interface: &crate::config::InterfaceConfig,
        _prepared: &PreparedInterface,
    ) -> Result<(), BackendError> {
        self.calls += 1;
        if self.fail_calls.contains(&self.calls) {
            return Err(BackendError::new(format!(
                "injected peer replacement failure on {} call {}",
                self.name, self.calls
            )));
        }
        self.peers = interface
            .peers
            .iter()
            .map(|peer| peer.public_key.clone())
            .collect();
        Ok(())
    }

    fn shutdown(&self) {}
    fn wait(&mut self) {}
}

fn peer_interface(peer_key: &str) -> crate::config::InterfaceConfig {
    crate::config::InterfaceConfig {
        tunnel_type: crate::config::TunnelType::WireGuard,
        address: vec!["10.0.0.1/24".to_owned()],
        mtu: 1380,
        listen_port: None,
        private_key: "private".to_owned(),
        socket_fwmark: None,
        peers: vec![PeerConfig {
            public_key: peer_key.to_owned(),
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.0.0.2/32".to_owned()],
            persistent_keepalive_secs: None,
            persistent_keepalive_range: None,
        }],
        awg: boringtun::noise::amnezia::AmneziaWgConfig::default(),
    }
}

fn peer_test_config(wg0: &str, wg1: &str) -> Config {
    Config {
        daemon: crate::config::DaemonConfig::default(),
        interfaces: [
            ("wg0".to_owned(), peer_interface(wg0)),
            ("wg1".to_owned(), peer_interface(wg1)),
        ]
        .into_iter()
        .collect(),
        routing: crate::config::RoutingConfig::default(),
        firewall: crate::config::FirewallConfig::default(),
    }
}

fn peer_test_prepared() -> std::collections::BTreeMap<String, PreparedInterface> {
    [
        (
            "wg0".to_owned(),
            PreparedInterface {
                peer_endpoints: vec![None],
            },
        ),
        (
            "wg1".to_owned(),
            PreparedInterface {
                peer_endpoints: vec![None],
            },
        ),
    ]
    .into_iter()
    .collect()
}

fn sample_conntrack_decision() -> crate::routing::RoutingDecision {
    crate::routing::RoutingDecision {
        priority: 10,
        ingress: "wg-ingress".to_owned(),
        source: Some(vec!["10.0.0.2/32".to_owned()]),
        destination: Some(vec!["0.0.0.0/0".to_owned()]),
        egress: "awg-uplink".to_owned(),
        routing_mark: 0x8000_0001,
        conntrack_mark: 0x5001_0000,
        nat: crate::config::NatMode::None,
        nat_to: None,
    }
}

#[test]
fn control_socket_recovers_stale_socket_files() {
    let path = std::env::temp_dir().join(format!(
        "vpn-relay-control-stale-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let stale = UnixListener::bind(&path).unwrap();
    drop(stale);
    let socket = ControlSocket::bind(path.clone()).unwrap();
    assert!(path.exists());
    drop(socket);
    assert!(!path.exists());
}

#[test]
fn get_stats_control_request_uses_tagged_operation() {
    let encoded = serde_json::to_string(&ControlRequest::GetStats).unwrap();
    assert_eq!(encoded, r#"{"operation":"get_stats"}"#);
    let decoded: ControlRequest = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, ControlRequest::GetStats);
}

#[test]
fn stats_control_response_preserves_client_and_endpoint_metadata() {
    let response = ControlResponse {
        ok: true,
        error: None,
        import_report: None,
        stats: Some(vec![InterfaceStats {
            name: "wg0".to_owned(),
            peers: vec![PeerStats {
                public_key: "aabb".to_owned(),
                client_ips: vec!["10.0.0.2/32".to_owned()],
                endpoint: Some("203.0.113.10:51820".parse().unwrap()),
                tx_bytes: 1234,
                rx_bytes: 5678,
                handshake_age_secs: Some(12),
            }],
        }]),
    };
    let encoded = serde_json::to_vec(&response).unwrap();
    let decoded: ControlResponse = serde_json::from_slice(&encoded).unwrap();
    let stats = decoded.stats.unwrap();
    let peer = &stats[0].peers[0];
    assert_eq!(peer.client_ips, vec!["10.0.0.2/32".to_owned()]);
    assert_eq!(peer.endpoint, Some("203.0.113.10:51820".parse().unwrap()));
    assert_eq!(peer.tx_bytes, 1234);
    assert_eq!(peer.rx_bytes, 5678);
    assert_eq!(peer.handshake_age_secs, Some(12));
}
