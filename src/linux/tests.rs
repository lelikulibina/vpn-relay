use super::*;

fn cleanup_test_plan() -> RoutingPlan {
    RoutingPlan {
        nft_family: "inet".into(),
        nft_table: "vpn_relay".into(),
        managed_interfaces: vec!["wg0".into(), "awg0".into()],
        egresses: vec![crate::routing::EgressPlan {
            interface: "awg0".into(),
            mark: 0x8000_0001,
            table_id: 10001,
            ip_rule_priority: 10001,
        }],
        decisions: Vec::new(),
        input_rules: Vec::new(),
        output_rules: Vec::new(),
        socket_marks: Vec::new(),
        ipv6_drop_interfaces: Vec::new(),
        interface_indices: None,
    }
}

#[test]
fn socket_fwmark_apply_failure_at_each_install_boundary_rolls_back_all_rules() {
    let plan = {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
        plan
    };

    for failure_position in 1..=2 {
        let mut calls = Vec::new();
        let mut add_count = 0;
        let mut failure_index = None;
        let result = apply_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if args.get(2).is_some_and(|part| part == "add") {
                add_count += 1;
                if add_count == failure_position {
                    failure_index = Some(calls.len() - 1);
                    return Err(LinuxError::Command {
                        program: format!("ip {}", args.join(" ")),
                        status: "exit status 2".into(),
                        stderr: format!(
                            "injected socket install failure at step {failure_position}"
                        ),
                    });
                }
            }
            Ok(())
        });

        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains(&format!("step {failure_position}"))));
        let rollback = &calls[failure_index.expect("failure was injected")..];
        let cleanup = rollback
            .iter()
            .filter(|args| {
                args.get(2).is_some_and(|part| part == "del")
                    && args.get(4).is_some_and(|part| part == "9000")
            })
            .count();
        assert_eq!(
            cleanup, 2,
            "failure at socket install step {failure_position} must roll back every socket mark"
        );
    }
}

#[test]
fn socket_fwmark_stale_rule_cleanup_failure_aborts_install_and_rolls_back() {
    let mut plan = cleanup_test_plan();
    plan.socket_marks = vec![0x1000_0001, 0x1000_0002];

    for failure_position in 1..=2 {
        let mut calls = Vec::new();
        let mut stale_cleanup_attempts = 0;
        let mut failure_injected = false;
        let result = apply_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            let is_socket_rule = args.get(1).is_some_and(|part| part == "rule")
                && args.get(4).is_some_and(|part| part == "9000");
            if is_socket_rule && args.get(2).is_some_and(|part| part == "del") && !failure_injected
            {
                stale_cleanup_attempts += 1;
                if stale_cleanup_attempts == failure_position {
                    failure_injected = true;
                    return Err(LinuxError::Command {
                        program: format!("ip {}", args.join(" ")),
                        status: "exit status 2".into(),
                        stderr: format!(
                            "injected stale socket rule cleanup failure at step {failure_position}"
                        ),
                    });
                }
            }
            Ok(())
        });

        assert!(
            failure_injected,
            "failure point {failure_position} was not reached"
        );
        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains(&format!("step {failure_position}"))));
        assert!(
            !calls.iter().any(|args| {
                args.get(1).is_some_and(|part| part == "rule")
                    && args.get(2).is_some_and(|part| part == "add")
                    && args.get(3).is_some_and(|part| part == "priority")
                    && args.get(4).is_some_and(|part| part == "9000")
                    && args.get(5).is_some_and(|part| part == "fwmark")
                    && args.get(6).is_some_and(|value| {
                        plan.socket_marks
                            .iter()
                            .any(|mark| value == &format!("0x{mark:x}"))
                    })
                    && args.get(7).is_some_and(|part| part == "lookup")
                    && args.get(8).is_some_and(|part| part == "main")
                    && args.get(9).is_some_and(|part| part == "protocol")
                    && args.get(10).is_some_and(|part| part == ROUTING_PROTOCOL)
            }),
            "socket rules must not be installed after stale-rule cleanup fails; calls: {calls:?}"
        );

        let rollback = calls
            .iter()
            .filter(|args| {
                args.get(1).is_some_and(|part| part == "rule")
                    && args.get(2).is_some_and(|part| part == "del")
                    && args.get(4).is_some_and(|part| part == "9000")
            })
            .count();
        assert_eq!(
            rollback,
            failure_position + 2,
            "failed pre-cleanup plus rollback must attempt every socket mark"
        );
    }
}

#[test]
fn socket_fwmark_cleanup_attempts_every_rule_after_failures() {
    let mut plan = cleanup_test_plan();
    plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
    let mut cleanup_attempts = 0;
    let result = remove_policy_routing_with(&plan, &mut |_program, args| {
        if args.get(2).is_some_and(|part| part == "del")
            && args.get(4).is_some_and(|part| part == "9000")
        {
            cleanup_attempts += 1;
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected socket cleanup failure".into(),
            });
        }
        Ok(())
    });

    assert_eq!(cleanup_attempts, 2);
    assert!(matches!(result, Err(LinuxError::Cleanup(message))
        if message.matches("injected socket cleanup failure").count() == 2));
}

#[test]
fn egress_stale_rule_cleanup_failure_aborts_install_and_rolls_back() {
    let plan = cleanup_test_plan();

    for failure_position in 1..=1 {
        let mut calls = Vec::new();
        let mut stale_cleanup_attempts = 0;
        let mut failure_injected = false;
        let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            let is_stale_delete = args.get(2).is_some_and(|part| part == "del")
                && (args.get(1).is_some_and(|part| part == "rule")
                    || args.get(1).is_some_and(|part| part == "route"));
            if is_stale_delete && !failure_injected {
                stale_cleanup_attempts += 1;
                if stale_cleanup_attempts == failure_position {
                    failure_injected = true;
                    return Err(LinuxError::Command {
                        program: format!("ip {}", args.join(" ")),
                        status: "exit status 2".into(),
                        stderr: format!(
                            "injected stale egress cleanup failure at step {failure_position}"
                        ),
                    });
                }
            }
            Ok(())
        });

        assert!(
            failure_injected,
            "failure point {failure_position} was not reached"
        );
        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains(&format!("step {failure_position}"))));
        assert!(
            !calls.iter().any(|args| {
                args.get(2).is_some_and(|part| part == "replace")
                    || args.get(2).is_some_and(|part| part == "add")
            }),
            "egress routes and rules must not be installed after stale cleanup fails"
        );

        let cleanup = calls
            .iter()
            .filter(|args| {
                args.get(2).is_some_and(|part| part == "del")
                    && (args.get(1).is_some_and(|part| part == "rule")
                        || args.get(1).is_some_and(|part| part == "route"))
            })
            .count();
        assert_eq!(
            cleanup,
            failure_position + 2,
            "failed pre-cleanup plus rollback must attempt all IPv4 egress resources"
        );
    }
}

#[test]
fn egress_apply_failure_at_each_ipv4_install_boundary_rolls_back_all_resources() {
    let plan = cleanup_test_plan();
    let failure_points = [("-4", "route", "replace"), ("-4", "rule", "add")];

    for (failed_family, failed_kind, failed_operation) in failure_points {
        let mut calls = Vec::new();
        let mut injected = false;
        let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if !injected
                && args.first().is_some_and(|family| family == failed_family)
                && args.get(1).is_some_and(|kind| kind == failed_kind)
                && args
                    .get(2)
                    .is_some_and(|operation| operation == failed_operation)
            {
                injected = true;
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: format!(
                        "injected {failed_family} {failed_kind} {failed_operation} failure"
                    ),
                });
            }
            Ok(())
        });

        assert!(
            injected,
            "failure point {failed_family} {failed_kind} {failed_operation} was not reached"
        );
        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains(&format!("injected {failed_family} {failed_kind} {failed_operation} failure"))));

        let cleanup = &calls[calls.len() - 2..];
        assert_eq!(cleanup.len(), 2);
        assert!(cleanup
            .iter()
            .any(|args| args.first().is_some_and(|value| value == "-4")
                && args.get(1).is_some_and(|value| value == "rule")
                && args.get(2).is_some_and(|value| value == "del")));
        assert!(cleanup
            .iter()
            .any(|args| args.first().is_some_and(|value| value == "-4")
                && args.get(1).is_some_and(|value| value == "route")
                && args.get(2).is_some_and(|value| value == "del")));
    }
}

#[test]
fn egress_apply_reports_rollback_failure_without_hiding_install_failure() {
    let plan = cleanup_test_plan();
    let mut calls = 0usize;
    let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
        calls += 1;
        if args.get(2).is_some_and(|part| part == "add") {
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected install failure".into(),
            });
        }
        if calls > 3 {
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected rollback failure".into(),
            });
        }
        Ok(())
    });

    assert!(
        matches!(result, Err(LinuxError::Rollback { operation, rollback })
            if operation.contains("injected install failure")
                && rollback.contains("injected rollback failure"))
    );
}

#[test]
fn egress_apply_aggregates_every_rollback_cleanup_failure() {
    let plan = cleanup_test_plan();
    let mut calls = Vec::new();
    let mut failure_index = None;
    let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
        calls.push(args.to_vec());
        if failure_index.is_none()
            && args.get(1).is_some_and(|part| part == "rule")
            && args.get(2).is_some_and(|part| part == "add")
        {
            failure_index = Some(calls.len() - 1);
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected primary install failure".into(),
            });
        }
        if failure_index.is_some() {
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: format!("injected rollback cleanup failure: {}", args.join(" ")),
            });
        }
        Ok(())
    });

    let cleanup = &calls[failure_index.expect("install failure injected") + 1..];
    assert_eq!(cleanup.len(), 2, "every IPv4 resource cleanup must run");
    assert!(cleanup
        .iter()
        .all(|args| args.get(2).is_some_and(|op| op == "del")));
    assert!(
        matches!(result, Err(LinuxError::Rollback { operation, rollback })
            if operation.contains("injected primary install failure")
                && rollback.matches("injected rollback cleanup failure").count() == 2)
    );
}

#[test]
fn egress_cleanup_attempts_both_ipv4_resources_after_command_failures() {
    let plan = cleanup_test_plan();
    let mut calls = Vec::new();
    let result = remove_egress_policy_routing_with(&plan, &mut |_program, args| {
        calls.push(args.to_vec());
        Err(LinuxError::Command {
            program: format!("ip {}", args.join(" ")),
            status: "exit status 2".into(),
            stderr: "RTNETLINK answers: Operation not permitted".into(),
        })
    });

    assert_eq!(
        calls.len(),
        2,
        "IPv4 route and rule cleanup must both be attempted"
    );
    assert!(matches!(result, Err(LinuxError::Cleanup(message))
        if message.matches("Operation not permitted").count() == 2));
    assert!(calls
        .iter()
        .any(|args| args.first().is_some_and(|family| family == "-4")));
    assert!(calls
        .iter()
        .any(|args| args.get(1).is_some_and(|kind| kind == "rule")));
    assert!(calls
        .iter()
        .any(|args| args.get(1).is_some_and(|kind| kind == "route")));
}

#[test]
fn egress_cleanup_treats_missing_resources_as_already_removed() {
    let plan = cleanup_test_plan();
    let mut calls = 0;
    let result = remove_egress_policy_routing_with(&plan, &mut |_program, _args| {
        calls += 1;
        Err(LinuxError::Command {
            program: "ip".into(),
            status: "exit status 2".into(),
            stderr: "RTNETLINK answers: No such process".into(),
        })
    });

    assert!(result.is_ok());
    assert_eq!(calls, 2, "cleanup must inspect both IPv4 resources");
}

#[test]
fn egress_cleanup_aggregates_failures_across_multiple_interfaces() {
    let mut plan = cleanup_test_plan();
    plan.egresses.push(crate::routing::EgressPlan {
        interface: "wg1".into(),
        mark: 0x8000_0002,
        table_id: 10002,
        ip_rule_priority: 10002,
    });
    let mut calls = Vec::new();
    let result = remove_egress_policy_routing_with(&plan, &mut |_program, args| {
        calls.push(args.to_vec());
        Err(LinuxError::Command {
            program: format!("ip {}", args.join(" ")),
            status: "exit status 2".into(),
            stderr: format!("injected cleanup failure for {}", args.join(" ")),
        })
    });

    assert_eq!(
        calls.len(),
        4,
        "both IPv4 resources on both interfaces must be attempted"
    );
    assert!(matches!(result, Err(LinuxError::Cleanup(message))
        if message.matches("injected cleanup failure").count() == 4));
    for interface in ["awg0", "wg1"] {
        let expected_mark = if interface == "awg0" {
            "0x80000001"
        } else {
            "0x80000002"
        };
        assert!(calls.iter().any(|args| {
            args.get(1).is_some_and(|v| v == "rule")
                && args.get(2).is_some_and(|v| v == "del")
                && args.iter().any(|v| v == expected_mark)
        }));
        assert!(calls.iter().any(|args| {
            args.get(1).is_some_and(|v| v == "route")
                && args.get(2).is_some_and(|v| v == "del")
                && args.iter().any(|v| v == interface)
        }));
    }
}

#[test]
fn policy_apply_aggregates_socket_rollback_failures_after_egress_rollback() {
    let mut plan = cleanup_test_plan();
    plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
    let mut calls = Vec::new();
    let mut install_failure_index = None;
    let result = apply_policy_routing_with(&plan, &mut |_program, args| {
        calls.push(args.to_vec());
        if install_failure_index.is_none()
            && args.get(1).is_some_and(|part| part == "rule")
            && args.get(2).is_some_and(|part| part == "add")
            && args.first().is_some_and(|family| family == "-4")
            && args.get(4).is_some_and(|priority| priority == "10001")
        {
            install_failure_index = Some(calls.len() - 1);
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected egress installation failure".into(),
            });
        }
        if let Some(index) = install_failure_index {
            let after_failure = &calls[index + 1..];
            let socket_cleanup_started = after_failure.iter().any(|call| {
                call.get(1).is_some_and(|part| part == "rule")
                    && call.get(2).is_some_and(|part| part == "del")
                    && call.get(4).is_some_and(|priority| priority == "9000")
            });
            if socket_cleanup_started {
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected socket rollback failure".into(),
                });
            }
        }
        Ok(())
    });

    let failure_index = install_failure_index.expect("egress install failure injected");
    let rollback_calls = &calls[failure_index + 1..];
    let egress_cleanup = rollback_calls
        .iter()
        .filter(|args| {
            args.get(2).is_some_and(|operation| operation == "del")
                && (args.get(1).is_some_and(|kind| kind == "route")
                    || args.get(4).is_some_and(|priority| priority == "10001"))
        })
        .count();
    let socket_cleanup = rollback_calls
        .iter()
        .filter(|args| {
            args.get(4).is_some_and(|priority| priority == "9000")
                && args.get(2).is_some_and(|operation| operation == "del")
        })
        .count();

    assert_eq!(
        egress_cleanup, 2,
        "nested IPv4 egress rollback must complete first"
    );
    assert_eq!(
        socket_cleanup, 2,
        "outer rollback must attempt every socket mark"
    );
    assert!(
        matches!(result, Err(LinuxError::Rollback { operation, rollback })
            if operation.contains("injected egress installation failure")
                && rollback.matches("injected socket rollback failure").count() == 2)
    );
}

#[test]
fn nested_policy_rollback_does_not_repeat_egress_cleanup() {
    let mut plan = cleanup_test_plan();
    plan.socket_marks = vec![0x1000_0001];
    let mut calls = Vec::new();
    let mut install_failed = false;
    let mut failure_index = None;
    let result = apply_policy_routing_with(&plan, &mut |_program, args| {
        calls.push(args.to_vec());
        if !install_failed
            && args.get(1).is_some_and(|v| v == "rule")
            && args.get(2).is_some_and(|v| v == "add")
            && args.get(4).is_some_and(|v| v == "10001")
            && args.first().is_some_and(|v| v == "-4")
        {
            install_failed = true;
            failure_index = Some(calls.len() - 1);
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected egress install failure".into(),
            });
        }
        if args.get(2).is_some_and(|v| v == "del") && args.get(1).is_some_and(|v| v == "route") {
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "injected egress rollback failure".into(),
            });
        }
        Ok(())
    });

    assert!(
        matches!(result, Err(LinuxError::Rollback { operation, rollback })
            if operation.contains("injected egress install failure")
                && rollback.contains("injected egress rollback failure"))
    );
    let egress_cleanup_calls = calls[failure_index.expect("install failure injected")..]
        .iter()
        .filter(|args| args.get(2).is_some_and(|v| v == "del") && args.iter().any(|v| v == "10001"))
        .count();
    assert_eq!(
        egress_cleanup_calls, 2,
        "IPv4 egress rollback must run exactly once"
    );
    let socket_cleanup_calls = calls[failure_index.expect("install failure injected")..]
        .iter()
        .filter(|args| {
            args.get(2).is_some_and(|v| v == "del") && args.get(4).is_some_and(|v| v == "9000")
        })
        .count();
    assert_eq!(
        socket_cleanup_calls, 1,
        "outer rollback must still clean the socket mark"
    );
}

#[test]
fn policy_cleanup_aggregates_socket_and_egress_failures() {
    let mut plan = cleanup_test_plan();
    plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
    let mut calls = Vec::new();
    let result = remove_policy_routing_with(&plan, &mut |_program, args| {
        calls.push(args.to_vec());
        let socket_rule = args.get(1).is_some_and(|kind| kind == "rule")
            && args.get(4).is_some_and(|priority| priority == "9000");
        let egress_rule = args.get(1).is_some_and(|kind| kind == "rule")
            && args.get(4).is_some_and(|priority| priority == "10001");
        let egress_route = args.get(1).is_some_and(|kind| kind == "route")
            && args.iter().any(|value| value == "10001");
        if socket_rule || egress_rule || egress_route {
            let category = if socket_rule { "socket" } else { "egress" };
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: format!("injected {category} cleanup failure"),
            });
        }
        Ok(())
    });

    let socket_calls = calls
        .iter()
        .filter(|args| {
            args.get(1).is_some_and(|kind| kind == "rule")
                && args.get(4).is_some_and(|priority| priority == "9000")
        })
        .count();
    let egress_calls = calls
        .iter()
        .filter(|args| {
            (args.get(1).is_some_and(|kind| kind == "rule")
                && args.get(4).is_some_and(|priority| priority == "10001"))
                || (args.get(1).is_some_and(|kind| kind == "route")
                    && args.iter().any(|value| value == "10001"))
        })
        .count();

    assert_eq!(socket_calls, 2, "all socket marks must be attempted");
    assert_eq!(
        egress_calls, 2,
        "the IPv4 egress route and rule must both be attempted"
    );
    assert!(matches!(result, Err(LinuxError::Cleanup(message))
        if message.matches("injected socket cleanup failure").count() == 2
            && message.matches("injected egress cleanup failure").count() == 2));
}

#[test]
fn nft_json_ownership_requires_the_exact_inert_owner_marker_rule() {
    let owned = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay"}},{"chain":{"family":"inet","table":"vpn_relay","name":"vpn_relay_owner"}},{"rule":{"family":"inet","table":"vpn_relay","chain":"vpn_relay_owner","comment":"managed by vpn-relay","expr":[{"return":null}]}}]}"#;
    assert!(table_is_owned(owned, "inet", "vpn_relay"));
    assert!(!table_is_owned(owned, "ip", "vpn_relay"));
    assert!(!table_is_owned(owned, "inet", "other_table"));

    let wrong_chain = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay"}},{"rule":{"family":"inet","table":"vpn_relay","chain":"input","comment":"managed by vpn-relay"}}]}"#;
    assert!(!table_is_owned(wrong_chain, "inet", "vpn_relay"));
    let wrong_comment = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay"}},{"rule":{"family":"inet","table":"vpn_relay","chain":"vpn_relay_owner","comment":"owned by someone else"}}]}"#;
    assert!(!table_is_owned(wrong_comment, "inet", "vpn_relay"));
    assert!(!table_is_owned("not json", "inet", "vpn_relay"));
}

#[test]
fn nft_apply_does_not_mutate_when_inspection_fails() {
    let plan = cleanup_test_plan();
    let mut apply_calls = 0;
    let result = apply_nft_with(
        &plan,
        &mut |_plan| {
            Err(LinuxError::Conflict {
                resource: "nft table inet vpn_relay".into(),
                details: "unowned table".into(),
            })
        },
        &mut |_payload| {
            apply_calls += 1;
            Ok(())
        },
    );

    assert!(matches!(result, Err(LinuxError::Conflict { .. })));
    assert_eq!(apply_calls, 0, "must not mutate an unowned table");
}

#[test]
fn nft_apply_creates_missing_table_with_typed_json_batch() {
    let plan = cleanup_test_plan();
    let mut submitted = None;
    apply_nft_with(&plan, &mut |_plan| Ok(false), &mut |payload| {
        submitted = Some(payload.to_owned());
        Ok(())
    })
    .unwrap();

    let document: serde_json::Value = serde_json::from_str(&submitted.unwrap()).unwrap();
    let objects = document["nftables"].as_array().unwrap();
    assert!(objects[0].get("delete").is_none());
    assert_eq!(objects[0]["add"]["table"]["family"], "inet");
    assert_eq!(objects[0]["add"]["table"]["name"], "vpn_relay");
    assert_eq!(objects[1]["add"]["chain"]["name"], "vpn_relay_owner");
    assert_eq!(objects[2]["add"]["rule"]["chain"], "vpn_relay_owner");
    assert_eq!(objects[2]["add"]["rule"]["comment"], "managed by vpn-relay");
    assert_eq!(objects[3]["add"]["set"]["name"], "managed_interfaces");
}

#[test]
fn nft_apply_replaces_owned_table_in_one_atomic_json_batch() {
    let plan = cleanup_test_plan();
    let mut submitted = None;
    let result = apply_nft_with(&plan, &mut |_plan| Ok(true), &mut |payload| {
        submitted = Some(payload.to_owned());
        Err(LinuxError::Command {
            program: "nft -j -f -".into(),
            status: "exit status 1".into(),
            stderr: "injected transaction failure".into(),
        })
    });

    let document: serde_json::Value = serde_json::from_str(&submitted.unwrap()).unwrap();
    let objects = document["nftables"].as_array().unwrap();
    assert_eq!(objects[0]["delete"]["table"]["family"], "inet");
    assert_eq!(objects[0]["delete"]["table"]["name"], "vpn_relay");
    assert_eq!(objects[3]["add"]["rule"]["comment"], "managed by vpn-relay");
    assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
        if stderr.contains("injected transaction failure")));
}

#[test]
fn nft_remove_does_not_delete_when_inspection_fails() {
    let plan = cleanup_test_plan();
    let mut delete_calls = 0;
    let result = remove_nft_with(
        &plan,
        &mut |_plan| {
            Err(LinuxError::Command {
                program: "nft -j list table".into(),
                status: "exit status 1".into(),
                stderr: "permission denied".into(),
            })
        },
        &mut |_payload| {
            delete_calls += 1;
            Ok(())
        },
    );

    assert!(matches!(
        result,
        Err(LinuxError::Command { ref stderr, .. }) if stderr == "permission denied"
    ));
    assert_eq!(
        delete_calls, 0,
        "delete must not run after failed inspection"
    );
}

#[test]
fn nft_remove_skips_missing_table_and_propagates_json_delete_failure() {
    let plan = cleanup_test_plan();
    let mut delete_calls = 0;
    remove_nft_with(&plan, &mut |_plan| Ok(false), &mut |_payload| {
        delete_calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(delete_calls, 0);

    let result = remove_nft_with(&plan, &mut |_plan| Ok(true), &mut |payload| {
        delete_calls += 1;
        let document: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(
            document["nftables"][0]["delete"]["table"]["name"],
            "vpn_relay"
        );
        Err(LinuxError::Command {
            program: "nft -j -f -".into(),
            status: "exit status 1".into(),
            stderr: "injected delete failure".into(),
        })
    });
    assert_eq!(delete_calls, 1);
    assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
        if stderr.contains("injected delete failure")));
}

fn ipv4_link_response(forwarding: u32) -> Vec<u8> {
    let mut devconf = vec![0u8; IPV4_DEVCONF_MAX * 4];
    devconf[0..4].copy_from_slice(&forwarding.to_ne_bytes());
    let mut inet = Vec::new();
    append_netlink_attribute(&mut inet, IFLA_INET_CONF, &devconf);
    let mut af_spec = Vec::new();
    append_netlink_attribute(&mut af_spec, AF_INET_ATTR | NLA_F_NESTED, &inet);
    let mut attributes = Vec::new();
    append_netlink_attribute(&mut attributes, IFLA_AF_SPEC | NLA_F_NESTED, &af_spec);
    build_link_message(RTM_NEWLINK, 0, 9, 1, &attributes).unwrap()
}

#[test]
fn rtnetlink_extended_ack_extracts_kernel_message() {
    let mut response = vec![0u8; 16];
    response[0..4].copy_from_slice(&40u32.to_ne_bytes());
    response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    response[6..8].copy_from_slice(&NLM_F_CAPPED.to_ne_bytes());
    response.extend_from_slice(&(-libc::EINVAL).to_ne_bytes());
    let mut original = [0u8; 16];
    original[0..4].copy_from_slice(&16u32.to_ne_bytes());
    response.extend_from_slice(&original);
    let message = b"invalid forwarding attribute\0";
    let attribute_length = 4 + message.len();
    response.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    response.extend_from_slice(&(NLMSGERR_ATTR_MSG | NLA_F_NET_BYTEORDER).to_ne_bytes());
    response.extend_from_slice(message);
    response.resize(align_netlink(response.len()), 0);
    let length = response.len();
    response[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    response[6..8].copy_from_slice(&(NLM_F_CAPPED | NLM_F_ACK_TLVS).to_ne_bytes());
    assert_eq!(
        netlink_extended_ack(&response, 0, length).as_deref(),
        Some("invalid forwarding attribute")
    );
}

#[test]
fn rtnetlink_extended_ack_extracts_uncapped_kernel_message() {
    let mut response = vec![0u8; 16];
    response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    response.extend_from_slice(&(-libc::EINVAL).to_ne_bytes());
    let mut original = [0u8; 16];
    original[0..4].copy_from_slice(&20u32.to_ne_bytes());
    response.extend_from_slice(&original);
    response.extend_from_slice(&[1, 2, 3, 4]);
    let message = b"invalid uncapped attribute\0";
    let attribute_length = 4 + message.len();
    response.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    response.extend_from_slice(&NLMSGERR_ATTR_MSG.to_ne_bytes());
    response.extend_from_slice(message);
    response.resize(align_netlink(response.len()), 0);
    let length = response.len();
    response[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    response[6..8].copy_from_slice(&NLM_F_ACK_TLVS.to_ne_bytes());
    assert_eq!(
        netlink_extended_ack(&response, 0, length).as_deref(),
        Some("invalid uncapped attribute")
    );
}

#[test]
fn rtnetlink_extended_ack_ignores_truncated_error_header() {
    let response = vec![0u8; 35];
    assert_eq!(netlink_extended_ack(&response, 0, response.len()), None);
}

#[test]
fn rtnetlink_extended_ack_ignores_malformed_attributes() {
    let mut response = vec![0u8; 36];
    response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    response[6..8].copy_from_slice(&(NLM_F_CAPPED | NLM_F_ACK_TLVS).to_ne_bytes());
    response[16..20].copy_from_slice(&(-libc::EINVAL).to_ne_bytes());
    response[20..24].copy_from_slice(&16u32.to_ne_bytes());
    response.extend_from_slice(&3u16.to_ne_bytes());
    response.extend_from_slice(&NLMSGERR_ATTR_MSG.to_ne_bytes());
    let length = response.len();
    response[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    assert_eq!(netlink_extended_ack(&response, 0, length), None);
}

#[test]
fn rtnetlink_ipv4_forwarding_readback_parses_kernel_devconf() {
    assert!(parse_link_ipv4_forwarding(&ipv4_link_response(1), 9).unwrap());
    assert!(!parse_link_ipv4_forwarding(&ipv4_link_response(0), 9).unwrap());
    assert!(matches!(
        parse_link_ipv4_forwarding(&ipv4_link_response(2), 9),
        Err(LinuxError::Conflict { .. })
    ));
}

#[test]
fn rtnetlink_ipv4_forwarding_rejects_response_for_different_ifindex() {
    let response = ipv4_link_response(1);
    assert!(matches!(
        parse_link_ipv4_forwarding(&response, 10),
        Err(LinuxError::Conflict { details, .. })
            if details.contains("ifindex 9")
    ));
}

#[test]
fn rtnetlink_ipv4_forwarding_rejects_truncated_devconf() {
    let mut inet = Vec::new();
    append_netlink_attribute(&mut inet, IFLA_INET_CONF, &[]);
    let mut af_spec = Vec::new();
    append_netlink_attribute(&mut af_spec, AF_INET_ATTR | NLA_F_NESTED, &inet);
    let mut attributes = Vec::new();
    append_netlink_attribute(&mut attributes, IFLA_AF_SPEC | NLA_F_NESTED, &af_spec);
    let response = build_link_message(RTM_NEWLINK, 0, 9, 1, &attributes).unwrap();
    assert!(matches!(
        parse_link_ipv4_forwarding(&response, 9),
        Err(LinuxError::Conflict { details, .. }) if details.contains("omitted")
    ));
}

#[test]
fn rtnetlink_forwarding_set_failure_matrix_stops_at_each_boundary() {
    for stage in [
        "identity_before_send",
        "send_or_ack",
        "readback",
        "identity_after_readback",
    ] {
        let mut verify_calls = 0usize;
        let mut request_calls = 0usize;
        let mut readback_calls = 0usize;
        let result = set_ipv4_interface_forwarding_with(
            "eth0",
            7,
            true,
            |_, _| {
                verify_calls += 1;
                if (stage == "identity_before_send" && verify_calls == 1)
                    || (stage == "identity_after_readback" && verify_calls == 2)
                {
                    Err(LinuxError::Conflict {
                        resource: "injected interface identity".into(),
                        details: format!("injected {stage} failure"),
                    })
                } else {
                    Ok(())
                }
            },
            |ifindex, message_type, flags, _| {
                request_calls += 1;
                assert_eq!(ifindex, 7);
                assert_eq!(message_type, RTM_NEWLINK);
                assert_eq!(flags, NLM_F_REQUEST | NLM_F_ACK);
                if stage == "send_or_ack" {
                    Err(LinuxError::Command {
                        program: "injected rtnetlink send/ACK".into(),
                        status: "failed".into(),
                        stderr: format!("injected {stage} failure"),
                    })
                } else {
                    Ok(Vec::new())
                }
            },
            |_| {
                readback_calls += 1;
                if stage == "readback" {
                    Err(LinuxError::Command {
                        program: "injected RTM_GETLINK readback".into(),
                        status: "failed".into(),
                        stderr: format!("injected {stage} failure"),
                    })
                } else {
                    Ok(true)
                }
            },
        );
        assert!(result.is_err(), "{stage} failure was not propagated");
        assert_eq!(
            verify_calls,
            if stage == "identity_after_readback" {
                2
            } else {
                1
            },
            "unexpected identity check count for {stage}"
        );
        assert_eq!(
            request_calls,
            if stage == "identity_before_send" {
                0
            } else {
                1
            },
            "unsafe or missing RTM_NEWLINK request for {stage}"
        );
        assert_eq!(
            readback_calls,
            if matches!(stage, "readback" | "identity_after_readback") {
                1
            } else {
                0
            },
            "unexpected RTM_GETLINK readback count for {stage}"
        );
    }
}

#[test]
fn rtnetlink_forwarding_set_rejects_acknowledged_value_mismatch() {
    let mut verify_calls = 0usize;
    let result = set_ipv4_interface_forwarding_with(
        "eth0",
        7,
        true,
        |_, _| {
            verify_calls += 1;
            Ok(())
        },
        |_, _, _, _| Ok(Vec::new()),
        |_| Ok(false),
    );
    assert!(matches!(
        result,
        Err(LinuxError::Conflict { details, .. })
            if details.contains("reports forwarding=0")
    ));
    assert_eq!(verify_calls, 2);
}

#[test]
fn rtnetlink_reads_loopback_ipv4_forwarding_by_ifindex() {
    let index = interface_index("lo").expect("loopback interface exists");
    let netlink_value = ipv4_interface_forwarding(index).unwrap();
    let sysctl_value = std::fs::read_to_string("/proc/sys/net/ipv4/conf/lo/forwarding")
        .unwrap()
        .trim()
        == "1";
    assert_eq!(netlink_value, sysctl_value);
}

#[test]
fn interface_name_round_trips_current_network_namespace_identity() {
    let index = interface_index("lo").expect("loopback interface exists");
    assert_eq!(interface_name(index).unwrap(), "lo");
    verify_interface_identity("lo", index).unwrap();
}

#[test]
fn interface_identity_rejects_zero_and_mismatched_links() {
    assert!(matches!(
        interface_name(0),
        Err(LinuxError::Conflict { .. })
    ));
    let index = interface_index("lo").unwrap();
    assert!(matches!(
        verify_interface_identity("lo", index.saturating_add(1)),
        Err(LinuxError::Conflict { .. }) | Err(LinuxError::Command { .. })
    ));
}

#[test]
fn interface_identity_rejects_reused_names_and_indices() {
    let name_reused =
        verify_interface_identity_with("eth0", 7, |_| Ok(9), |_| Ok("eth0".to_owned()));
    assert!(matches!(name_reused, Err(LinuxError::Conflict { .. })));

    let index_reused =
        verify_interface_identity_with("eth0", 7, |_| Ok(7), |_| Ok("eth1".to_owned()));
    assert!(matches!(index_reused, Err(LinuxError::Conflict { .. })));

    verify_interface_identity_with("eth0", 7, |_| Ok(7), |_| Ok("eth0".to_owned())).unwrap();
}

#[test]
fn interface_identity_propagates_missing_link_lookup_errors() {
    let missing_name = verify_interface_identity_with(
        "eth0",
        7,
        |_| {
            Err(LinuxError::Conflict {
                resource: "network interface 'eth0'".into(),
                details: "interface disappeared".into(),
            })
        },
        |_| Ok("eth0".to_owned()),
    );
    assert!(matches!(
        missing_name,
        Err(LinuxError::Conflict { details, .. }) if details == "interface disappeared"
    ));

    let missing_index = verify_interface_identity_with(
        "eth0",
        7,
        |_| Ok(7),
        |_| {
            Err(LinuxError::Conflict {
                resource: "network interface index 7".into(),
                details: "interface index disappeared".into(),
            })
        },
    );
    assert!(matches!(
        missing_index,
        Err(LinuxError::Conflict { details, .. }) if details == "interface index disappeared"
    ));
}

#[test]
fn nft_ownership_requires_exact_owner_chain_rule_and_table_identity() {
    let owned = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay"}},{"rule":{"family":"inet","table":"vpn_relay","chain":"vpn_relay_owner","comment":"managed by vpn-relay","expr":[{"return":null}]}}]}"#;
    assert!(table_is_owned(owned, "inet", "vpn_relay"));
    assert!(!table_is_owned(owned, "ip", "vpn_relay"));
    assert!(!table_is_owned(owned, "inet", "other"));
    let wrong_chain = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay"}},{"rule":{"family":"inet","table":"vpn_relay","chain":"input","comment":"managed by vpn-relay"}}]}"#;
    assert!(!table_is_owned(wrong_chain, "inet", "vpn_relay"));
    assert!(!table_is_owned("not json", "inet", "vpn_relay"));
}

#[test]
fn recognizes_only_exact_daemon_owned_ip_rules() {
    assert!(rule_has_owned_identity(
        "10000: from all fwmark 0x80000000 lookup 10000 proto 242",
        0x8000_0000,
        "10000"
    ));
    assert!(!rule_has_owned_identity(
        "10000: from all fwmark 0x80000000 lookup 10000",
        0x8000_0000,
        "10000"
    ));
    assert!(!rule_has_owned_identity(
        "10000: from all fwmark 0x80000001 lookup 10000 proto 242",
        0x8000_0000,
        "10000"
    ));
    assert!(!rule_has_owned_identity(
        "10000: from all fwmark 0x80000000 lookup 10001 proto 242",
        0x8000_0000,
        "10000"
    ));
}

#[test]
fn detects_ip_rules_that_shadow_or_overlap_reserved_fwmarks() {
    assert!(rule_matches_fwmark(
        "100: from all fwmark 0x80000000 lookup 10000",
        0x8000_0000
    ));
    assert!(rule_matches_fwmark(
        "100: from all fwmark 0x80000000/0xffff0000 lookup 10000",
        0x8000_0001
    ));
    assert!(rule_matches_fwmark(
        "100: from all fwmark 0x0/0x0 lookup main",
        0x8000_0001
    ));
    assert!(!rule_matches_fwmark(
        "100: from all fwmark 0x80000001 lookup 10000",
        0x8000_0000
    ));
    assert!(!rule_matches_fwmark(
        "100: from all lookup 10000",
        0x8000_0000
    ));
}

#[test]
fn recognizes_owned_default_routes_and_kernel_metadata() {
    assert!(route_has_owned_identity(
        "default dev awg-primary proto 242",
        "awg-primary"
    ));
    assert!(route_has_owned_identity(
        "default dev awg-primary proto 242 metric 1024 pref medium",
        "awg-primary"
    ));
    assert!(!route_has_owned_identity(
        "default dev awg-primary",
        "awg-primary"
    ));
    assert!(!route_has_owned_identity(
        "default via 192.0.2.1 dev awg-primary proto 242",
        "awg-primary"
    ));
    assert!(!route_has_owned_identity(
        "default dev awg-secondary proto 242",
        "awg-primary"
    ));
    assert!(!route_has_owned_identity(
        "default dev awg-primary proto 242 mtu 1400",
        "awg-primary"
    ));
}

