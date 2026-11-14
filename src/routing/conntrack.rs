//! Durable conntrack decision identity allocation and history validation.

use super::{RoutingDecision, RoutingPlan};

const FIRST_CONNTRACK_MARK: u32 = 0x5000_0000;
const LEGACY_CONNTRACK_MARK: u32 = 0x4000_0000;

/// Assign decision marks without reusing an ID that may still exist in
/// conntrack. The history is persisted for the lifetime of the network
/// namespace, so a daemon restart with a changed config cannot reinterpret
/// old conntrack entries as a different routing decision.
pub(super) fn assign_stable_conntrack_marks(
plan: &mut RoutingPlan,
history: &mut Vec<RoutingDecision>,
) -> Result<(), String> {
    validate_conntrack_mark_history(history)?;

    let mut used_marks: std::collections::BTreeSet<u32> = history
        .iter()
        .map(|decision| decision.conntrack_mark)
        .collect();

    for decision in &mut plan.decisions {
        let mut key = decision.clone();
        key.conntrack_mark = 0;
        // Routing marks are implementation details of the current policy
        // routing table allocation. Keep the conntrack decision identity
        // stable when mark_base changes so established flows can be
        // remapped by the new nftables prerouting rules without losing
        // their decision during an atomic policy switch.
        key.routing_mark = 0;
        let existing_mark = history.iter().find_map(|previous| {
            let mut previous_key = previous.clone();
            previous_key.conntrack_mark = 0;
            previous_key.routing_mark = 0;
            (previous_key == key).then_some(previous.conntrack_mark)
        });

        if let Some(mark) = existing_mark {
            decision.conntrack_mark = mark;
            continue;
        }

        let (_id, mark) = (1..=0x0fff)
            .map(|id| (id, FIRST_CONNTRACK_MARK | (id << 16)))
            .find(|(_, mark)| !used_marks.contains(mark))
            .ok_or_else(|| {
                "all 4095 vpn-relay conntrack decision IDs are reserved; existing conntrack entries must expire before new routing decisions can be added"
                    .to_owned()
            })?;
        used_marks.insert(mark);
        decision.conntrack_mark = mark;
        history.push(decision.clone());
    }

    Ok(())
}

/// Reject corrupted or ambiguous persisted history instead of risking
/// reuse of a mark that could still identify an older connection.
pub(super) fn validate_conntrack_mark_history(
history: &[RoutingDecision],
) -> Result<(), String> {
    let mut used_marks = std::collections::BTreeSet::new();
    let mut keys = Vec::with_capacity(history.len());

    for decision in history {
        let mark = decision.conntrack_mark;
        let id = (mark & 0x0fff_0000) >> 16;
        let namespace = mark & 0xf000_0000;
        if (namespace != FIRST_CONNTRACK_MARK && namespace != LEGACY_CONNTRACK_MARK)
            || mark & 0x0000_ffff != 0
            || id == 0
            || id > 0x0fff
            || !used_marks.insert(mark)
        {
            return Err(format!(
                "invalid or duplicate persisted conntrack decision mark 0x{mark:08x}"
            ));
        }

        // Older versions allocated a new conntrack ID when routing
        // mark_base changed. Preserve compatibility with those valid
        // historical aliases: only an exact decision duplicate (including
        // its routing mark) is ambiguous. The active plan still reuses the
        // first matching conntrack ID independent of routing_mark.
        let mut key = decision.clone();
        key.conntrack_mark = 0;
        if keys.contains(&key) {
            return Err("duplicate persisted conntrack decision identity".to_owned());
        }
        keys.push(key);
    }

    Ok(())
}
