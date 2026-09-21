//! Build human-readable blocking chains for unresolved objects.

use std::collections::HashSet;

use super::graph::{CandidateNode, Graph};

/// Describe why `id` cannot be reconstructed: walk its delta base links and
/// stop at the first missing/failed dependency. Cycles are rendered once.
pub fn blocking_chain(graph: &Graph, id: i64) -> String {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = Some(id);
    let mut hops = 0;
    while let Some(node_id) = cur {
        if !seen.insert(node_id) {
            out.push(format!("{} (cycle)", label(graph, node_id)));
            break;
        }
        out.push(label(graph, node_id));
        let node = match graph.nodes.get(&node_id) {
            Some(n) => n,
            None => {
                out.push("missing-candidate".into());
                break;
            }
        };
        if let Some(err) = &node.parse_error {
            out.push(format!("error: {err}"));
            break;
        }
        match next_base(graph, node) {
            Ok(Some(next)) => cur = Some(next),
            Ok(None) => break,
            Err(missing) => {
                out.push(missing);
                break;
            }
        }
        hops += 1;
        if hops > 200 {
            out.push("chain too long".into());
            break;
        }
    }
    out.join(" -> ")
}

fn next_base(graph: &Graph, node: &CandidateNode) -> Result<Option<i64>, String> {
    if let Some(offset) = node.base_offset {
        return match graph.by_pack_offset.get(&(node.source_id, offset)) {
            Some(id) => Ok(Some(*id)),
            None => Err(format!(
                "missing ofs-base@pack-offset {offset} (source {})",
                node.source_id
            )),
        };
    }
    if let Some(oid) = &node.base_ref {
        return match graph.best_for(oid) {
            Some(n) => Ok(Some(n.id)),
            None => Err(format!("missing ref-base {oid}")),
        };
    }
    Ok(None)
}

fn label(graph: &Graph, id: i64) -> String {
    match graph.nodes.get(&id) {
        Some(n) => {
            let oid = if n.oid.is_empty() { "?" } else { &n.oid[..8] };
            format!("{}({oid})@{}", n.kind_name, n.locator)
        }
        None => format!("candidate#{id}"),
    }
}
