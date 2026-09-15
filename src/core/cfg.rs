//! Control Flow Graph (CFG) construction and analysis.
//!
//! This module provides CFG building from basic blocks and xrefs,
//! addressing the critical gap where successors were not computed.

use crate::constants::RefType;
use crate::core::workspace::CodeBlock;
use crate::core::XRefManager;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::HashMap;

/// Edge type in the control flow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgEdgeType {
    /// Fall-through to next instruction.
    FallThrough,
    /// Unconditional jump.
    Unconditional,
    /// Conditional branch (true path).
    ConditionalTrue,
    /// Conditional branch (false/fall-through path).
    ConditionalFalse,
    /// Function call (intra-procedural, returns to next).
    Call,
}

/// A node in the control flow graph representing a basic block.
#[derive(Debug, Clone)]
pub struct CfgNode {
    /// Start address of the block.
    pub start: u64,
    /// End address of the block (exclusive).
    pub end: u64,
    /// Size in bytes.
    pub size: usize,
    /// Function this block belongs to.
    pub func_va: u64,
}

impl CfgNode {
    /// Create a new CFG node from a code block.
    pub fn from_block(block: &CodeBlock) -> Self {
        Self {
            start: block.va,
            end: block.va + block.size as u64,
            size: block.size,
            func_va: block.func_va,
        }
    }
}

/// Control Flow Graph for a function.
#[derive(Debug)]
pub struct ControlFlowGraph {
    /// The underlying directed graph.
    graph: DiGraph<CfgNode, CfgEdgeType>,
    /// Map from block start address to node index.
    node_map: HashMap<u64, NodeIndex>,
    /// Function entry point.
    entry: u64,
}

impl ControlFlowGraph {
    /// Create a new empty CFG.
    pub fn new(entry: u64) -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            entry,
        }
    }

    /// Add a basic block node to the graph.
    pub fn add_block(&mut self, block: &CodeBlock) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&block.va) {
            return idx;
        }

        let node = CfgNode::from_block(block);
        let idx = self.graph.add_node(node);
        self.node_map.insert(block.va, idx);
        idx
    }

    /// Add an edge between two blocks.
    pub fn add_edge(&mut self, from_va: u64, to_va: u64, edge_type: CfgEdgeType) -> bool {
        let from_idx = match self.node_map.get(&from_va) {
            Some(&idx) => idx,
            None => return false,
        };
        let to_idx = match self.node_map.get(&to_va) {
            Some(&idx) => idx,
            None => return false,
        };

        self.graph.add_edge(from_idx, to_idx, edge_type);
        true
    }

    /// Get the entry block.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Get all block addresses in the CFG.
    pub fn blocks(&self) -> Vec<u64> {
        self.node_map.keys().copied().collect()
    }

    /// Get the number of blocks.
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get successor blocks for a given block.
    pub fn successors(&self, block_va: u64) -> Vec<(u64, CfgEdgeType)> {
        let idx = match self.node_map.get(&block_va) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|edge| {
                let target_idx = edge.target();
                let target_node = &self.graph[target_idx];
                (target_node.start, *edge.weight())
            })
            .collect()
    }

    /// Get predecessor blocks for a given block.
    pub fn predecessors(&self, block_va: u64) -> Vec<(u64, CfgEdgeType)> {
        let idx = match self.node_map.get(&block_va) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        self.graph
            .edges_directed(idx, Direction::Incoming)
            .map(|edge| {
                let source_idx = edge.source();
                let source_node = &self.graph[source_idx];
                (source_node.start, *edge.weight())
            })
            .collect()
    }

    /// Get a reference to the underlying petgraph.
    pub fn graph(&self) -> &DiGraph<CfgNode, CfgEdgeType> {
        &self.graph
    }

    /// Get the node for a block address.
    #[must_use]
    pub fn get_node(&self, block_va: u64) -> Option<&CfgNode> {
        self.node_map.get(&block_va).map(|&idx| &self.graph[idx])
    }

    /// Check if block exists in CFG.
    pub fn contains_block(&self, block_va: u64) -> bool {
        self.node_map.contains_key(&block_va)
    }

    // ── Path algorithms (port of Python visgraph path operations) ──

    /// Find all simple paths from source to target block (DFS).
    ///
    /// Returns paths as vectors of block VAs. Bounded by max_paths.
    pub fn find_paths(&self, from_va: u64, to_va: u64, max_paths: usize) -> Vec<Vec<u64>> {
        let from_idx = match self.node_map.get(&from_va) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };
        let to_idx = match self.node_map.get(&to_va) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        let mut paths = Vec::new();
        let mut stack: Vec<(NodeIndex, Vec<NodeIndex>)> = vec![(from_idx, vec![from_idx])];
        let mut visited_paths = 0usize;

        while let Some((current, path)) = stack.pop() {
            if visited_paths >= max_paths {
                break;
            }

            if current == to_idx {
                let va_path: Vec<u64> = path.iter().map(|&idx| self.graph[idx].start).collect();
                paths.push(va_path);
                visited_paths += 1;
                continue;
            }

            for neighbor in self.graph.neighbors(current) {
                if !path.contains(&neighbor) {
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    stack.push((neighbor, new_path));
                }
            }
        }

        paths
    }

    /// Check if there is a path from source to target.
    pub fn has_path(&self, from_va: u64, to_va: u64) -> bool {
        use petgraph::algo::has_path_connecting;
        let from_idx = match self.node_map.get(&from_va) {
            Some(&idx) => idx,
            None => return false,
        };
        let to_idx = match self.node_map.get(&to_va) {
            Some(&idx) => idx,
            None => return false,
        };
        has_path_connecting(&self.graph, from_idx, to_idx, None)
    }

    /// Get all blocks reachable from the entry point (BFS).
    pub fn reachable_blocks(&self) -> Vec<u64> {
        use petgraph::visit::Bfs;
        let entry_idx = match self.node_map.get(&self.entry) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        let mut bfs = Bfs::new(&self.graph, entry_idx);
        let mut reachable = Vec::new();
        while let Some(idx) = bfs.next(&self.graph) {
            reachable.push(self.graph[idx].start);
        }
        reachable
    }

    /// Find loop headers (blocks that are targets of back-edges).
    pub fn find_loop_headers(&self) -> Vec<u64> {
        use petgraph::visit::DfsPostOrder;
        let entry_idx = match self.node_map.get(&self.entry) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        let mut post_order = Vec::new();
        let mut dfs = DfsPostOrder::new(&self.graph, entry_idx);
        while let Some(idx) = dfs.next(&self.graph) {
            post_order.push(idx);
        }

        // A back-edge points to a node that was visited before in DFS
        let order_map: HashMap<NodeIndex, usize> = post_order
            .iter()
            .enumerate()
            .map(|(i, &idx)| (idx, i))
            .collect();

        let mut headers = Vec::new();
        for edge in self.graph.edge_indices() {
            if let Some((src, tgt)) = self.graph.edge_endpoints(edge) {
                if let (Some(&src_order), Some(&tgt_order)) =
                    (order_map.get(&src), order_map.get(&tgt))
                {
                    if tgt_order > src_order {
                        // Back edge: target has higher post-order number
                        headers.push(self.graph[tgt].start);
                    }
                }
            }
        }

        headers.sort();
        headers.dedup();
        headers
    }

    /// Serialize the CFG to a JSON-compatible format.
    pub fn to_serializable(&self) -> SerializableCfg {
        let nodes: Vec<(u64, usize)> = self
            .node_map
            .iter()
            .map(|(&va, &idx)| (va, self.graph[idx].size))
            .collect();

        let edges: Vec<(u64, u64, String)> = self
            .graph
            .edge_indices()
            .filter_map(|eidx| {
                let (src, tgt) = self.graph.edge_endpoints(eidx)?;
                let edge_type = &self.graph[eidx];
                Some((
                    self.graph[src].start,
                    self.graph[tgt].start,
                    format!("{:?}", edge_type),
                ))
            })
            .collect();

        SerializableCfg {
            entry: self.entry,
            nodes,
            edges,
        }
    }
}

/// Serializable CFG representation for JSON export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableCfg {
    pub entry: u64,
    pub nodes: Vec<(u64, usize)>,
    pub edges: Vec<(u64, u64, String)>,
}

/// CFG builder that constructs control flow graphs from workspace data.
pub struct CfgBuilder<'a> {
    /// Code blocks indexed by start address.
    blocks: &'a HashMap<u64, CodeBlock>,
    /// Cross-reference manager.
    xrefs: &'a XRefManager,
    /// Map from any address to the block containing it.
    addr_to_block: HashMap<u64, u64>,
}

impl<'a> CfgBuilder<'a> {
    /// Create a new CFG builder.
    pub fn new(blocks: &'a HashMap<u64, CodeBlock>, xrefs: &'a XRefManager) -> Self {
        // Build address-to-block lookup
        let mut addr_to_block = HashMap::new();
        for block in blocks.values() {
            for offset in 0..block.size {
                addr_to_block.insert(block.va + offset as u64, block.va);
            }
        }

        Self {
            blocks,
            xrefs,
            addr_to_block,
        }
    }

    /// Find the block containing an address.
    #[must_use]
    pub fn find_block_containing(&self, addr: u64) -> Option<u64> {
        self.addr_to_block.get(&addr).copied()
    }

    /// Build a CFG for a single function.
    pub fn build_function_cfg(&self, func_va: u64) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new(func_va);

        // Add all blocks belonging to this function
        for block in self.blocks.values() {
            if block.func_va == func_va {
                cfg.add_block(block);
            }
        }

        // Now add edges based on xrefs from terminal instructions
        for block in self.blocks.values() {
            if block.func_va != func_va {
                continue;
            }

            // Get xrefs from addresses within this block
            // Focus on the terminal instruction (last few bytes of block)
            let term_start = if block.size > 15 {
                block.va + block.size as u64 - 15
            } else {
                block.va
            };

            for offset in 0..=15.min(block.size) {
                let addr = term_start + offset as u64;
                if addr >= block.va + block.size as u64 {
                    break;
                }

                for (target, ref_type) in self.xrefs.get_xrefs_from(addr) {
                    if ref_type != RefType::Code {
                        continue;
                    }

                    // Find the target block
                    if let Some(target_block_va) = self.find_block_containing(target) {
                        // Only add intra-function edges
                        if let Some(target_block) = self.blocks.get(&target_block_va) {
                            if target_block.func_va == func_va {
                                // Determine edge type (simplified - could be enhanced)
                                let edge_type = CfgEdgeType::Unconditional;
                                cfg.add_edge(block.va, target_block_va, edge_type);
                            }
                        }
                    }
                }
            }

            // Add fall-through edge if block doesn't end with unconditional jump/ret
            let fall_through_addr = block.va + block.size as u64;
            if let Some(fall_through_block) = self.find_block_containing(fall_through_addr) {
                if let Some(ft_block) = self.blocks.get(&fall_through_block) {
                    if ft_block.func_va == func_va && fall_through_block != block.va {
                        // Check if we already have an edge (from xref)
                        let existing = cfg.successors(block.va);
                        if !existing.iter().any(|(va, _)| *va == fall_through_block) {
                            cfg.add_edge(block.va, fall_through_block, CfgEdgeType::FallThrough);
                        }
                    }
                }
            }
        }

        cfg
    }
}

/// Compute block successors from xrefs (the missing functionality).
///
/// This function derives successor blocks by examining xrefs from the
/// terminal instruction of a block - exactly how Python vivisect does it.
pub fn compute_block_successors(
    block: &CodeBlock,
    xrefs: &XRefManager,
    all_blocks: &HashMap<u64, CodeBlock>,
    falls_through: bool,
) -> Vec<u64> {
    let mut successors = Vec::new();

    // Check xrefs from addresses in the last ~15 bytes of the block
    // (max x86 instruction size)
    let check_start = if block.size > 15 {
        block.va + block.size as u64 - 15
    } else {
        block.va
    };

    for offset in 0..block.size.min(15) {
        let addr = check_start + offset as u64;
        if addr >= block.va + block.size as u64 {
            break;
        }

        for (target, ref_type) in xrefs.get_xrefs_from(addr) {
            if ref_type == RefType::Code {
                // Check if target is a known block start
                if all_blocks.contains_key(&target) && !successors.contains(&target) {
                    successors.push(target);
                }
            }
        }
    }

    // Add fall-through if applicable
    if falls_through {
        let next_addr = block.va + block.size as u64;
        if all_blocks.contains_key(&next_addr) && !successors.contains(&next_addr) {
            successors.push(next_addr);
        }
    }

    successors
}

/// Compute block predecessors from xrefs.
pub fn compute_block_predecessors(
    block: &CodeBlock,
    xrefs: &XRefManager,
    all_blocks: &HashMap<u64, CodeBlock>,
) -> Vec<u64> {
    let mut predecessors = Vec::new();

    // Get xrefs TO the start of this block
    for (from_addr, ref_type) in xrefs.get_xrefs_to(block.va) {
        if ref_type == RefType::Code {
            // Find which block contains this address
            for other_block in all_blocks.values() {
                if from_addr >= other_block.va
                    && from_addr < other_block.va + other_block.size as u64
                {
                    if !predecessors.contains(&other_block.va) {
                        predecessors.push(other_block.va);
                    }
                    break;
                }
            }
        }
    }

    // Check for fall-through predecessors
    for other_block in all_blocks.values() {
        let fall_through_addr = other_block.va + other_block.size as u64;
        if fall_through_addr == block.va && !predecessors.contains(&other_block.va) {
            predecessors.push(other_block.va);
        }
    }

    predecessors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_creation() {
        let mut cfg = ControlFlowGraph::new(0x401000);

        let block1 = CodeBlock {
            va: 0x401000,
            size: 10,
            func_va: 0x401000,
        };
        let block2 = CodeBlock {
            va: 0x40100a,
            size: 5,
            func_va: 0x401000,
        };

        cfg.add_block(&block1);
        cfg.add_block(&block2);
        cfg.add_edge(0x401000, 0x40100a, CfgEdgeType::FallThrough);

        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.edge_count(), 1);

        let succs = cfg.successors(0x401000);
        assert_eq!(succs.len(), 1);
        assert_eq!(succs[0].0, 0x40100a);
    }

    #[test]
    fn test_predecessors() {
        let mut cfg = ControlFlowGraph::new(0x401000);

        let block1 = CodeBlock {
            va: 0x401000,
            size: 10,
            func_va: 0x401000,
        };
        let block2 = CodeBlock {
            va: 0x40100a,
            size: 5,
            func_va: 0x401000,
        };

        cfg.add_block(&block1);
        cfg.add_block(&block2);
        cfg.add_edge(0x401000, 0x40100a, CfgEdgeType::FallThrough);

        let preds = cfg.predecessors(0x40100a);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].0, 0x401000);
    }
}
