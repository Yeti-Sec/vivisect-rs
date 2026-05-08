//! Call graph construction and analysis.
//!
//! This module provides the CallGraph structure for tracking
//! function call relationships, similar to Python vivisect's _call_graph.

use crate::constants::RefType;
use crate::core::XRefManager;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

/// A call graph representing function call relationships.
#[derive(Debug)]
pub struct CallGraph {
    /// The underlying directed graph.
    /// Nodes are function VAs, edges represent calls.
    graph: DiGraph<u64, CallEdgeInfo>,
    /// Map from function VA to node index.
    node_map: HashMap<u64, NodeIndex>,
}

/// Information about a call edge.
#[derive(Debug, Clone)]
pub struct CallEdgeInfo {
    /// Call site address (where the call instruction is).
    pub call_site: u64,
    /// Whether this is a direct or indirect call.
    pub is_direct: bool,
}

impl CallGraph {
    /// Create a new empty call graph.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    /// Add a function to the call graph.
    pub fn add_function(&mut self, func_va: u64) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&func_va) {
            return idx;
        }
        let idx = self.graph.add_node(func_va);
        self.node_map.insert(func_va, idx);
        idx
    }

    /// Add a call edge between two functions.
    ///
    /// # Arguments
    /// * `caller` - The calling function's VA
    /// * `callee` - The called function's VA
    /// * `call_site` - Address of the call instruction
    /// * `is_direct` - Whether this is a direct call (not through register/memory)
    pub fn add_call(
        &mut self,
        caller: u64,
        callee: u64,
        call_site: u64,
        is_direct: bool,
    ) {
        let caller_idx = self.add_function(caller);
        let callee_idx = self.add_function(callee);

        self.graph.add_edge(
            caller_idx,
            callee_idx,
            CallEdgeInfo {
                call_site,
                is_direct,
            },
        );
    }

    /// Get all functions that call the given function (callers/incoming).
    pub fn get_callers(&self, func_va: u64) -> Vec<(u64, CallEdgeInfo)> {
        let idx = match self.node_map.get(&func_va) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        self.graph
            .edges_directed(idx, Direction::Incoming)
            .map(|edge| {
                let caller_idx = edge.source();
                let caller_va = self.graph[caller_idx];
                (caller_va, edge.weight().clone())
            })
            .collect()
    }

    /// Get all functions called by the given function (callees/outgoing).
    pub fn get_callees(&self, func_va: u64) -> Vec<(u64, CallEdgeInfo)> {
        let idx = match self.node_map.get(&func_va) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|edge| {
                let callee_idx = edge.target();
                let callee_va = self.graph[callee_idx];
                (callee_va, edge.weight().clone())
            })
            .collect()
    }

    /// Get just the caller function addresses.
    pub fn get_caller_vas(&self, func_va: u64) -> Vec<u64> {
        self.get_callers(func_va)
            .into_iter()
            .map(|(va, _)| va)
            .collect()
    }

    /// Get just the callee function addresses.
    pub fn get_callee_vas(&self, func_va: u64) -> Vec<u64> {
        self.get_callees(func_va)
            .into_iter()
            .map(|(va, _)| va)
            .collect()
    }

    /// Get all functions in the call graph.
    pub fn get_functions(&self) -> Vec<u64> {
        self.node_map.keys().copied().collect()
    }

    /// Get the number of functions.
    pub fn function_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of call edges.
    pub fn call_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Check if a function exists in the call graph.
    pub fn contains_function(&self, func_va: u64) -> bool {
        self.node_map.contains_key(&func_va)
    }

    /// Get a reference to the underlying petgraph.
    pub fn graph(&self) -> &DiGraph<u64, CallEdgeInfo> {
        &self.graph
    }

    /// Find root functions (functions with no callers).
    pub fn find_roots(&self) -> Vec<u64> {
        self.node_map
            .iter()
            .filter(|(_, &idx)| {
                self.graph
                    .edges_directed(idx, Direction::Incoming)
                    .next()
                    .is_none()
            })
            .map(|(&va, _)| va)
            .collect()
    }

    /// Find leaf functions (functions that don't call anything).
    pub fn find_leaves(&self) -> Vec<u64> {
        self.node_map
            .iter()
            .filter(|(_, &idx)| {
                self.graph
                    .edges_directed(idx, Direction::Outgoing)
                    .next()
                    .is_none()
            })
            .map(|(&va, _)| va)
            .collect()
    }

    /// Find recursive functions (functions that call themselves).
    pub fn find_recursive(&self) -> Vec<u64> {
        self.node_map
            .iter()
            .filter(|(&va, &idx)| {
                self.graph
                    .edges_directed(idx, Direction::Outgoing)
                    .any(|edge| self.graph[edge.target()] == va)
            })
            .map(|(&va, _)| va)
            .collect()
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing a call graph from workspace data.
pub struct CallGraphBuilder<'a> {
    xrefs: &'a XRefManager,
    functions: &'a HashSet<u64>,
}

impl<'a> CallGraphBuilder<'a> {
    /// Create a new call graph builder.
    pub fn new(xrefs: &'a XRefManager, functions: &'a HashSet<u64>) -> Self {
        Self { xrefs, functions }
    }

    /// Build the call graph by analyzing xrefs.
    ///
    /// This looks for Code xrefs where the target is a known function,
    /// and the source is within a different function.
    pub fn build(&self, func_to_block: &HashMap<u64, u64>) -> CallGraph {
        let mut cg = CallGraph::new();

        // Add all functions
        for &func_va in self.functions {
            cg.add_function(func_va);
        }

        // Analyze xrefs to find calls
        for source_va in self.xrefs.get_xref_sources() {
            for (target_va, ref_type) in self.xrefs.get_xrefs_from(source_va) {
                if ref_type != RefType::Code {
                    continue;
                }

                // Check if target is a function entry
                if !self.functions.contains(&target_va) {
                    continue;
                }

                // Find which function contains the source address
                if let Some(&caller_func) = func_to_block.get(&source_va) {
                    if caller_func != target_va {
                        // This is a call from one function to another
                        cg.add_call(caller_func, target_va, source_va, true);
                    }
                }
            }
        }

        cg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callgraph_creation() {
        let mut cg = CallGraph::new();

        cg.add_call(0x401000, 0x402000, 0x401050, true);
        cg.add_call(0x401000, 0x403000, 0x401080, true);
        cg.add_call(0x402000, 0x403000, 0x402010, true);

        assert_eq!(cg.function_count(), 3);
        assert_eq!(cg.call_count(), 3);

        // Test callers
        let callers = cg.get_caller_vas(0x403000);
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&0x401000));
        assert!(callers.contains(&0x402000));

        // Test callees
        let callees = cg.get_callee_vas(0x401000);
        assert_eq!(callees.len(), 2);
    }

    #[test]
    fn test_roots_and_leaves() {
        let mut cg = CallGraph::new();

        // main -> helper -> leaf
        cg.add_call(0x401000, 0x402000, 0x401010, true);
        cg.add_call(0x402000, 0x403000, 0x402010, true);

        let roots = cg.find_roots();
        assert_eq!(roots.len(), 1);
        assert!(roots.contains(&0x401000));

        let leaves = cg.find_leaves();
        assert_eq!(leaves.len(), 1);
        assert!(leaves.contains(&0x403000));
    }

    #[test]
    fn test_recursive() {
        let mut cg = CallGraph::new();

        // Self-recursive function
        cg.add_call(0x401000, 0x401000, 0x401050, true);
        cg.add_call(0x401000, 0x402000, 0x401010, true);

        let recursive = cg.find_recursive();
        assert_eq!(recursive.len(), 1);
        assert!(recursive.contains(&0x401000));
    }
}
