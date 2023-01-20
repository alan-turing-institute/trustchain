use crate::chain::{Chain, DIDChain, PrettyDID};
use petgraph::dot::{Config, Dot};
use petgraph::graph::DiGraph;
use std::collections::HashMap;
use std::fmt::Display;
use thiserror::Error;

/// An error relating to Trustchain graphs.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GraphError {
    /// Constructed graph is not a tree.
    #[error("Graph is not a tree.")]
    NotATree,
}

/// Wrapper struct for a petgraph DiGraph of documents.
#[derive(Debug)]
pub struct TrustchainGraph {
    graph: DiGraph<String, String>,
}

/// Read chains from a vector and return a DiGraph, a subtype of a petgraph [Graph](https://docs.rs/petgraph/latest/petgraph/graph/struct.Graph.html).
fn read_chains(chains: &Vec<DIDChain>, label_width: usize) -> DiGraph<String, String> {
    let mut nodes = HashMap::<String, petgraph::prelude::NodeIndex>::new();
    let mut graph = DiGraph::<String, String>::new();
    for chain in chains {
        let mut did = chain.root().to_owned();
        let mut level = 0;
        // Add source
        match nodes.get(&did) {
            Some(_) => (),
            None => {
                let pretty_did = PrettyDID::new(&chain.data(&did).unwrap().0, level, label_width)
                    .to_node_string();
                let ns = graph.add_node(pretty_did);
                nodes.insert(did.to_owned(), ns);
            }
        }
        while let Some(ddid) = chain.downstream(&did) {
            // Get source node
            let ns = match nodes.get(&did) {
                Some(&v) => v,
                None => panic!(),
            };
            // Add or retrieve target
            let nt = match nodes.get(ddid) {
                Some(&v) => v,
                None => {
                    let pretty_ddid =
                        PrettyDID::new(&chain.data(ddid).unwrap().0, level + 1, label_width)
                            .to_node_string();
                    let nt = graph.add_node(pretty_ddid);
                    nodes.insert(ddid.to_owned(), nt);
                    nt
                }
            };
            // Add edge if not in graph
            if !graph.contains_edge(ns, nt) {
                graph.extend_with_edges([(ns, nt, "".to_string())]);
            }

            // Update did
            did = ddid.to_owned();
            level += 1;
        }
    }
    graph
}

impl TrustchainGraph {
    /// Makes a new TrustchainGraph instance.
    pub fn new(chains: &Vec<DIDChain>, label_width: usize) -> Result<Self, GraphError> {
        let graph = read_chains(chains, label_width);
        Ok(Self { graph })
    }

    /// Outputs graph to graphviz format.
    pub fn to_dot(&self) -> String {
        // Output the tree to `graphviz` `DOT` format
        format!("{}", Dot::with_config(&self.graph, &[Config::EdgeNoLabel]))
    }
}

impl Display for TrustchainGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.to_dot())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::test_chain;

    const DEFAULT_LABEL_WIDTH: usize = 30;

    #[test]
    fn test_read_chains() -> Result<(), GraphError> {
        let chains = vec![test_chain().unwrap(), test_chain().unwrap()];
        let graph = TrustchainGraph::new(&chains, DEFAULT_LABEL_WIDTH);
        assert!(graph.is_ok());
        if let Ok(graph) = graph {
            assert_eq!(graph.graph.node_count(), 3);
            assert_eq!(graph.graph.edge_count(), 2);
        }
        Ok(())
    }
    #[test]
    fn test_to_dot() -> Result<(), GraphError> {
        let chains = vec![test_chain().unwrap(), test_chain().unwrap()];
        let graph = TrustchainGraph::new(&chains, DEFAULT_LABEL_WIDTH)?;
        format!("{}", graph.to_dot());
        Ok(())
    }
    #[test]
    fn test_display() -> Result<(), GraphError> {
        let chains = vec![test_chain().unwrap(), test_chain().unwrap()];
        let graph = TrustchainGraph::new(&chains, DEFAULT_LABEL_WIDTH)?;
        format!("{}", graph);
        Ok(())
    }
}
