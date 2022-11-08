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
    // TODO add error types
}

/// Wrapper struct for a petgraph DiGraph of documents.
#[derive(Debug)]
pub struct TrustchainGraph {
    graph: DiGraph<String, String>,
}

/// Read chains from a vector and return a DiGraph.
/// See: https://docs.rs/petgraph/latest/petgraph/graph/struct.Graph.html
fn read_chains(chains: &Vec<DIDChain>) -> DiGraph<String, String> {
    let mut nodes = HashMap::<String, petgraph::prelude::NodeIndex>::new();
    let mut graph = DiGraph::<String, String>::new();
    const MAX_WIDTH: usize = 35;
    for chain in chains {
        let mut did = chain.root().to_owned();
        let mut level = 0;
        // Add source
        let ns = match nodes.get(&did) {
            Some(&v) => v,
            None => {
                let pretty_did =
                    PrettyDID::new(&chain.data(&did).unwrap().0, level, MAX_WIDTH).to_node_string();
                let ns = graph.add_node(pretty_did);
                nodes.insert(did.to_owned(), ns);
                ns
            }
        };
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
                        PrettyDID::new(&chain.data(ddid).unwrap().0, level + 1, MAX_WIDTH)
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

impl From<Vec<DIDChain>> for TrustchainGraph {
    fn from(chains: Vec<DIDChain>) -> Self {
        TrustchainGraph::new(&chains).unwrap()
    }
}

impl TrustchainGraph {
    /// Makes a new TrustchainGraph instance.
    pub fn new(chains: &Vec<DIDChain>) -> Result<Self, GraphError> {
        let graph = read_chains(chains);
        Ok(Self { graph })
    }

    /// Outputs graph to graphviz format.
    pub fn to_dot(&self) -> String {
        // Output the tree to `graphviz` `DOT` format
        format!("{}", Dot::with_config(&self.graph, &[Config::EdgeNoLabel]))
    }

    /// Saves to a graphviz/dot file
    pub fn save(&self) {
        todo!()
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
    use crate::TRUSTCHAIN_DATA;

    use super::*;
    use std::path::Path;

    fn get_test_did_chains() -> Result<Vec<DIDChain>, Box<dyn std::error::Error>> {
        let root_path = std::env::var(TRUSTCHAIN_DATA).unwrap();
        let read_file = std::fs::read_to_string(
            Path::new(&root_path)
                .join("resources")
                .join("test")
                .join("test_did_chains.json"),
        )?;
        let did_chains: Vec<DIDChain> = serde_json::from_str(read_file.as_str())?;
        Ok(did_chains)
    }

    #[test]
    fn test_read_chains() {
        let chains = get_test_did_chains().unwrap();
        let graph = TrustchainGraph::new(&chains);
        assert!(graph.is_ok());
    }
    #[test]
    fn test_to_dot() -> Result<(), GraphError> {
        let chains = get_test_did_chains().unwrap();
        let graph = TrustchainGraph::new(&chains)?;
        print!("{}", graph.to_dot());
        Ok(())
    }
    // #[test]
    // fn invalid_not_a_tree() {
    //     todo!()
    // }
    // #[test]
    // fn valid_tree() {
    //     todo!()
    // }
    // #[test]
    // fn display() {
    //     todo!()
    // }
}
