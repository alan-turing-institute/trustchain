use crate::chain::{Chain, DIDChain, PrettyDID};
use petgraph::adj::NodeIndex;
use petgraph::dot::{Config, Dot};
use petgraph::graph::{DiGraph, Node};
use petgraph::prelude::DiGraphMap;
use ssi::did::Document;
use std::collections::{HashMap, HashSet};
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
struct TrustchainGraph {
    // TODO: check this is correct type spec
    graph: DiGraph<String, String>,
}

/// Read chains from a vector and return a DiGraph.
/// See: https://docs.rs/petgraph/latest/petgraph/graph/struct.Graph.html
fn read_chains(chains: &Vec<DIDChain>) -> DiGraph<String, String> {
    let mut nodes = HashMap::<String, petgraph::prelude::NodeIndex>::new();
    let mut graph = DiGraph::<String, String>::new();
    for chain in chains {
        let mut did = chain.root().to_owned();
        let mut level = 0;
        while let Some(ddid) = chain.downstream(&did) {
            // Add target
            let nt = match nodes.get(ddid) {
                Some(&v) => v,
                None => {
                    let pretty_ddid =
                        PrettyDID::from((&chain.data(ddid).unwrap().0, level + 1)).to_node_string();
                    let nt = graph.add_node(pretty_ddid);
                    nodes.insert(ddid.to_owned(), nt);
                    nt
                }
            };
            // Add source
            let ns = match nodes.get(&did) {
                Some(&v) => v,
                None => {
                    let pretty_did =
                        PrettyDID::from((&chain.data(&did).unwrap().0, level)).to_node_string();
                    let ns = graph.add_node(pretty_did);
                    nodes.insert(did.to_owned(), ns);
                    ns
                }
            };
            if !graph.contains_edge(ns, nt) {
                graph.extend_with_edges([(ns, nt, "".to_string())]);
            }

            // Update udid and did
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
    fn new(chains: &Vec<DIDChain>) -> Result<Self, GraphError> {
        let graph = read_chains(chains);
        Ok(Self { graph })
    }

    /// Outputs graph to graphviz format.
    fn to_graphviz(&self) {
        todo!()
    }

    /// Saves to a graphviz/dot file
    fn save(&self) {
        todo!()
    }
}

impl Display for TrustchainGraph {
    /// TODO: Implements diplay.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{
        TEST_ROOT_DOCUMENT, TEST_ROOT_DOCUMENT_METADATA, TEST_ROOT_PLUS_1_DOCUMENT,
        TEST_ROOT_PLUS_1_DOCUMENT_METADATA, TEST_ROOT_PLUS_2_DOCUMENT,
        TEST_ROOT_PLUS_2_DOCUMENT_METADATA, TEST_SIDETREE_DOCUMENT,
        TEST_SIDETREE_DOCUMENT_METADATA, TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF,
        TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF, TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF,
        TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER, TEST_TRUSTCHAIN_DOCUMENT,
        TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };
    // TODO: temporary public tests for test chain before test chain fixture available
    use crate::chain::tests::test_chain;
    use crate::utils::canonicalize;

    #[test]
    fn read_chains() {
        // let doc1: Document = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT).unwrap();
        // let doc2: Document = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT).unwrap();
        // let mut forest = Vec::new();
        // forest.push(vec![doc1, doc2]);
        let chains = vec![test_chain().unwrap(), test_chain().unwrap()];
        let graph = TrustchainGraph::new(&chains).unwrap();

        // Output the tree to `graphviz` `DOT` format
        let dot = Dot::with_config(
            &graph.graph,
            &[Config::GraphContentOnly, Config::EdgeNoLabel],
        );
        // let g: Graph = parse(
        println!("{}", "DiGraph {".to_owned());
        println!("{}", dot);
        println!("{}", "}".to_owned());
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
    // fn to_graphviz() {
    //     todo!()
    // }
    // #[test]
    // fn display() {
    //     todo!()
    // }
}
