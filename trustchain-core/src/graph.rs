use petgraph::adj::NodeIndex;
use petgraph::dot::{Config, Dot};
use petgraph::graph::DiGraph;
use ssi::did::Document;
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
    graph: DiGraph<String, ()>,
}

/// Read forest from a vector of vectors (list of trees) and return a DiGraph.
/// See: https://docs.rs/petgraph/latest/petgraph/graph/struct.Graph.html
fn read_forest(forest: &Vec<Vec<Document>>) -> DiGraph<String, ()> {
    let mut graph = DiGraph::new();
    let mut edges = Vec::new();
    for tree in forest {
        for i in 1..tree.len() {
            // TODO: check if node already present? Might need new struct (e.g. HashMap)
            // to store nodes as encountered and only add once.
            // TODO: consider whether to use a formatted string with more than DID
            // as graph label (e.g. truncated DID, service info, key info, etc)
            let ns = graph.add_node(tree[i - 1].id.clone());
            let nt = graph.add_node(tree[i].id.clone());
            edges.push((ns, nt));
        }
    }
    graph.extend_with_edges(&edges);
    graph
}

impl TrustchainGraph {
    /// Makes a new TrustchainGraph instance.
    fn new(forest: &Vec<Vec<Document>>) -> Result<Self, GraphError> {
        let graph = read_forest(&forest);
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
        TEST_SIDETREE_DOCUMENT, TEST_SIDETREE_DOCUMENT_METADATA,
        TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
        TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF, TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER,
        TEST_TRUSTCHAIN_DOCUMENT, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };
    use crate::utils::canonicalize;

    #[test]
    fn read_forest() {
        let doc1: Document = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT).unwrap();
        let doc2: Document = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT).unwrap();
        let mut forest = Vec::new();
        forest.push(vec![doc1, doc2]);
        let graph = TrustchainGraph::new(&forest).unwrap();

        // Output the tree to `graphviz` `DOT` format
        let dot = Dot::with_config(
            &graph.graph,
            &[Config::GraphContentOnly, Config::EdgeNoLabel],
        );
        println!("{:?}", dot);
    }
    #[test]
    fn invalid_not_a_tree() {
        todo!()
    }
    #[test]
    fn valid_tree() {
        todo!()
    }
    #[test]
    fn to_graphviz() {
        todo!()
    }
    #[test]
    fn display() {
        todo!()
    }
}
