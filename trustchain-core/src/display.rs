use crate::chain::{Chain, DIDChain};
use petgraph::dot::{Config, Dot};
use petgraph::graph::DiGraph;
use ssi::did::{Document, Service, ServiceEndpoint};
use ssi::one_or_many::OneOrMany;
use std::collections::HashMap;
use std::fmt::{self, Display};
use thiserror::Error;

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => s[..idx - 3].to_string() + "...",
    }
}

fn get_service_endpoint_string(doc: &Document) -> Option<String> {
    match doc.select_service("TrustchainID") {
        Some(Service {
            service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(service_endpoint))),
            ..
        }) => Some(service_endpoint.to_string()),
        _ => None,
    }
}

/// A struct for displaying a DID in a box.
pub struct PrettyDID {
    did: String,
    level: usize,
    endpoint: Option<String>,
    max_width: usize,
}

impl PrettyDID {
    pub fn new(doc: &Document, level: usize, max_width: usize) -> Self {
        let endpoint = get_service_endpoint_string(doc);
        Self {
            did: doc.id.to_string(),
            level,
            endpoint,
            max_width,
        }
    }
    pub fn get_width(&self) -> usize {
        format!(" DID: {} ", self.did).len().min(self.max_width)
    }
    fn get_text_width(&self) -> usize {
        self.get_width() - 2
    }
    pub fn get_strings(&self) -> [String; 3] {
        let text_width = self.get_text_width();
        let level_string = truncate(&format!("Level: {}", self.level), text_width);
        let did_string = truncate(&format!("DID: {}", self.did), text_width);
        let endpoint_string = match &self.endpoint {
            Some(s) => truncate(&format!("Endpoint: {}", s), text_width),
            _ => truncate(&format!("Endpoint: {}", ""), text_width),
        };
        [level_string, did_string, endpoint_string]
    }
    pub fn to_node_string(&self) -> String {
        let strings = self.get_strings();
        strings.join("\n")
    }
}

impl fmt::Display for PrettyDID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Style:
        // "+---------------+"
        // "| level: ...    |"
        // "| did: ...      |"  ✅
        // "| endpoint: ... |"
        // "+---------------+"
        let box_width = self.get_width();
        let text_width = box_width - 2;
        let [level_string, did_string, endpoint_string] = self.get_strings();
        writeln!(f, "+{}+", "-".repeat(box_width))?;
        writeln!(f, "| {0:<1$} |   ", level_string, text_width)?;
        writeln!(f, "| {0:<1$} |  ✅", did_string, text_width)?;
        writeln!(f, "| {0:<1$} |   ", endpoint_string, text_width)?;
        writeln!(f, "+{}+", "-".repeat(box_width))?;
        Ok(())
    }
}

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
