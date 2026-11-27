//! Layer 5: Multi-scope `Node` container and single-scope `ScopeInstance` public facades.

pub(crate) mod node;
pub(crate) mod scope;

pub use node::{Node, NodeBuilder, NodeLimits, WeakNode};
pub use scope::{ScopeBuilder, ScopeInstance, WeakScope};
