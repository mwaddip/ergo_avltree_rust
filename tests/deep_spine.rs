//! Regression test: a crafted proof encoding a deep left spine must not drive
//! label computation to the packed depth.
//!
//! `Node::label` used to recurse into both children, so the recursion depth was
//! the depth of the tree — and a verifier's tree is materialised from proof
//! bytes. `reconstruct_tree` evaluates `label(&root)` *before* comparing it
//! against the starting digest, so the attacker needs no valid digest at all:
//! any 33 bytes reach the traversal. The result was a stack overflow, which
//! aborts the process rather than raising a catchable panic.
//!
//! The depth below sits above the pre-fix threshold (which was around 1400 on a
//! 2 MiB stack) and below the depth at which dropping the tree still recurses,
//! so a regression here fails loudly. Note that a failure aborts the whole test
//! binary — that is inherent to testing stack exhaustion.

use bytes::Bytes;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;

mod common;
use common::generate_tree;

const LEAF: u8 = 2;
const LABEL: u8 = 3;
const END_OF_TREE: u8 = 4;

/// ~170 KB of proof: deep enough that the recursive version could not survive.
const SPINE_DEPTH: usize = 5_000;

#[test]
fn deep_spine_proof_is_rejected_without_exhausting_the_stack() {
    let mut proof: Vec<u8> = Vec::new();
    proof.push(LEAF);
    proof.extend_from_slice(&[0x10, 0x20, 0xaa]); // key, nextLeafKey, value
    for _ in 0..SPINE_DEPTH {
        proof.push(LABEL);
        proof.extend_from_slice(&[0x11u8; 32]);
        proof.push(0x00); // internal node, balance 0
    }
    proof.push(END_OF_TREE);
    proof.push(0x01); // directions

    // 33 arbitrary bytes: the digest comparison is never reached, the
    // traversal that computes the label to compare against it is.
    let v = BatchAVLVerifier::new(
        &Bytes::from(vec![7u8; 33]),
        &Bytes::from(proof),
        generate_tree(1, Some(1)),
        None,
        None,
    );
    assert!(v.is_err(), "deep-spine proof must be rejected");
}
