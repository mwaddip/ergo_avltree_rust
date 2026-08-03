//! Regression test: a crafted proof encoding a deep spine must be rejected
//! before recursive verifier paths or `Rc` teardown can exhaust the stack.

use blake2::digest::Digest as _;
use bytes::Bytes;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree_rust::batch_node::{AVLTree, Blake2b256, Node, NodeHeader};
use ergo_avltree_rust::operation::Digest32;
use std::env;
use std::process::Command;
use std::thread;

const LEAF: u8 = 2;
const LABEL: u8 = 3;
const END_OF_TREE: u8 = 4;
const CHILD_ENV: &str = "ERGO_AVLTREE_DEEP_SPINE_CHILD";

/// Well above the recursive `Rc` teardown threshold observed on supported hosts.
const SPINE_DEPTH: usize = 50_000;

fn dummy_resolver(digest: &Digest32) -> Node {
    Node::LabelOnly(NodeHeader::new(Some(*digest), None))
}

fn generate_tree() -> AVLTree {
    AVLTree::new(dummy_resolver, 1, Some(1))
}

fn deep_spine_proof(depth: usize) -> Bytes {
    let mut proof = Vec::with_capacity(6 + depth * 34);
    proof.push(LEAF);
    proof.extend_from_slice(&[0x10, 0x20, 0xaa]); // key, nextLeafKey, value
    for _ in 0..depth {
        proof.push(LABEL);
        proof.extend_from_slice(&[0x11; 32]);
        proof.push(0x00); // internal node, balance 0
    }
    proof.push(END_OF_TREE);
    proof.push(0x01); // directions
    Bytes::from(proof)
}

fn deep_spine_digest(depth: usize) -> Bytes {
    assert!(depth <= u8::MAX as usize);

    let mut leaf_hasher = Blake2b256::new();
    leaf_hasher.update([0]);
    leaf_hasher.update([0x10]);
    leaf_hasher.update([0xaa]);
    leaf_hasher.update([0x20]);
    let mut label = [0; 32];
    label.copy_from_slice(&leaf_hasher.finalize());

    for _ in 0..depth {
        let mut internal_hasher = Blake2b256::new();
        internal_hasher.update([1]);
        internal_hasher.update([0]);
        internal_hasher.update(label);
        internal_hasher.update([0x11; 32]);
        label.copy_from_slice(&internal_hasher.finalize());
    }

    let mut digest = Vec::from(label);
    digest.push(depth as u8);
    Bytes::from(digest)
}

fn reject_deep_spine() {
    let result = BatchAVLVerifier::new(
        &Bytes::from(vec![7; 33]),
        &deep_spine_proof(SPINE_DEPTH),
        generate_tree(),
        None,
        None,
    );
    assert!(result.is_err(), "deep-spine proof must be rejected");
}

#[test]
fn deep_spine_proof_is_rejected_without_exhausting_the_stack() {
    if env::var_os(CHILD_ENV).is_some() {
        thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(reject_deep_spine)
            .expect("deep-spine worker must start")
            .join()
            .expect("deep-spine worker must return without panicking");
        return;
    }

    let status = Command::new(env::current_exe().expect("test executable must be available"))
        .env(CHILD_ENV, "1")
        .arg("--exact")
        .arg("deep_spine_proof_is_rejected_without_exhausting_the_stack")
        .arg("--nocapture")
        .status()
        .expect("deep-spine child process must start");

    assert!(
        status.success(),
        "deep-spine child process aborted with {status}"
    );
}

#[test]
fn proof_at_maximum_format_depth_is_accepted() {
    thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            let verifier = BatchAVLVerifier::new(
                &deep_spine_digest(u8::MAX as usize),
                &deep_spine_proof(u8::MAX as usize),
                generate_tree(),
                None,
                None,
            );
            assert!(verifier.is_ok(), "depth 255 is representable by the digest");
        })
        .expect("depth-boundary worker must start")
        .join()
        .expect("depth-boundary worker must return without panicking");
}

#[test]
fn proof_above_maximum_format_depth_is_rejected() {
    let error = BatchAVLVerifier::new(
        &Bytes::from(vec![0; 33]),
        &deep_spine_proof(u8::MAX as usize + 1),
        generate_tree(),
        None,
        None,
    )
    .err()
    .expect("depth 256 must be rejected before the node is linked");

    assert_eq!(
        error.to_string(),
        "proof tree depth 256 exceeds maximum 255"
    );
}
