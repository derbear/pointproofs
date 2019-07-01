use super::{Params, commit};
use sha2::Digest;



pub fn prove(params: &Params, values: &[Vec<u8>], index : usize) -> Vec<Vec<u8>> {
    // TODO: error handling if the prover params length is not equal to values length
    // TODO: figure out if the input for values is the right one to use
    // TODO: is this the correct output type?
    prove_rec(params, values, 0, 0, index)
}

fn prove_rec(params: &Params, values: &[Vec<u8>], level: usize, current_node_index: usize, index_being_proven: usize) -> Vec<Vec<u8>> {
    if level<params.max_depth { // internal node
        if (index_being_proven >> (params.max_depth-level-1))&1 == 0 { // next step is to the left, so push right child onto the proof
            let mut ret = prove_rec(params, values, level+1, current_node_index*2, index_being_proven);
            ret.push(commit::commit_rec(params, values, level+1, current_node_index*2+1));
            ret
        } else { // next step is to the right, so push left child onto the proof
            let mut ret = prove_rec(params, values, level+1, current_node_index*2+1, index_being_proven);
            ret.push(commit::commit_rec(params, values, level+1, current_node_index*2));
            ret
        }
    } else { // leaf level, so empty proof
        Vec::with_capacity(params.max_depth)
    }
}
  

// For updating your proof when someone else's value changes
// Not for updating your own proof when your value changes -- because then the proof does not change!
// TODO: This can be made more efficient for batch update scenario if we supply the hash values on the path from changed index to the root
pub fn proof_update(params: &Params, proof : & mut Vec<Vec<u8>>, proof_index : usize, changed_index : usize, changed_index_proof : &[Vec<u8>], value_after : &[u8]) {
    if proof_index != changed_index {
        let mut path_diff = (proof_index ^ changed_index)>>1;
        let mut update_height = 0;
        while path_diff!=0 {
            update_height+=1;
            path_diff >>= 1;
        }
        proof[update_height] = commit::commit_update_helper(params, changed_index, changed_index_proof, value_after, update_height);
    }
}
