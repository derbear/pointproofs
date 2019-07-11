extern crate veccom;

use veccom::veccom_pairings::paramgen::*;
use veccom::veccom_pairings::commit::*;
use veccom::veccom_pairings::verify::*;
use veccom::veccom_pairings::prove::*;

fn print_48_bytes(b : [u8; 48])->String {
    let mut ret = "".to_string();
    for i in 0..48 {
        ret = ret + &format!("{:02x}", b[i]);
    }
    ret
}

pub fn main() {
    let n = 10usize;
    let update_index = n/2;

    let (prover_params, verifier_params) = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n);

    let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
    println!("Commiting to the following {} strings", n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        println!("{}", s);
        init_values.push(s.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        old_values.push(&init_values[i]);
    }

    let old_com = commit(&prover_params, &old_values);
    let old_commitment_bytes = convert_commitment_to_bytes(&old_com);
    println!("\nCommitment:  {}", print_48_bytes(old_commitment_bytes));

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove(&prover_params, &old_values, i));
        let proof_bytes = convert_proof_to_bytes(&proofs[i]);
        println!("Old Proof {}: {}", i, print_48_bytes(proof_bytes));
    }

    for i in 0..n {
        assert!(verify(&verifier_params, &old_com, &proofs[i], &old_values[i], i));
    }

    let s = format!("\"this is new message number {}\"", update_index);
    println!("\nUpdating string {} to {}", update_index, s);
    let new_value = s.into_bytes();

    let new_com = commit_update(&prover_params, &old_com, update_index, &old_values[update_index], &new_value);
    let new_commitment_bytes = convert_commitment_to_bytes(&new_com);
    println!("New Commitment:  {}", print_48_bytes(new_commitment_bytes));

    assert!(verify(&verifier_params, &new_com, &proofs[update_index], &new_value, update_index));
    assert!(!verify(&verifier_params, &new_com, &proofs[update_index], &old_values[update_index], update_index));

    for i in 0..n {
        if i!=update_index {
            assert!(!verify(&verifier_params, &new_com, &proofs[i], &old_values[i], i));
        }
        proofs[i]=proof_update(&prover_params, &proofs[i], i, update_index, &old_values[update_index], &new_value);
        let proof_bytes = convert_proof_to_bytes(&proofs[i]);
        println!("New Proof {}: {}", i, print_48_bytes(proof_bytes));
        if i!=update_index {
            assert!(verify(&verifier_params, &new_com, &proofs[i], &old_values[i], i));
        }
    }
}
