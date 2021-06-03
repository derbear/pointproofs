// custom benchmarking for Aardvark for consistency against EDRAX VCs
// requires nightly for std::hint::black_box
#![feature(bench_black_box)]

extern crate rand;
extern crate veccom;

use std::env;
use std::hint;
use std::time::{Instant,Duration};

use veccom::pairings::*;
use veccom::merkle::*;

const WARM: usize = 100;

fn bench_pairing_commit (prover_params: &ProverParams, n: usize, k: usize) -> Vec<Duration> {
    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for _ in 0..(WARM+k) {
        let base: usize = rand::random();
        let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", base+i);
            init_values.push(s.into_bytes());
        }

        let mut values: Vec<&[u8]> = Vec::with_capacity(n);
        for i in 0..n {
            values.push(&init_values[i]);
        }

        let now = Instant::now();
        hint::black_box(commit(
            hint::black_box(prover_params),
            hint::black_box(&values)),
        );
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_pairing_open (prover_params: &ProverParams, n: usize, k: usize) -> Vec<Duration> {
    let base: usize = rand::random();
    let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", base+i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for _ in 0..(WARM+k) {
        let r: usize = rand::random();
        let i = r % n;
        let now = Instant::now();
        hint::black_box(convert_proof_to_bytes(&prove(
            hint::black_box(prover_params),
            hint::black_box(&values),
            hint::black_box(i),
        )));
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_pairing_verify (prover_params: &ProverParams, verifier_params: &VerifierParams, n: usize, k: usize) -> Vec<Duration> {
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let com = commit(&prover_params, &values);

    let mut proofs = Vec::with_capacity(WARM+k);
    let mut proof_indexes = Vec::with_capacity(WARM+k);
    for _ in 0..(WARM+k) {
        let r: usize = rand::random();
        let i = r % n;
        proof_indexes.push(i);
        proofs.push(convert_proof_to_bytes(&prove(&prover_params, &values, i)));
    }

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for j in 0..(WARM+k) {
        let i = proof_indexes[j];
        let now = Instant::now();
        assert!(
            hint::black_box(veccom::pairings::verify(
                hint::black_box(&verifier_params),
                hint::black_box(&com),
                &convert_bytes_to_proof(
                    hint::black_box(&proofs[j])),
                hint::black_box(&values[i]),
                hint::black_box(i),
        )));
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_pairing_commit_update (prover_params: &ProverParams, n: usize, k: usize) -> Vec<Duration> {
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let com = commit(&prover_params, &values);

    let base: usize = rand::random();
    let mut init_new_values = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        let t = format!("this is new message number {}", base+j);
        init_new_values.push(t.into_bytes());
    }

    let mut new_values: Vec<&[u8]> = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        new_values.push(&init_new_values[j]);
    }

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for j in 0..(WARM+k) {
        let r: usize = rand::random();
        let i = r % n;
        let now = Instant::now();
        hint::black_box(veccom::pairings::commit_update(
            hint::black_box(prover_params),
            hint::black_box(&com),
            hint::black_box(i),
            hint::black_box(&values[i]),
            hint::black_box(&new_values[j]),
        ));
        measurements.push(now.elapsed());
        values[i] = new_values[j];
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_pairing_proof_update (prover_params: &ProverParams, n: usize, k: usize) -> Vec<Duration> {
    // Does not include to/from bytes conversion, because this is supposed to be a local operation
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let base: usize = rand::random();
    let mut init_update_new_values = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        let t = format!("this is new message number {}", base+j);
        init_update_new_values.push(t.into_bytes());
    }

    let mut proofs = Vec::with_capacity(WARM+k);
    let mut proof_indexes = Vec::with_capacity(WARM+k);
    let mut update_indexes = Vec::with_capacity(WARM+k);
    let mut update_old_values = Vec::with_capacity(WARM+k);
    let mut update_new_values = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        let ur: usize = rand::random();
        let ui = ur % n;
        
        let mut pr: usize = rand::random();
        let mut pi = pr % n;
        while ui == pi {
            pr = rand::random();
            pi = pr % n;
        }
        
        update_indexes.push(ui);
        update_old_values.push(values[ui]);
        update_new_values.push(&init_update_new_values[j]);

        proof_indexes.push(pi);
        proofs.push(prove(prover_params, &values, pi));

        values[ui] = update_new_values[j];
    }

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for j in 0..(WARM+k) {
        let now = Instant::now();
        hint::black_box(veccom::pairings::proof_update(
            hint::black_box(prover_params),
            hint::black_box(&proofs[j]),
            hint::black_box(proof_indexes[j]),
            hint::black_box(update_indexes[j]),
            hint::black_box(update_old_values[j]),
            hint::black_box(update_new_values[j]),
        ));
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_merkle_commit (params: &Params, n: usize, k: usize) -> Vec<Duration> {
    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for _ in 0..(WARM+k) {
        let base: usize = rand::random();
        let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", base+i);
            init_values.push(s.into_bytes());
        }

        let mut values: Vec<&[u8]> = Vec::with_capacity(n);
        for i in 0..n {
            values.push(&init_values[i]);
        }

        let now = Instant::now();
        hint::black_box(commit_no_tree(
            hint::black_box(&params),
            hint::black_box(&values),
        ));
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_merkle_open (params: &Params, n: usize, k: usize) -> Vec<Duration> {
    let mut init_values = Vec::with_capacity(n);
    let mut values:Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }        
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let tree = commit_with_tree(&params, &values);

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for _ in 0..(WARM+k) {
        let r: usize = rand::random();
        let i = r % n;
        let now = Instant::now();
        hint::black_box(prove_from_tree(
            hint::black_box(&params),
            hint::black_box(&tree),
            hint::black_box(i),
        ));
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_merkle_verify (params: &Params, n: usize, k: usize) -> Vec<Duration> {
    let mut init_values = Vec::with_capacity(n);
    let mut values:Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }        
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let com = commit_no_tree(&params, &values);

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for _ in 0..(WARM+k) {
        let r: usize = rand::random();
        let i = r % n;
        let proof = prove_from_scratch(&params, &values, i);

        let now = Instant::now();
        assert!(hint::black_box(veccom::merkle::verify(
            hint::black_box(&params),
            hint::black_box(&com),
            hint::black_box(&proof),
            hint::black_box(values[i]),
            hint::black_box(i),
        )));
        measurements.push(now.elapsed());
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_merkle_commit_update (params: &Params, n: usize, k: usize) -> Vec<Duration> {
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    // let com = commit(&prover_params, &values);

    let base: usize = rand::random();
    let mut init_new_values = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        let t = format!("this is new message number {}", base+j);
        init_new_values.push(t.into_bytes());
    }

    let mut new_values: Vec<&[u8]> = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        new_values.push(&init_new_values[j]);
    }

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for j in 0..(WARM+k) {
        let r: usize = rand::random();
        let i = r % n;

        let proof = prove_from_scratch(&params, &values, i);
        let now = Instant::now();
        hint::black_box(veccom::merkle::commit_update(
            hint::black_box(&params),
            hint::black_box(i),
            hint::black_box(&proof),
            hint::black_box(new_values[j]),
        ));
        measurements.push(now.elapsed());
        values[i] = new_values[j];
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn bench_merkle_proof_update (params: &Params, n: usize, k: usize) -> Vec<Duration> {
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let base: usize = rand::random();
    let mut init_new_values = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        let t = format!("this is new message number {}", base+j);
        init_new_values.push(t.into_bytes());
    }

    let mut new_values: Vec<&[u8]> = Vec::with_capacity(WARM+k);
    for j in 0..WARM+k {
        new_values.push(&init_new_values[j]);
    }

    let mut measurements: Vec<Duration> = Vec::with_capacity(WARM+k);
    for j in 0..(WARM+k) {
        let r1: usize = rand::random();
        let i1 = r1 % n;
        
        let mut r2: usize = rand::random();
        let mut i2 = r2 % n;
        while i1 == i2 {
            r2 = rand::random();
            i2 = r2 % n;
        }

        let mut proof1 = prove_from_scratch(&params, &values, i1);
        let proof2 = prove_from_scratch(&params, &values, i2);
        let helper_info = veccom::merkle::commit_update(&params, i2, &proof2, &new_values[j]).1;
        let now = Instant::now();
        hint::black_box(veccom::merkle::proof_update(
            hint::black_box(&params),
            hint::black_box(&mut proof1),
            hint::black_box(i1),
            hint::black_box(i2),
            hint::black_box(&proof2),
            hint::black_box(&new_values[j]),
            hint::black_box(Some(&helper_info)),
        ));
        measurements.push(now.elapsed());
        values[i2] = new_values[j];
    }
    let m = measurements.drain(WARM..).collect();
    m
}

fn vec_duration_to_micros(vec: Vec<Duration>) -> Vec<u128> {
    vec.into_iter().map(|d| d.as_micros()).collect()
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    let n_str = &args[1];
    let k_str = &args[2];

    let n: usize = n_str.parse().unwrap();
    let k: usize = k_str.parse().unwrap();

    // println!("init params... n={}, iters={}", n, k);
    // println!("");

    println!("iters,{}", k);

    let (mut prover_params, verifier_params) = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n);
    prover_params.precomp_256();

    // println!("bench_pairing_commit:");
    print!("bench_pairing_commit,");
    println!("{:?}\n", vec_duration_to_micros(bench_pairing_commit(&prover_params, n, k)));

    // println!("bench_pairing_open:");
    print!("bench_pairing_open,");
    println!("{:?}\n", vec_duration_to_micros(bench_pairing_open(&prover_params, n, k)));

    // println!("bench_pairing_verify:");
    print!("bench_pairing_verify,");
    println!("{:?}\n", vec_duration_to_micros(bench_pairing_verify(&prover_params, &verifier_params, n, k)));

    // println!("bench_pairing_commit_update:");
    print!("bench_pairing_commit_update,");
    println!("{:?}\n", vec_duration_to_micros(bench_pairing_commit_update(&prover_params, n, k)));

    // println!("bench_pairing_proof_update:");
    print!("bench_pairing_proof_update,");
    println!("{:?}\n", vec_duration_to_micros(bench_pairing_proof_update(&prover_params, n, k)));

    let params: Params = paramgen(n);

    // println!("bench_merkle_commit:");
    print!("bench_merkle_commit,");
    println!("{:?}\n", vec_duration_to_micros(bench_merkle_commit(&params, n, k)));

    // println!("bench_merkle_open:");
    print!("bench_merkle_open,");
    println!("{:?}\n", vec_duration_to_micros(bench_merkle_open(&params, n, k)));

    // println!("bench_merkle_verify:");
    print!("bench_merkle_verify,");
    println!("{:?}\n", vec_duration_to_micros(bench_merkle_verify(&params, n, k)));

    // println!("bench_merkle_commit_update:");
    print!("bench_merkle_commit_update,");
    println!("{:?}\n", vec_duration_to_micros(bench_merkle_commit_update(&params, n, k)));

    // println!("bench_merkle_proof_update:");
    print!("bench_merkle_proof_update,");
    println!("{:?}\n", vec_duration_to_micros(bench_merkle_proof_update(&params, n, k)));
}
