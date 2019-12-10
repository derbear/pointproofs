use super::err::*;
use super::hash_to_field_veccom::hash_to_field_veccom;
use super::param::*;
use super::{Commitment, ProverParams};
use ff::Field;
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::hash_to_field_veccom::hash_to_field_repr_veccom;
use pairings::*;

impl Commitment {
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
    ) -> Result<Self, String> {
        // checks that cipersuite is supported
        assert!(
            check_ciphersuite(prover_params.ciphersuite),
            ERR_CIPHERSUITE.to_owned()
        );

        if prover_params.n != values.len() {
            return Err(ERR_INVALID_VALUE.to_owned());
        };

        let scalars_fr_repr: Vec<FrRepr> = values
            .iter()
            .map(|s| hash_to_field_repr_veccom(s.as_ref()))
            .collect();
        let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
        let commit = {
            if prover_params.precomp.len() == 512 * prover_params.n {
                VeccomG1Affine::sum_of_products_precomp_256(
                    &prover_params.generators[0..prover_params.n],
                    &scalars_u64,
                    &prover_params.precomp,
                )
            } else {
                VeccomG1Affine::sum_of_products(
                    &prover_params.generators[0..prover_params.n],
                    &scalars_u64,
                )
            }
        };

        Ok(Self {
            ciphersuite: prover_params.ciphersuite,
            commit,
        })
    }

    pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) -> Result<(), String> {
        // checks that cipersuite is supported
        if self.ciphersuite != prover_params.ciphersuite {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if prover_params.n <= changed_index {
            return Err(ERR_INVALID_INDEX.to_owned());
        };

        let mut multiplier = hash_to_field_veccom(&value_before);
        multiplier.negate();
        multiplier.add_assign(&hash_to_field_veccom(&value_after));

        let res = if prover_params.precomp.len() == 3 * prover_params.generators.len() {
            prover_params.generators[changed_index].mul_precomp_3(
                multiplier,
                &prover_params.precomp[changed_index * 3..(changed_index + 1) * 3],
            )
        } else if prover_params.precomp.len() == 256 * prover_params.generators.len() {
            prover_params.generators[changed_index].mul_precomp_256(
                multiplier,
                &prover_params.precomp[changed_index * 256..(changed_index + 1) * 256],
            )
        } else {
            prover_params.generators[changed_index].mul(multiplier)
        };

        self.commit.add_assign(&res);
        Ok(())
    }
}
