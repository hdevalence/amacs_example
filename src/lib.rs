#![feature(test)]
#![allow(non_snake_case)]

extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate sha3;
#[macro_use]
extern crate zkp;
#[macro_use]
extern crate serde_derive;

use sha3::Sha3_512;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};

use zkp::Transcript;

pub(crate) mod proofs {
    create_nipk!{
        cred_issue_2_clear,
        (x_0_blinding, x_0, x_1, x_2),
        (X_0, X_1, X_2, A, B, P, Q, m_1_P, m_2_P)
        :
        X_0 = (B * x_0 + A * x_0_blinding),
        X_1 = (A * x_1),
        X_2 = (A * x_2),
        Q = (P * x_0 + m_1_P * x_1 + m_2_P * x_2)
    }

    create_nipk!{
        cred_show_2_hidden,
        (m_1, m_2, z_1, z_2, minus_z_Q),
        (X_1, X_2, A, V, P, C_m_1, C_m_2)
        :
        C_m_1 = (P * m_1 + A * z_1),
        C_m_2 = (P * m_2 + A * z_2),
        V = (A * minus_z_Q + X_1 * z_1 + X_2 * z_2)
    }
}

struct PedersenGens {
    /// Basepoint
    B: RistrettoPoint,
    /// Blinding basepoint
    A: RistrettoPoint,
}

impl Default for PedersenGens {
    fn default() -> Self {
        use curve25519_dalek::constants;
        PedersenGens {
            B: constants::RISTRETTO_BASEPOINT_POINT,
            A: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }
}

struct IssuerSecret {
    x_0_blinding: Scalar,
    x_0: Scalar,
    x_1: Scalar,
    x_2: Scalar,
}

impl Default for IssuerSecret {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        IssuerSecret {
            x_0_blinding: Scalar::random(&mut rng),
            x_0: Scalar::random(&mut rng),
            x_1: Scalar::random(&mut rng),
            x_2: Scalar::random(&mut rng),
        }
    }
}

#[derive(Clone)]
struct IssuerPublic {
    X_0: RistrettoPoint,
    X_1: RistrettoPoint,
    X_2: RistrettoPoint,
}

impl<'a> From<&'a IssuerSecret> for IssuerPublic {
    fn from(sk: &'a IssuerSecret) -> Self {
        let pg = PedersenGens::default();
        IssuerPublic {
            X_0: sk.x_0 * pg.B + sk.x_0_blinding * pg.A,
            X_1: sk.x_1 * pg.A,
            X_2: sk.x_2 * pg.A,
        }
    }
}

struct IssuerKeypair {
    sk: IssuerSecret,
    pk: IssuerPublic,
}

impl From<IssuerSecret> for IssuerKeypair {
    fn from(sk: IssuerSecret) -> Self {
        let pk = (&sk).into();
        IssuerKeypair { sk, pk }
    }
}

impl Default for IssuerKeypair {
    fn default() -> Self {
        IssuerSecret::default().into()
    }
}

struct Tag {
    P: RistrettoPoint,
    Q: RistrettoPoint,
}

impl Tag {
    fn randomize(&self) -> Tag {
        let t = Scalar::random(&mut rand::thread_rng());
        Tag {
            P: self.P * t,
            Q: self.Q * t,
        }
    }
}

struct Credential {
    m_1: Scalar,
    m_2: Scalar,
    tag: Tag,
}

struct ClearIssuanceRequest {
    m_1: Scalar,
    m_2: Scalar,
}

struct ClearIssuanceResponse {
    tag: Tag,
    proof: proofs::cred_issue_2_clear::Proof,
}

impl IssuerKeypair {
    fn issue_clear(
        &self,
        transcript: &mut Transcript,
        req: &ClearIssuanceRequest,
    ) -> ClearIssuanceResponse {
        let pg = PedersenGens::default();

        // Choose a random scalar for the tag
        let b = Scalar::random(&mut rand::thread_rng());

        // Construct the tag data
        let P = b * pg.B;
        let Q = ((self.sk.x_0 + self.sk.x_1 * req.m_1 + self.sk.x_2 * req.m_2) * b) * pg.B;

        // Need to compute these to form the proof
        let m_1_P = req.m_1 * P;
        let m_2_P = req.m_2 * P;

        use self::proofs::cred_issue_2_clear::*;

        // Return the issuance response
        ClearIssuanceResponse {
            tag: Tag { P, Q },
            proof: Proof::create(
                transcript,
                Publics {
                    A: &pg.A,
                    B: &pg.B,
                    P: &P,
                    Q: &Q,
                    X_0: &self.pk.X_0,
                    X_1: &self.pk.X_1,
                    X_2: &self.pk.X_2,
                    m_1_P: &m_1_P,
                    m_2_P: &m_2_P,
                },
                Secrets {
                    x_0_blinding: &self.sk.x_0_blinding,
                    x_0: &self.sk.x_0,
                    x_1: &self.sk.x_1,
                    x_2: &self.sk.x_2,
                },
            ),
        }
    }
}

impl ClearIssuanceResponse {
    fn validate(
        self,
        pk: &IssuerPublic,
        req: &ClearIssuanceRequest,
        transcript: &mut Transcript,
    ) -> Result<Credential, ()> {
        let pg = PedersenGens::default();

        // Need to compute these to check the proof
        let m_1_P = req.m_1 * self.tag.P;
        let m_2_P = req.m_2 * self.tag.P;

        use self::proofs::cred_issue_2_clear::*;

        // Verify the issuance proof
        let res = self.proof.verify(
            transcript,
            Publics {
                A: &pg.A,
                B: &pg.B,
                P: &self.tag.P,
                Q: &self.tag.Q,
                X_0: &pk.X_0,
                X_1: &pk.X_1,
                X_2: &pk.X_2,
                m_1_P: &m_1_P,
                m_2_P: &m_2_P,
            },
        )?;

        Ok(Credential {
            m_1: req.m_1,
            m_2: req.m_2,
            tag: self.tag,
        })
    }
}

struct CredentialPresentation {
    tag: Tag,
    C_Q: RistrettoPoint,
    C_m_1: RistrettoPoint,
    C_m_2: RistrettoPoint,
    V: RistrettoPoint,
    proof: proofs::cred_show_2_hidden::Proof,
}

impl Credential {
    fn present(&self, pk: &IssuerPublic, transcript: &mut Transcript) -> CredentialPresentation {
        let pg = PedersenGens::default();
        // Create an ephemeral tag
        let tag = self.tag.randomize();

        let mut rng = rand::thread_rng();
        let z_1 = Scalar::random(&mut rng);
        let z_2 = Scalar::random(&mut rng);
        let minus_z_Q = Scalar::random(&mut rng);

        let C_m_1 = RistrettoPoint::multiscalar_mul(&[self.m_1, z_1], &[tag.P, pg.A]);
        let C_m_2 = RistrettoPoint::multiscalar_mul(&[self.m_2, z_2], &[tag.P, pg.A]);
        let C_Q = tag.Q - pg.A * minus_z_Q;

        let V = RistrettoPoint::multiscalar_mul(&[z_1, z_2, minus_z_Q], &[pk.X_1, pk.X_2, pg.A]);

        use self::proofs::cred_show_2_hidden::*;

        let proof = Proof::create(
            transcript,
            Publics {
                X_1: &pk.X_1,
                X_2: &pk.X_2,
                A: &pg.A,
                V: &V,
                P: &tag.P,
                C_m_1: &C_m_1,
                C_m_2: &C_m_2,
            },
            Secrets {
                m_1: &self.m_1,
                m_2: &self.m_2,
                z_1: &z_1,
                z_2: &z_2,
                minus_z_Q: &minus_z_Q,
            },
        );

        CredentialPresentation {
            tag,
            C_Q,
            C_m_1,
            C_m_2,
            V,
            proof,
        }
    }
}

impl IssuerKeypair {
    fn verify_presentation(
        &self,
        pres: &CredentialPresentation,
        transcript: &mut Transcript,
    ) -> Result<(), ()> {
        if pres.tag.P.is_identity() {
            return Err(());
        }

        let pg = PedersenGens::default();

        let V_prime = RistrettoPoint::multiscalar_mul(
            &[self.sk.x_0, self.sk.x_1, self.sk.x_2],
            &[pres.tag.P, pres.C_m_1, pres.C_m_2],
        ) - pres.C_Q;

        use self::proofs::cred_show_2_hidden::*;

        pres.proof.verify(
            transcript,
            Publics {
                X_1: &self.pk.X_1,
                X_2: &self.pk.X_2,
                A: &pg.A,
                V: &V_prime,
                P: &pres.tag.P,
                C_m_1: &pres.C_m_1,
                C_m_2: &pres.C_m_2,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_issue() {
        let keypair = IssuerKeypair::default();
        let pk = keypair.pk.clone();

        let req = ClearIssuanceRequest {
            m_1: 1u64.into(),
            m_2: 2u64.into(),
        };

        let mut issuer_transcript = Transcript::new(b"ClearIssueDemo");
        let response = keypair.issue_clear(&mut issuer_transcript, &req);

        let mut client_transcript = Transcript::new(b"ClearIssueDemo");
        let issuance_result = response.validate(&pk, &req, &mut client_transcript);

        assert!(issuance_result.is_ok());
    }

    #[test]
    fn check_presentation() {
        let keypair = IssuerKeypair::default();
        let pk = keypair.pk.clone();

        // Wrap credential issuance (test setup) in its own scope
        let cred = {
            let req = ClearIssuanceRequest {
                m_1: 1u64.into(),
                m_2: 2u64.into(),
            };

            let mut issuer_transcript = Transcript::new(b"ClearIssueDemo");
            let response = keypair.issue_clear(&mut issuer_transcript, &req);

            let mut client_transcript = Transcript::new(b"ClearIssueDemo");
            let issuance_result = response.validate(&pk, &req, &mut client_transcript);

            issuance_result.unwrap()
        };

        let mut client_transcript = Transcript::new(b"CredShowDemo");
        let presentation = cred.present(&pk, &mut client_transcript);

        let mut issuer_transcript = Transcript::new(b"CredShowDemo");
        let pres_result = keypair.verify_presentation(&presentation, &mut issuer_transcript);

        assert!(pres_result.is_ok());
    }
}
