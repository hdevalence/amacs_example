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
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul};

use zkp::{CompactProof, Transcript};

pub mod proofs {
    define_proof! {
        cred_issue_2_clear,
        "2attr cred issue clear",
        (x_0_blinding, x_0, x_1, x_2),
        (m_1_P, m_2_P, P, Q),
        (X_0, X_1, X_2, A, B)
        :
        X_0 = (x_0 * B + x_0_blinding * A),
        X_1 = (x_1 * A),
        X_2 = (x_2 * A),
        Q = (x_0 * P + x_1 * m_1_P + x_2 * m_2_P)
    }

    define_proof! {
        cred_show_2_hidden,
        "2attr cred show hidden",
        (m_1, m_2, z_1, z_2, minus_z_Q),
        (V, P, C_m_1, C_m_2),
        (X_1, X_2, A)
        :
        C_m_1 = (m_1 * P + z_1 * A),
        C_m_2 = (m_2 * P + z_2 * A),
        V = (minus_z_Q * A + z_1 * X_1 + z_2 * X_2)
    }

    define_proof! {
        cred_issue_2_blind_user,
        "2attr cred blind issue user proof",
        (d, e_1, e_2, m_1, m_2),
        (E_1_0, E_1_1, E_2_0, E_2_1, D),
        (B)
        :
        D = (d * B),
        E_1_0 = (e_1 * B),
        E_1_1 = (m_1 * B + e_1 * D),
        E_2_0 = (e_2 * B),
        E_2_1 = (m_2 * B + e_2 * D)
    }

    define_proof! {
        cred_issue_2_blind_issuer,
        "2attr cred blind issue issuer proof",
        (x_0_blinding, x_0, x_1, x_2, b, s, t_1, t_2),
        (P, D, T_1a, T_2a, T_1b, T_2b, E_Q_0, E_Q_1, E_1_0, E_1_1, E_2_0, E_2_1),
        (X_0, X_1, X_2, A, B)
        :
        X_0 = (x_0 * B + x_0_blinding * A),
        X_1 = (x_1 * A),
        X_2 = (x_2 * A),
        P = (b * B),
        T_1a = (b * X_1),
        T_1b = (t_1 * A),
        T_2a = (b * X_2),
        T_2b = (t_2 * A),
        E_Q_0 = (s * B + t_1 * E_1_0 + t_2 * E_2_0),
        E_Q_1 = (s * D + t_1 * E_1_1 + t_2 * E_2_1 + x_0 * P)
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

pub struct IssuerSecret {
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
pub struct IssuerPublic {
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

pub struct IssuerKeypair {
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

pub struct Credential {
    m_1: Scalar,
    m_2: Scalar,
    tag: Tag,
}

pub struct ClearIssuanceRequest {
    m_1: Scalar,
    m_2: Scalar,
}

pub struct ClearIssuanceResponse {
    tag: Tag,
    proof: CompactProof,
}

impl IssuerKeypair {
    fn clear_issue(
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

        let (proof, _points) = prove_compact(
            transcript,
            ProveAssignments {
                x_0_blinding: &self.sk.x_0_blinding,
                x_0: &self.sk.x_0,
                x_1: &self.sk.x_1,
                x_2: &self.sk.x_2,
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
        );

        // Return the issuance response
        ClearIssuanceResponse {
            tag: Tag { P, Q },
            proof,
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
        verify_compact(
            &self.proof,
            transcript,
            // A non-proof-of-concept impl could avoid these compressions.
            VerifyAssignments {
                A: &pg.A.compress(),
                B: &pg.B.compress(),
                P: &self.tag.P.compress(),
                Q: &self.tag.Q.compress(),
                X_0: &pk.X_0.compress(),
                X_1: &pk.X_1.compress(),
                X_2: &pk.X_2.compress(),
                m_1_P: &m_1_P.compress(),
                m_2_P: &m_2_P.compress(),
            },
        )
        .map_err(|_discard_error| ())?;

        Ok(Credential {
            m_1: req.m_1,
            m_2: req.m_2,
            tag: self.tag,
        })
    }
}

pub struct BlindIssuanceRequestSecret {
    d: Scalar,
    m_1: Scalar,
    m_2: Scalar,
}

impl BlindIssuanceRequestSecret {
    fn new(m_1: Scalar, m_2: Scalar) -> Self {
        BlindIssuanceRequestSecret {
            d: Scalar::random(&mut rand::thread_rng()),
            m_1,
            m_2,
        }
    }
}

pub struct BlindIssuanceRequest {
    enc_m_1: (CompressedRistretto, CompressedRistretto),
    enc_m_2: (CompressedRistretto, CompressedRistretto),
    D: CompressedRistretto,
    proof: CompactProof,
}

impl BlindIssuanceRequest {
    fn new(sk: &BlindIssuanceRequestSecret, transcript: &mut Transcript) -> Self {
        let mut rng = rand::thread_rng();

        let pg = PedersenGens::default();

        let e_1 = Scalar::random(&mut rng);
        let e_2 = Scalar::random(&mut rng);

        let D = sk.d * pg.B;

        let enc_m_1 = (e_1 * pg.B, sk.m_1 * pg.B + e_1 * D);
        let enc_m_2 = (e_2 * pg.B, sk.m_2 * pg.B + e_2 * D);

        use self::proofs::cred_issue_2_blind_user::*;

        let (proof, points) = prove_compact(
            transcript,
            ProveAssignments {
                d: &sk.d,
                e_1: &e_1,
                e_2: &e_2,
                m_1: &sk.m_1,
                m_2: &sk.m_2,
                E_1_0: &enc_m_1.0,
                E_1_1: &enc_m_1.1,
                E_2_0: &enc_m_2.0,
                E_2_1: &enc_m_2.1,
                D: &D,
                B: &pg.B,
            },
        );

        BlindIssuanceRequest {
            enc_m_1: (points.E_1_0, points.E_1_1),
            enc_m_2: (points.E_2_0, points.E_2_1),
            D: points.D,
            proof,
        }
    }
}

pub struct BlindIssuanceResponse {
    P: RistrettoPoint,
    T_1: RistrettoPoint,
    T_2: RistrettoPoint,
    enc_Q: (RistrettoPoint, RistrettoPoint),
    proof: CompactProof,
}

impl IssuerKeypair {
    fn blind_issue(
        &self,
        transcript: &mut Transcript,
        req: &BlindIssuanceRequest,
    ) -> Result<BlindIssuanceResponse, ()> {
        let pg = PedersenGens::default();

        use self::proofs::cred_issue_2_blind_issuer as issuer_proof;
        use self::proofs::cred_issue_2_blind_user as user_proof;

        // First, verify the request is well-formed:
        user_proof::verify_compact(
            &req.proof,
            transcript,
            user_proof::VerifyAssignments {
                E_1_0: &req.enc_m_1.0,
                E_1_1: &req.enc_m_1.1,
                E_2_0: &req.enc_m_2.0,
                E_2_1: &req.enc_m_2.1,
                D: &req.D,
                B: &pg.B.compress(),
            },
        )?;

        // Now issue the credential

        let mut rng = rand::thread_rng();

        let b = Scalar::random(&mut rng);
        let P = b * pg.B;

        let s = Scalar::random(&mut rng);

        let b_x_1 = b * self.sk.x_1;
        let b_x_2 = b * self.sk.x_2;

        let enc_Q = (
            // sB + b*x_1*Enc(m_1)[0] + b*x_2*Enc(m_2)[0]
            RistrettoPoint::multiscalar_mul(
                &[s, b_x_1, b_x_2],
                &[pg.B, req.enc_m_1.0, req.enc_m_2.0],
            ),
            // sD + x_0*P + b*x_1*Enc(m_1)[0] + b*x_2*Enc(m_2)[0]
            RistrettoPoint::multiscalar_mul(
                &[s, self.sk.x_0, b_x_1, b_x_2],
                &[req.D, P, req.enc_m_1.1, req.enc_m_2.1],
            ),
        );

        let t_1 = b * self.sk.x_1;
        let T_1 = b * self.pk.X_1;
        let t_2 = b * self.sk.x_2;
        let T_2 = b * self.pk.X_2;

        let (proof, _points) = issuer_proof::prove_compact(
            transcript,
            issuer_proof::ProveAssignments {
                X_0: &self.pk.X_0,
                X_1: &self.pk.X_1,
                X_2: &self.pk.X_2,
                A: &pg.A,
                B: &pg.B,
                P: &P,
                D: &req.D,
                T_1a: &T_1,
                T_1b: &T_1,
                T_2a: &T_2,
                T_2b: &T_2,
                E_Q_0: &enc_Q.0,
                E_Q_1: &enc_Q.1,
                E_1_0: &req.enc_m_1.0,
                E_1_1: &req.enc_m_1.1,
                E_2_0: &req.enc_m_2.0,
                E_2_1: &req.enc_m_2.1,
                x_0_blinding: &self.sk.x_0_blinding,
                x_0: &self.sk.x_0,
                x_1: &self.sk.x_1,
                x_2: &self.sk.x_2,
                b: &b,
                s: &s,
                t_1: &t_1,
                t_2: &t_2,
            },
        );

        Ok(BlindIssuanceResponse {
            P,
            T_1,
            T_2,
            enc_Q,
            proof,
        })
    }
}

impl BlindIssuanceResponse {
    fn validate(
        self,
        req: &BlindIssuanceRequest,
        sk: &BlindIssuanceRequestSecret,
        pk: &IssuerPublic,
        transcript: &mut Transcript,
    ) -> Result<Credential, ()> {
        let pg = PedersenGens::default();

        use self::proofs::cred_issue_2_blind_issuer::*;

        verify_compact(
            &self.proof,
            transcript,
            VerifyAssignments {
                X_0: &pk.X_0,
                X_1: &pk.X_1,
                X_2: &pk.X_2,
                A: &pg.A,
                B: &pg.B,
                P: &self.P,
                D: &req.D,
                T_1a: &self.T_1,
                T_1b: &self.T_1,
                T_2a: &self.T_2,
                T_2b: &self.T_2,
                E_Q_0: &self.enc_Q.0,
                E_Q_1: &self.enc_Q.1,
                E_1_0: &req.enc_m_1.0,
                E_1_1: &req.enc_m_1.1,
                E_2_0: &req.enc_m_2.0,
                E_2_1: &req.enc_m_2.1,
            },
        )?;

        let Q = self.enc_Q.1 - sk.d * self.enc_Q.0;

        Ok(Credential {
            m_1: sk.m_1,
            m_2: sk.m_2,
            tag: Tag { P: self.P, Q },
        })
    }
}

pub struct CredentialPresentation {
    tag: Tag,
    C_Q: RistrettoPoint,
    C_m_1: RistrettoPoint,
    C_m_2: RistrettoPoint,
    V: RistrettoPoint,
    proof: CompactProof,
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

        let proof = prove_compact(
            transcript,
            ProveAssignments {
                X_1: &pk.X_1,
                X_2: &pk.X_2,
                A: &pg.A,
                V: &V,
                P: &tag.P,
                C_m_1: &C_m_1,
                C_m_2: &C_m_2,
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

        verify_compact(
            &pres.proof,
            transcript,
            VerifyAssignments {
                X_1: &self.pk.X_1,
                X_2: &self.pk.X_2,
                A: &pg.A,
                V: &V_prime,
                P: &pres.tag.P,
                C_m_1: &pres.C_m_1,
                C_m_2: &pres.C_m_2,
            },
        ).map_err(|_discard_error| ())?
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
        let response = keypair.clear_issue(&mut issuer_transcript, &req);

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
            let response = keypair.clear_issue(&mut issuer_transcript, &req);

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

    #[test]
    fn blind_issue() {
        let keypair = IssuerKeypair::default();
        let pk = keypair.pk.clone();

        let mut user_transcript = Transcript::new(b"BlindIssueDemo");
        let mut issuer_transcript = Transcript::new(b"BlindIssueDemo");

        let req_sk = BlindIssuanceRequestSecret::new(1u64.into(), 2u64.into());
        let req = BlindIssuanceRequest::new(&req_sk, &mut user_transcript);

        let resp = keypair.blind_issue(&mut issuer_transcript, &req).unwrap();

        let issuance_result = resp.validate(&req, &req_sk, &pk, &mut user_transcript);

        assert!(issuance_result.is_ok());
    }

    #[test]
    fn check_blind_issue_presentation() {
        let keypair = IssuerKeypair::default();
        let pk = keypair.pk.clone();

        // Wrap credential issuance (test setup) in its own scope
        let cred = {
            let mut user_transcript = Transcript::new(b"BlindIssueDemo");
            let mut issuer_transcript = Transcript::new(b"BlindIssueDemo");

            let req_sk = BlindIssuanceRequestSecret::new(1u64.into(), 2u64.into());
            let req = BlindIssuanceRequest::new(&req_sk, &mut user_transcript);

            let resp = keypair.blind_issue(&mut issuer_transcript, &req).unwrap();

            let issuance_result = resp.validate(&req, &req_sk, &pk, &mut user_transcript);

            issuance_result.unwrap()
        };

        let mut client_transcript = Transcript::new(b"CredShowDemo");
        let presentation = cred.present(&pk, &mut client_transcript);

        let mut issuer_transcript = Transcript::new(b"CredShowDemo");
        let pres_result = keypair.verify_presentation(&presentation, &mut issuer_transcript);

        assert!(pres_result.is_ok());
    }
}
