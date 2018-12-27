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

    create_nipk!{
        cred_issue_2_blind_user,
        (d, e_1, e_2, m_1, m_2),
        (E_1_0, E_1_1, E_2_0, E_2_1, D, B)
        :
        D = (B * d),
        E_1_0 = (B * e_1),
        E_1_1 = (B * m_1 + D * e_1),
        E_2_0 = (B * e_2),
        E_2_1 = (B * m_2 + D * e_2)
    }

    create_nipk!{
        cred_issue_2_blind_issuer,
        (x_0_blinding, x_0, x_1, x_2, b, s, t_1, t_2),
        (X_0, X_1, X_2, A, B, P, D, T_1a, T_2a, T_1b, T_2b,
         E_Q_0, E_Q_1, E_1_0, E_1_1, E_2_0, E_2_1)
        :
        X_0 = (B * x_0 + A * x_0_blinding),
        X_1 = (A * x_1),
        X_2 = (A * x_2),
        P = (B * b),
        T_1a = (X_1 * b),
        T_1b = (A * t_1),
        T_2a = (X_2 * b),
        T_2b = (A * t_2),
        E_Q_0 = (B * s + E_1_0 * t_1 + E_2_0 * t_2),
        E_Q_1 = (D * s + E_1_1 * t_1 + E_2_1 * t_2 + P * x_0)
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
    proof: proofs::cred_issue_2_clear::Proof,
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
    enc_m_1: (RistrettoPoint, RistrettoPoint),
    enc_m_2: (RistrettoPoint, RistrettoPoint),
    D: RistrettoPoint,
    proof: proofs::cred_issue_2_blind_user::Proof,
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

        BlindIssuanceRequest {
            enc_m_1,
            enc_m_2,
            D,
            proof: Proof::create(
                transcript,
                Publics {
                    E_1_0: &enc_m_1.0,
                    E_1_1: &enc_m_1.1,
                    E_2_0: &enc_m_2.0,
                    E_2_1: &enc_m_2.1,
                    D: &D,
                    B: &pg.B,
                },
                Secrets {
                    d: &sk.d,
                    e_1: &e_1,
                    e_2: &e_2,
                    m_1: &sk.m_1,
                    m_2: &sk.m_2,
                },
            ),
        }
    }
}

pub struct BlindIssuanceResponse {
    P: RistrettoPoint,
    T_1: RistrettoPoint,
    T_2: RistrettoPoint,
    enc_Q: (RistrettoPoint, RistrettoPoint),
    proof: proofs::cred_issue_2_blind_issuer::Proof,
}

impl IssuerKeypair {
    fn blind_issue(
        &self,
        transcript: &mut Transcript,
        req: &BlindIssuanceRequest,
    ) -> Result<BlindIssuanceResponse, ()> {
        let pg = PedersenGens::default();

        // First, verify the request is well-formed:
        let req_well_formed = {
            use self::proofs::cred_issue_2_blind_user::*;

            req.proof.verify(
                transcript,
                Publics {
                    E_1_0: &req.enc_m_1.0,
                    E_1_1: &req.enc_m_1.1,
                    E_2_0: &req.enc_m_2.0,
                    E_2_1: &req.enc_m_2.1,
                    D: &req.D,
                    B: &pg.B,
                },
            )
        };

        if req_well_formed.is_err() {
            return Err(());
        }

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

        use self::proofs::cred_issue_2_blind_issuer::*;

        Ok(BlindIssuanceResponse {
            P,
            T_1,
            T_2,
            enc_Q,
            proof: Proof::create(
                transcript,
                Publics {
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
                },
                Secrets {
                    x_0_blinding: &self.sk.x_0_blinding,
                    x_0: &self.sk.x_0,
                    x_1: &self.sk.x_1,
                    x_2: &self.sk.x_2,
                    b: &b,
                    s: &s,
                    t_1: &t_1,
                    t_2: &t_2,
                },
            ),
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

        let resp_result = self.proof.verify(
            transcript,
            Publics {
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
        );

        if resp_result.is_err() {
            return Err(());
        }

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
