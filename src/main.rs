use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use der::asn1::{OctetStringRef, UintRef};
use der::Encode;
use rand::rand_core::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

mod arithmetic;
mod asn1;
mod convert;
mod generate;
mod loaders;
mod pss;
mod signature;
mod types;
mod zkp;

pub use types::{
    KeyShare, PublicParameters, ShareProof, SignatureShare, ThresholdParameters, VerifyShare,
};

use asn1::{CorrectnessProofDer, ShoupVerificationKey, SignatureShareDer};
use crypto_bigint::modular::BoxedMontyForm;
use crypto_bigint::BoxedUint;
use der::Decode;
use generate::generate;
use loaders::{
    load_key_share, load_key_shares, load_pub_params, load_signature_shares, load_verify_shares,
};
use signature::{combine_shares, gen_signature_share, threshold_sign};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sign a message using private key shares
    Sign {
        /// File to read the data from
        #[arg(long = "in", short)]
        infile: PathBuf,

        /// Filename to output the signature to
        #[arg(long = "out", short)]
        outfile: PathBuf,

        /// Directory containing the private key shares
        shares: PathBuf,

        /// Minimum number of shares required for signing
        #[arg(short, long)]
        threshold: Option<u16>,

        /// Number of total shareholders
        #[arg(short = 'T', long)]
        total: Option<u16>,
    },

    /// Compute a signature share for a message using a single key share
    Mint {
        /// File to read the message from
        #[arg(long = "in", short)]
        infile: PathBuf,

        /// Key share file
        #[arg(long = "key-share", short = 'k')]
        key_share: PathBuf,

        /// Output file for the signature share
        #[arg(long = "out", short)]
        outfile: PathBuf,

        /// File whose bytes are used as the PRNG seed (defaults to SHA-256 of the input file)
        #[arg(long = "rand")]
        rand: Option<PathBuf>,

        /// Include a zero-knowledge proof of correct signing
        #[arg(long)]
        provable: bool,
    },

    /// Combine signature shares into a full signature
    Combine {
        /// File to read the message from
        #[arg(long = "in", short)]
        infile: PathBuf,

        /// Directory containing the signature shares
        sig_shares: PathBuf,

        /// Public key file
        #[arg(long = "pub", short)]
        pubkey: PathBuf,

        /// Verification key file
        #[arg(long = "vk")]
        vk: Option<PathBuf>,

        /// Directory containing the per-share verification keys
        #[arg(long = "vk-shares")]
        vk_shares: Option<PathBuf>,

        /// File whose bytes are used as the PRNG seed (defaults to SHA-256 of the input file)
        #[arg(long = "rand")]
        rand: Option<PathBuf>,

        /// Minimum number of shares required for signing
        #[arg(short, long)]
        threshold: u16,

        /// Total number of shareholders
        #[arg(short = 'T', long)]
        total: u16,

        /// Output file for the combined signature
        #[arg(long = "out", short)]
        outfile: PathBuf,
    },

    /// Generate key shares and the public key
    Gen {
        /// RSA key size in bits (2048, 3072, or 4096)
        #[arg(long, short = 'b', default_value_t = 3072)]
        bits: u32,

        /// Minimum number of shares required for signing
        #[arg(short, long)]
        threshold: u16,

        /// Number of total shareholders
        #[arg(short = 'T', long)]
        total: u16,

        /// Directory to output the generated key shares to
        shares_dir: PathBuf,

        /// Directory to output the generated verification shares to
        vk_dir: PathBuf,

        /// Filename to output the public key to
        #[arg(long = "pub", short)]
        pubkey_out: PathBuf,
    },
}

fn make_seed(rand: &Option<PathBuf>, msg: &[u8]) -> [u8; 32] {
    match rand {
        Some(path) => {
            let bytes = fs::read(path).expect("Failed to read rand file");
            assert!(bytes.len() >= 32, "rand file must be at least 32 bytes");
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            seed
        }
        None => Sha256::digest(msg).into(),
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Sign {
            infile,
            outfile,
            shares,
            threshold,
            total,
        } => {
            let msg = fs::read(infile).expect("Failed to read message file");

            let entries = fs::read_dir(shares).expect("Failed to list shares directory");
            let (key_shares, pub_params) = load_key_shares(entries);

            let num_shares = key_shares.len() as u16;
            let threshold = threshold.unwrap_or(num_shares);
            let total_shares = total.unwrap_or(num_shares);

            if key_shares.len() < threshold as usize {
                panic!("not enough secret shares");
            }
            if threshold > total_shares {
                panic!("the threshold is greater than the total share count");
            }

            let parameters = ThresholdParameters {
                threshold,
                total_shares,
            };
            let signature = threshold_sign(
                &key_shares,
                &pub_params,
                &msg,
                &parameters,
                false,
                &mut OsRng,
            );
            fs::write(outfile, &signature).expect("Failed to write signature to file");
        }

        Commands::Mint {
            infile,
            key_share,
            outfile,
            rand,
            provable,
        } => {
            let msg = fs::read(infile).unwrap_or_else(|e| {
                eprintln!("error: failed to read {}: {}", infile.display(), e);
                std::process::exit(1);
            });
            let (key, pub_params, vk, total_shares) = load_key_share(key_share);

            if *provable && vk.is_none() {
                eprintln!(
                    "error: --provable requires a verification key embedded in the key share"
                );
                std::process::exit(1);
            }

            let mut rng = ChaCha8Rng::from_seed(make_seed(rand, &msg));
            let (share, proof) = gen_signature_share(
                &key,
                &pub_params,
                &msg,
                total_shares,
                vk.as_ref().filter(|_| *provable),
                &mut rng,
            );

            let share_bytes = share.to_be_bytes();
            let index_bytes = (key.index - 1).to_be_bytes();

            let proof_der = proof.map(|p| {
                let c_bytes = p.challenge.to_be_bytes();
                let z_bytes = p.response.to_be_bytes();
                CorrectnessProofDer {
                    c: UintRef::new(c_bytes.as_ref()).unwrap(),
                    z: UintRef::new(z_bytes.as_ref()).unwrap(),
                }
                .to_der()
                .unwrap()
            });

            let sig_share = SignatureShareDer {
                share_index: OctetStringRef::new(&index_bytes).unwrap(),
                signature: UintRef::new(share_bytes.as_ref()).unwrap(),
                proof: proof_der
                    .as_deref()
                    .map(|b| OctetStringRef::new(b).unwrap()),
            };
            if let Err(e) = fs::write(outfile, sig_share.to_der().unwrap()) {
                eprintln!("error: failed to write {}: {}", outfile.display(), e);
                std::process::exit(1);
            }
        }

        Commands::Combine {
            infile,
            sig_shares,
            pubkey,
            vk,
            vk_shares,
            rand,
            threshold,
            total,
            outfile,
        } => {
            match (vk, vk_shares) {
                (Some(_), None) | (None, Some(_)) => {
                    eprintln!("error: --vk and --vk-shares must be provided together");
                    std::process::exit(1);
                }
                _ => {}
            }

            let msg = fs::read(infile).expect("Failed to read message file");
            let pub_params = load_pub_params(pubkey);
            let parameters = ThresholdParameters {
                threshold: *threshold,
                total_shares: *total,
            };
            let signature_shares = load_signature_shares(sig_shares);

            let vk_data = match (vk, vk_shares) {
                (Some(vk_path), Some(vk_shares_path)) => {
                    let vk_der = fs::read(vk_path).expect("Failed to read verification key");
                    let svk = ShoupVerificationKey::from_der(&vk_der)
                        .expect("Failed to decode verification key");
                    let mp = &pub_params.monty_params;
                    let v = BoxedUint::from_be_slice(svk.vk.as_bytes(), mp.bits_precision())
                        .expect("Failed to parse verification key bytes");
                    let vk_monty = BoxedMontyForm::new(v, mp.clone());

                    let entries =
                        fs::read_dir(vk_shares_path).expect("Failed to read vk-shares directory");
                    let verification_shares = load_verify_shares(entries, mp);

                    Some((vk_monty, verification_shares))
                }
                _ => None,
            };

            let mut rng = ChaCha8Rng::from_seed(make_seed(rand, &msg));
            let signature = combine_shares(
                &signature_shares,
                &msg,
                &pub_params,
                &parameters,
                vk_data.as_ref().map(|(v, s)| (v, s)),
                &mut rng,
            );
            fs::write(outfile, &signature).expect("Failed to write signature");
        }

        Commands::Gen {
            bits,
            threshold,
            total,
            shares_dir,
            vk_dir,
            pubkey_out,
        } => {
            #[cfg(not(debug_assertions))]
            if ![2048u32, 3072, 4096].contains(bits) {
                eprintln!(
                    "error: key size must be 2048, 3072, or 4096 bits (got {})",
                    bits
                );
                std::process::exit(1);
            }
            if threshold > total {
                panic!("the threshold is greater than the total share count");
            }
            let parameters = ThresholdParameters {
                threshold: *threshold,
                total_shares: *total,
            };
            generate(*bits, &parameters, pubkey_out, shares_dir, vk_dir);
        }
    }
}
