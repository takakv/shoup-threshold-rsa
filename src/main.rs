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

pub use types::{KeyShare, PublicParameters, SignatureShare, ThresholdParameters, VerifyShare};

use asn1::SignatureShareDer;
use generate::generate;
use loaders::{load_key_share, load_key_shares, load_pub_params, load_signature_shares};
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

        /// Optional output file for the verification share
        #[arg(long = "verify-out")]
        vk_share: Option<PathBuf>,

        /// Minimum number of shares required for signing
        #[arg(short, long)]
        threshold: Option<u16>,

        /// Number of total shareholders
        #[arg(short = 'T', long)]
        total: Option<u16>,
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
            vk_share: _,
            threshold,
            total,
        } => {
            let msg = fs::read(infile).expect("Failed to read message file");
            let (key, pub_params) = load_key_share(key_share);

            let parameters = ThresholdParameters {
                threshold: threshold.unwrap(),
                total_shares: total.unwrap(),
            };

            let mut rng = ChaCha8Rng::from_seed(make_seed(rand, &msg));
            let share_bytes =
                gen_signature_share(&key, &pub_params, &msg, &parameters, &mut rng).to_be_bytes();
            let index_bytes = (key.index - 1).to_be_bytes();

            let sig_share = SignatureShareDer {
                share_index: OctetStringRef::new(&index_bytes).unwrap(),
                signature: UintRef::new(share_bytes.as_ref()).unwrap(),
            };
            fs::write(outfile, sig_share.to_der().unwrap())
                .expect("Failed to write signature share");
        }

        Commands::Combine {
            infile,
            sig_shares,
            pubkey,
            rand,
            threshold,
            total,
            outfile,
        } => {
            let msg = fs::read(infile).expect("Failed to read message file");
            let pub_params = load_pub_params(pubkey);
            let parameters = ThresholdParameters {
                threshold: *threshold,
                total_shares: *total,
            };
            let shares = load_signature_shares(sig_shares);

            let mut rng = ChaCha8Rng::from_seed(make_seed(rand, &msg));
            let signature = combine_shares(&shares, &msg, &pub_params, &parameters, &mut rng);
            fs::write(outfile, &signature).expect("Failed to write signature");
        }

        Commands::Gen {
            threshold,
            total,
            shares_dir,
            vk_dir,
            pubkey_out,
        } => {
            if threshold > total {
                panic!("the threshold is greater than the total share count");
            }
            let parameters = ThresholdParameters {
                threshold: *threshold,
                total_shares: *total,
            };
            generate(512, &parameters, pubkey_out, shares_dir, vk_dir);
        }
    }
}
