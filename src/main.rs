use std::{
    collections::HashMap,
    fs::{self},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams}, BitOps, BoxedUint,
    Word,
};
use rasn::types::IntegerType;
use rug::{integer::Order, Integer};

mod arithmetic;
mod asn1;
mod convert;
mod generate;
mod pss;
mod signature;
mod zkp;

use asn1::{ShamirSecretShare, ShoupKeyShare, ShoupVerifyShare};
use convert::asn1uint_to_boxed_monty;
use generate::generate;
use signature::threshold_sign;

pub struct KeyShare {
    pub index: u16,
    pub d: BoxedUint,
}

pub struct PublicParameters {
    pub n: Integer,
    pub e: Integer,
    pub byte_len: usize,
    pub monty_params: BoxedMontyParams,
}

pub struct VerifyShare {
    pub index: u16,
    pub vk: BoxedMontyForm,
}

pub struct SignatureShare {
    pub index: u16,
    pub signature: Integer,
}

struct ThresholdParameters {
    threshold: u16,
    total_shares: u16,
}

fn load_key_shares<I>(entries: I) -> (Vec<KeyShare>, PublicParameters)
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut key_shares = Vec::new();
    let mut params: Option<PublicParameters> = None;

    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        };

        let data = fs::read(&path).expect("Failed to read share file");
        let shamir_share: ShamirSecretShare =
            rasn::der::decode(&data).expect("Failed to decode Shamir secret share");

        let bytes = &shamir_share.share_index;
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let rsa_share: ShoupKeyShare =
            rasn::der::decode(&shamir_share.secret_share).expect("Failed to decode RSA share");

        let (d_bytes, d_len) = rsa_share.d.to_unsigned_bytes_be();
        let d_boxed = BoxedUint::from_be_slice(d_bytes.as_ref(), (d_len * 8) as u32)
            .expect("Failed to build BoxedUint");
        key_shares.push(KeyShare { index, d: d_boxed });

        if params.is_none() {
            let (n_bytes, _) = rsa_share.n.to_unsigned_bytes_be();
            let n = Integer::from_digits(n_bytes.as_ref(), Order::Msf);

            let (e_bytes, _) = rsa_share.e.to_unsigned_bytes_be();
            let e = Integer::from_digits(e_bytes.as_ref(), Order::Lsf);

            let n_words = n.to_digits::<Word>(Order::Lsf);
            let n_boxed = BoxedUint::from_words(n_words);
            let n_odd = n_boxed.to_odd().expect("RSA modulus is not odd");

            params = Some(PublicParameters {
                n,
                e,
                byte_len: n_odd.bytes_precision(),
                monty_params: BoxedMontyParams::new(n_odd),
            });
        }
    }

    let params = params.expect("Could not parse RSA public parameters");
    (key_shares, params)
}

fn load_verify_shares<I>(entries: I, mp: &BoxedMontyParams) -> HashMap<u16, VerifyShare>
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut verify_shares = HashMap::new();
    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        };

        let data = fs::read(&path).expect("Failed to read share file");
        let verify_share: ShoupVerifyShare =
            rasn::der::decode(&data).expect("Failed to decode verification share");

        let bytes = &verify_share.share_index;
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        verify_shares.insert(
            index,
            VerifyShare {
                index,
                vk: asn1uint_to_boxed_monty(verify_share.public_share, mp),
            },
        );
    }

    verify_shares
}

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

    /// Generate key shares and the public key
    Gen {
        /// Minimum number of shares required for signing
        #[arg(short, long)]
        threshold: u16,

        /// Number of total shareholders
        #[arg(short = 'T', long)]
        total: u16,

        /// Directory to output the generated shares to
        shares_dir: PathBuf,

        /// Filename to output the public key to
        #[arg(long = "pub", short)]
        pubkey_out: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let provable = false;

    match &cli.command {
        Commands::Sign {
            infile,
            outfile,
            shares,
            threshold,
            total,
        } => {
            let msg = fs::read(&infile).expect("Failed to read message file");

            let entries = fs::read_dir(&shares).expect("Failed to list shares directory");
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

            let signature = threshold_sign(&key_shares, &pub_params, &msg, &parameters, provable);
            fs::write(&outfile, &signature).expect("Failed to write signature to file");
        }
        Commands::Gen {
            threshold,
            total,
            shares_dir,
            pubkey_out,
        } => {
            println!(
                "Generating keys with threshold={}, total={}, shares_dir={:?}, pubkey_out={:?}",
                threshold, total, shares_dir, pubkey_out
            );

            if threshold > total {
                panic!("the threshold is greater than the total share count");
            }

            let parameters = ThresholdParameters {
                threshold: *threshold,
                total_shares: *total,
            };

            generate(2048, &parameters, pubkey_out, shares_dir);
        }
    }
}
