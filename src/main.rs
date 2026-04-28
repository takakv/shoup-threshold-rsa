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
use der::Decode;
use rug::{integer::Order, Integer};

mod arithmetic;
mod asn1;
mod convert;
mod generate;
mod pss;
mod signature;
mod zkp;

use asn1::{ShamirSecretShare, ShoupKeyShare, ShoupVerifyShare, SignatureShareDer};
use der::{
    asn1::{OctetStringRef, UintRef},
    Encode,
};
use generate::generate;
use rand::rand_core::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use signature::{combine_shares, gen_signature_share, threshold_sign};

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

fn load_pub_params(pem_path: impl AsRef<std::path::Path>) -> PublicParameters {
    let pub_key =
        rsa::RsaPublicKey::read_public_key_pem_file(pem_path).expect("Failed to read public key");

    let n = Integer::from_digits(&pub_key.n().to_bytes_be(), Order::Msf);
    let e = Integer::from_digits(&pub_key.e().to_bytes_be(), Order::Msf);

    let n_words = n.to_digits::<Word>(Order::Lsf);
    let n_odd = BoxedUint::from_words(n_words)
        .to_odd()
        .expect("RSA modulus is not odd");
    let byte_len = n_odd.bytes_precision();
    let monty_params = BoxedMontyParams::new(n_odd);

    PublicParameters {
        n,
        e,
        byte_len,
        monty_params,
    }
}

fn load_signature_shares(dir: impl AsRef<std::path::Path>) -> Vec<SignatureShare> {
    let mut shares = Vec::new();
    for entry in fs::read_dir(dir).expect("Failed to read signature shares dir") {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let data = fs::read(&path).expect("Failed to read signature share");
        let der = SignatureShareDer::from_der(&data).expect("Failed to decode signature share");

        let bytes = der.share_index.as_bytes();
        let mut buf = [0u8; 2];
        buf[2 - bytes.len()..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let signature = Integer::from_digits(der.signature.as_bytes(), Order::Msf);
        shares.push(SignatureShare { index, signature });
    }
    shares
}

fn load_key_share(path: impl AsRef<std::path::Path>) -> (KeyShare, PublicParameters) {
    let data = fs::read(path).expect("Failed to read key share file");
    let shamir = ShamirSecretShare::from_der(&data).expect("Failed to decode Shamir secret share");

    let bytes = shamir.share_index.as_bytes();
    let mut buf = [0u8; 2];
    buf[2 - bytes.len()..].copy_from_slice(bytes);
    let index = u16::from_be_bytes(buf) + 1;

    let rsa_share = ShoupKeyShare::from_der(shamir.secret_share.as_bytes())
        .expect("Failed to decode RSA share");

    let n = Integer::from_digits(rsa_share.n.as_bytes(), Order::Msf);
    let e = Integer::from_digits(rsa_share.e.as_bytes(), Order::Lsf);

    let n_words = n.to_digits::<Word>(Order::Lsf);
    let n_odd = BoxedUint::from_words(n_words)
        .to_odd()
        .expect("RSA modulus is not odd");
    let bits_precision = 8 * n_odd.bytes_precision() as u32;

    let params = PublicParameters {
        n,
        e,
        byte_len: n_odd.bytes_precision(),
        monty_params: BoxedMontyParams::new(n_odd),
    };

    let d = BoxedUint::from_be_slice(rsa_share.d.as_bytes(), bits_precision)
        .expect("Failed to build BoxedUint");

    (KeyShare { index, d }, params)
}

fn load_key_shares<I>(entries: I) -> (Vec<KeyShare>, PublicParameters)
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut key_shares = Vec::new();
    let mut params: Option<PublicParameters> = None;
    let mut bits_precision = 0;

    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        };

        let data = fs::read(&path).expect("Failed to read share file");
        let shamir_share =
            ShamirSecretShare::from_der(&data).expect("Failed to decode Shamir secret share");

        let bytes = shamir_share.share_index.as_bytes();
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let rsa_share = ShoupKeyShare::from_der(shamir_share.secret_share.as_bytes())
            .expect("Failed to decode RSA share");

        if params.is_none() {
            let n = Integer::from_digits(rsa_share.n.as_bytes(), Order::Msf);
            let e = Integer::from_digits(rsa_share.e.as_bytes(), Order::Lsf);

            let n_words = n.to_digits::<Word>(Order::Lsf);
            let n_boxed = BoxedUint::from_words(n_words);
            let n_odd = n_boxed.to_odd().expect("RSA modulus is not odd");

            bits_precision = 8 * n_odd.bytes_precision() as u32;

            params = Some(PublicParameters {
                n,
                e,
                byte_len: n_odd.bytes_precision(),
                monty_params: BoxedMontyParams::new(n_odd),
            });
        }

        let d_boxed = BoxedUint::from_be_slice(rsa_share.d.as_bytes(), bits_precision)
            .expect("Failed to build BoxedUint");
        key_shares.push(KeyShare { index, d: d_boxed });
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
        let verify_share =
            ShoupVerifyShare::from_der(&data).expect("Failed to decode verification share");

        let bytes = verify_share.share_index.as_bytes();
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let vk = BoxedMontyForm::new(
            BoxedUint::from_be_slice(verify_share.public_share.as_bytes(), mp.bits_precision())
                .unwrap(),
            mp.clone(),
        );

        verify_shares.insert(index, VerifyShare { index, vk });
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

            let signature = threshold_sign(
                &key_shares,
                &pub_params,
                &msg,
                &parameters,
                provable,
                &mut OsRng,
            );
            fs::write(&outfile, &signature).expect("Failed to write signature to file");
        }
        Commands::Mint {
            infile,
            key_share,
            outfile,
            vk_share: _vk_share,
            threshold,
            total,
        } => {
            let msg = fs::read(infile).expect("Failed to read message file");
            let (key, pub_params) = load_key_share(key_share);

            let threshold = threshold.unwrap();
            let total_shares = total.unwrap();

            let parameters = ThresholdParameters {
                threshold,
                total_shares,
            };

            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(b"seed");
            let mut rng = ChaCha8Rng::from_seed(seed);
            let share_bytes =
                gen_signature_share(&key, &pub_params, &msg, &parameters, &mut rng).to_be_bytes();
            let index_bytes = (key.index - 1).to_be_bytes();

            let signature_share = SignatureShareDer {
                share_index: OctetStringRef::new(&index_bytes).unwrap(),
                signature: UintRef::new(share_bytes.as_ref()).unwrap(),
            };
            fs::write(outfile, signature_share.to_der().unwrap())
                .expect("Failed to write signature share");
        }
        Commands::Combine {
            infile,
            sig_shares,
            pubkey,
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
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(b"seed");
            let mut rng = ChaCha8Rng::from_seed(seed);
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
            println!(
                "Generating keys with threshold={}, total={}, shares_dir={:?}, vk_dir={:?}, pubkey_out={:?}",
                threshold, total, shares_dir, vk_dir, pubkey_out
            );

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
