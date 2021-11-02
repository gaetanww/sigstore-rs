//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate sigstore;
use sigstore::cosign::CosignCapabilities;
use sigstore::simple_signing::SimpleSigning;

extern crate anyhow;
use anyhow::Result;

use std::io::prelude::*;
use std::{collections::HashMap, fs::File};

extern crate clap;
use clap::{App, Arg};

extern crate tracing_subscriber;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

fn cli() -> App<'static, 'static> {
    App::new("verify")
        .about("verify a container image")
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("KEY")
                .help("Verification Key")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rekor-pub-key")
                .long("rekor-pub-key")
                .value_name("KEY")
                .help("File containing Rekor public key (e.g.: ~/.sigstore/root/targets/rekor.pub)")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("annotations")
                .short("a")
                .long("annotation")
                .value_name("PAIR")
                .help("Annotations that have to be satisfied")
                .required(false)
                .multiple(true)
                .number_of_values(1)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .help("Enable verbose mode"),
        )
        .arg(
            Arg::with_name("IMAGE")
                .help("Name of the image to use")
                .required(true)
                .index(1),
        )
}

async fn run_app() -> Result<Vec<SimpleSigning>> {
    let matches = cli().get_matches();

    let auth = &sigstore::registry::Auth::Anonymous;

    let mut rekor_pub_key_file = File::open(matches.value_of("rekor-pub-key").unwrap())?;
    let mut rekor_pub_key = String::new();
    rekor_pub_key_file.read_to_string(&mut rekor_pub_key)?;

    let mut client = sigstore::cosign::ClientBuilder::default()
        .with_rekor_pub_key(&rekor_pub_key)
        .build()
        .unwrap();

    let image: &str = matches.value_of("IMAGE").unwrap();

    let (cosign_signature_image, source_image_digest) = client.triangulate(image, auth).await?;

    let mut pub_key_file = File::open(matches.value_of("key").unwrap())?;
    let mut pub_key = String::new();
    pub_key_file.read_to_string(&mut pub_key)?;

    let annotations: Option<HashMap<String, String>>;
    annotations = match matches.values_of("annotations") {
        None => None,
        Some(items) => {
            let mut values: HashMap<String, String> = HashMap::new();
            for item in items {
                let tmp: Vec<_> = item.splitn(2, "=").collect();
                if tmp.len() == 2 {
                    values.insert(String::from(tmp[0]), String::from(tmp[1]));
                }
            }
            if values.is_empty() {
                None
            } else {
                Some(values)
            }
        }
    };

    // setup logging
    let level_filter = if matches.is_present("verbose") {
        "debug"
    } else {
        "info"
    };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    client
        .verify(
            auth,
            &source_image_digest,
            &cosign_signature_image,
            &pub_key,
            annotations,
        )
        .await
}

#[tokio::main]
pub async fn main() {
    let satistied_simple_signatures: Result<Vec<SimpleSigning>> = run_app().await;

    std::process::exit(match satistied_simple_signatures {
        Ok(signatures) => {
            if signatures.is_empty() {
                eprintln!("Image verification failed: no matching signature found.");
                1
            } else {
                println!("Image successfully verified");
                for signature in signatures {
                    println!("{}", signature);
                }
                0
            }
        }
        Err(err) => {
            eprintln!("Image verification failed: {:?}", err);
            1
        }
    });
}
