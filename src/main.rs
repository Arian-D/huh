use base64::{engine, engine::general_purpose, read, read::DecoderReader};
use clap::Parser;
use clap::ValueEnum;
use regex::Regex;
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use url::Url;

/// Analyze input
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The text to analyze
    #[arg(long)]
    text: String,
    #[arg(long, default_value_t = Severity::Medium, value_enum)]
    severity: Severity,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum Severity {
    // Don't publicize, don't upload file; just look without someone knowing you're looking
    Low,
    // Look up hashes, look up stuff on online databses, but don't do anything intrusive
    Medium,
    // Anything like port scans, vuln scan, and other aggressive methods
    GoWild,
}


fn main() {
    let args = Args::parse();
    // dbg!(args);
    detect(args.text).map(analyze);
}

#[derive(Debug)]
enum Thing {
    Base64(String),
    File(PathBuf),
    Ip(IpAddr),
    Uri(Url),
    Other(String),
}


/// Detect what we're dealing with
fn detect(text: String) -> Option<Thing> {
    // Check for base64
    // TODO: Change it to only detection and *not* decoding
    let mut reader = Cursor::new(text.clone().into_bytes());
    let mut decoder = read::DecoderReader::new(&mut reader, &general_purpose::STANDARD);
    let mut result = String::new();
    if let Ok(_) = decoder.read_to_string(&mut result) {
        return Some(Thing::Base64(result));
    }

    // Check for IP address
    let ip = text.parse::<IpAddr>();
    if let Ok(ip) = ip {
        return Some(Thing::Ip(ip));
    }

    // Check for URIs
    if let Ok(uri) = Url::parse(text.as_str()) {
        return Some(Thing::Uri(uri));
    }
    
    let path = PathBuf::from(text);
    if path.exists() {
        return Some(Thing::File(path));
    }
    None
}

/// Do things based on the input and severity
fn analyze(thing: Thing) {
    println!("We're dealing with a {thing:?}");
    match thing {
        Thing::Base64(text) => {
            detect(text).map(analyze);
        },
        Thing::Ip(ip) => {
            analyze_ip(ip);
        },
        other_thing => eprintln!("{other_thing:?} not yet implemented. Sowwy")
    }
}

fn analyze_ip(ip: IpAddr) -> Thing {
    Thing::Other(String::from("Not yet implemented"))
}

fn analyze_file(file_path: PathBuf) {
    eprintln!("Not implemented yet bozo")
    // TODO
}
