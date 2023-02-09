use base64::{engine, engine::general_purpose, read, read::DecoderReader};
use clap::Parser;
use regex::Regex;
use std::io::Cursor;
use std::io::Read;
use std::path::PathBuf;
use std::net::IpAddr;

#[derive(Debug)]
enum Thing {
    Base64(String),
    File(PathBuf),
    Ip(IpAddr),
}

/// Analyze input
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The text to analyze
    #[arg(long)]
    text: String,
}

fn main() {
    let args = Args::parse();

    // dbg!(args);
    detect(args.text).map(analyze);
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

    None
}

/// Do things based on the 
fn analyze(thing: Thing) {
    println!("{thing:?}")
}
