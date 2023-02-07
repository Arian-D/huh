use base64::{engine, engine::general_purpose, read, read::DecoderReader};
use clap::Parser;
use regex::Regex;
use std::io::Cursor;
use std::io::Read;

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

    analyze(args.text);
}

fn analyze(text: String) {
    // Check for base64
    let mut reader = Cursor::new(text.into_bytes());
    let mut decoder = read::DecoderReader::new(&mut reader, &general_purpose::STANDARD);
    let mut result = String::new();
    //.decoder.read_to_string(&mut result);
    if let Ok(_) = decoder.read_to_string(&mut result) {
        println!("{result}");
        return;
    }

    // if Regex::new(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$")
    //     .unwrap()
    //     .is_match(text.as_str())
    // {
    //     println!("It's base64");
    // } else {
    //     println!("It's not");
    // }
}
