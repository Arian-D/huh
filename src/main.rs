use base64::{engine, engine::general_purpose, read, read::DecoderReader};
use clap::Parser;
use clap::ValueEnum;
use regex::Regex;
use reqwest::blocking::get;
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Error;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::str::from_utf8;
use url::Url;
use serde_json::{from_str, Value, json};
use serde::{Serialize, Deserialize};

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

static USER_AGENT: &str = "some-bot/1.2.3";

fn main() {
    let args = Args::parse();
    // dbg!(args);
    detect(args.text).map(analyze);
}

#[derive(Debug)]
enum Thing {
    Base64(String),
    File(PathBuf),
    Email(String),
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

    // Check for files
    let path = PathBuf::from(text.clone());
    if path.exists() {
        return Some(Thing::File(path));
    }

    // Check for email
    let email_regex = Regex::new(r"(?i-u)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b").unwrap();
    if let Some(email) = email_regex.find(text.as_str()) {
        return Some(Thing::Email(String::from(email.as_str())));
    }

    // TODO: Phone number
    None
}

/// Do things based on the input and severity
fn analyze(thing: Thing) {
    println!("We're dealing with a {thing:?}");
    match thing {
        Thing::Base64(text) => {
            detect(text).map(analyze);
        }
        Thing::Ip(ip) => {
            analyze_ip(ip);
        }
        Thing::File(path) => {
            analyze_file(path);
        }
        Thing::Email(email) => {
            analyze_email(email);
        }
        other_thing => eprintln!("{other_thing:?} not yet implemented. Sowwy"),
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct IPGeoResp {
    isp: String,
    org: String,
}

fn analyze_ip(ip: IpAddr) {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        println!("Don't know what to do with {ip}");
    }
    // TODO: nmap etc
    // https://api.techniknews.net/ipgeo
    let resp = get(format!("https://api.techniknews.net/ipgeo/{ip}"))
        .and_then(|r| r.json::<IPGeoResp>());
    if let Ok(resp) = resp {
        println!("ISP: {}", resp.isp);
        println!("Organization: {}", resp.org);
    }
}

/// incomplete list of filetypes as a FileType
#[derive(Debug)]
enum FileType {
    Pdf,
    Png,
    Jpg,
    Mp4,
    Unknown(String),
}

/// Analyze file (WIP)
fn analyze_file(file_path: PathBuf) {
    // TODO: Move the detection to another function
    let output = Command::new("file")
        .arg("--brief")
        .arg(file_path.clone())
        .output()
        .unwrap()
        .stdout;
    let file_type = from_utf8(&output).unwrap();
    println!("Actual file type → \"{file_type}\" but I won't use it");

    println!("TODO: Virus total of the hash (or content if aggressive/public)");
    if let Some(extension) = file_path.extension() {
        let extension = format!("{extension:?}");
        let file_type: FileType = match extension.as_str() {
            "png" => FileType::Png,
            "jpg" | "jpeg" => FileType::Jpg,
            _ => FileType::Unknown(extension),
        };


        println!("TODO: file carving with binwalk");
        match file_type {
            FileType::Png => {
                println!("TODO: Look at exif data and steg");
                
            }
            other => {
                println!("TODO: Implement analysis for {other:?}");
            }
        }
    }
}

/// Checks email on some online databases
fn analyze_email(email: String) {
    // emailrep.io
    let emailrep_request = Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .unwrap()
        .get(format!("https://emailrep.io/{email}"))
        .send();
    if let Ok(resp) = emailrep_request {
        println!("{}", resp.text().unwrap());
    }
    // eva.pingutil.com
    let eva_request = Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://api.eva.pingutil.com/email?email={email}"))
        .send();
    if let Ok(resp) = eva_request {
        println!("{}", resp.text().unwrap());
    }
    // TODO: Parse results
}
