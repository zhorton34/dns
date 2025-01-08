```rust
//! A single-file DNS server + minimal client in Rust, demonstrating
//! many of the core RFC 1035 concepts in an educational, end-to-end manner.
//!
//! Features included in this single file:
//! - DNS Message parsing (Header, Question, ResourceRecord).
//! - Basic authoritative data (statically defined zone).
//! - Minimal recursion: if not found in authoritative data, we can do an
//!   upstream DNS query (UDP).
//! - Basic DNS client subroutines for performing queries.
//! - Single UDP socket listener on port 53 (by default).
//! - Can handle simple queries for common record types (A, NS, CNAME, MX, SOA).
//!
//! Run with: `cargo run --bin single_dns` (after placing in a Cargo project).
//! Then, use `dig @127.0.0.1 -p 53 example.com A` to query from local DNS server.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// DNS CLASS constants (for QCLASS, CLASS).
#[allow(dead_code)]
mod dns_class {
    pub const IN: u16 = 1;      // Internet
    pub const ANY: u16 = 255;   // Any class
}

/// DNS TYPE constants (for QTYPE, TYPE).
#[allow(dead_code)]
mod dns_type {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const MX: u16 = 15;
    pub const ANY: u16 = 255;
}

/// A DNSHeader represents the 12-byte header at the start of a DNS message.
#[derive(Debug, Clone)]
struct DNSHeader {
    pub id: u16,
    pub flags: u16,        // QR, OPCODE, AA, TC, RD, RA, Z, RCODE
    pub qdcount: u16,      // # of questions
    pub ancount: u16,      // # of answer RRs
    pub nscount: u16,      // # of authority RRs
    pub arcount: u16,      // # of additional RRs
}

/// A Question in the DNS message question section.
#[derive(Debug, Clone)]
struct DNSQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A Resource Record (RR) – used in Answers, Authority, Additional sections.
#[derive(Debug, Clone)]
struct DNSResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// RData can be many forms. We’ll handle only a subset: A, NS, CNAME, MX, SOA, etc.
#[derive(Debug, Clone)]
enum RData {
    A(Ipv4Addr),
    NS(String),
    CNAME(String),
    MX(u16, String), // (preference, exchange)
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Unknown(Vec<u8>),
}

/// A DNSMessage has: header, questions, answers, authorities, additionals.
#[derive(Debug, Clone)]
struct DNSMessage {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSResourceRecord>,
    pub authorities: Vec<DNSResourceRecord>,
    pub additionals: Vec<DNSResourceRecord>,
}

impl DNSMessage {
    /// Creates an empty DNSMessage for building a response.
    fn new_response(id: u16) -> Self {
        DNSMessage {
            header: DNSHeader {
                id,
                flags: 0,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

// ---------- PACK / UNPACK DNS MESSAGES (Parsing and building) ---------- //

fn parse_dns_message(buffer: &[u8]) -> Result<DNSMessage, String> {
    use std::convert::TryInto;

    if buffer.len() < 12 {
        return Err("Buffer too short for DNS header".to_string());
    }

    let header = DNSHeader {
        id: u16::from_be_bytes(buffer[0..2].try_into().unwrap()),
        flags: u16::from_be_bytes(buffer[2..4].try_into().unwrap()),
        qdcount: u16::from_be_bytes(buffer[4..6].try_into().unwrap()),
        ancount: u16::from_be_bytes(buffer[6..8].try_into().unwrap()),
        nscount: u16::from_be_bytes(buffer[8..10].try_into().unwrap()),
        arcount: u16::from_be_bytes(buffer[10..12].try_into().unwrap()),
    };

    // We'll parse the question section, then answer/authority/additional if needed.
    let mut offset = 12;
    let mut questions = Vec::with_capacity(header.qdcount as usize);

    for _ in 0..header.qdcount {
        let (qname, new_offset) = parse_domain_name(buffer, offset)?;
        offset = new_offset;
        if offset + 4 > buffer.len() {
            return Err("Buffer too short for question fields".to_string());
        }
        let qtype = u16::from_be_bytes(buffer[offset..offset+2].try_into().unwrap());
        let qclass = u16::from_be_bytes(buffer[offset+2..offset+4].try_into().unwrap());
        offset += 4;
        questions.push(DNSQuestion { qname, qtype, qclass });
    }

    let mut msg = DNSMessage {
        header,
        questions,
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    // For simplicity, let's parse answer/authority/additional *only* if needed
    // (We do minimal parsing here)
    for _ in 0..msg.header.ancount {
        let (rr, new_offset) = parse_resource_record(buffer, offset)?;
        offset = new_offset;
        msg.answers.push(rr);
    }
    for _ in 0..msg.header.nscount {
        let (rr, new_offset) = parse_resource_record(buffer, offset)?;
        offset = new_offset;
        msg.authorities.push(rr);
    }
    for _ in 0..msg.header.arcount {
        let (rr, new_offset) = parse_resource_record(buffer, offset)?;
        offset = new_offset;
        msg.additionals.push(rr);
    }

    Ok(msg)
}

/// Parse a DNS domain name starting at `offset`, returning (name, new_offset).
fn parse_domain_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let start_offset = offset;
    let mut jumped = false;
    let mut jump_offset = 0; // track where we jumped, if we do pointer compression

    loop {
        if offset >= buf.len() {
            return Err("Offset out of range while parsing domain".to_string());
        }
        let len = buf[offset];
        offset += 1;
        if len & 0xC0 == 0xC0 {
            // pointer
            if offset >= buf.len() {
                return Err("Offset out of range after pointer bytes".to_string());
            }
            let b2 = buf[offset];
            offset += 1;
            if !jumped {
                jump_offset = offset;
            }
            let pointer = (((len & 0x3F) as u16) << 8) | (b2 as u16);
            if pointer as usize >= buf.len() {
                return Err("Pointer out of range in domain name".to_string());
            }
            let (subname, _) = parse_domain_name(buf, pointer as usize)?;
            labels.push(subname);
            if !jumped {
                offset = jump_offset;
            }
            jumped = true;
            break;
        } else if len == 0 {
            // end of labels
            break;
        } else {
            if offset + (len as usize) > buf.len() {
                return Err("Label length beyond buffer".to_string());
            }
            let label_bytes = &buf[offset..offset + len as usize];
            offset += len as usize;
            let label = String::from_utf8_lossy(label_bytes).to_string();
            labels.push(label);
        }
    }

    let name = if labels.is_empty() {
        // root
        ".".to_owned()
    } else {
        let joined = labels.join(".");
        // handle case: if last label was a pointer
        if jumped {
            joined
        } else {
            joined + "."
        }
    };
    Ok((name, offset))
}

/// Parse a single ResourceRecord from `buf` at `offset`.
fn parse_resource_record(buf: &[u8], offset: usize)
    -> Result<(DNSResourceRecord, usize), String> 
{
    let (name, mut off) = parse_domain_name(buf, offset)?;
    if off + 10 > buf.len() {
        return Err("RR parse: not enough bytes for type/class/ttl/rdlength".to_string());
    }
    let rr_type = u16::from_be_bytes(buf[off..off+2].try_into().unwrap());
    let rr_class = u16::from_be_bytes(buf[off+2..off+4].try_into().unwrap());
    let ttl = u32::from_be_bytes(buf[off+4..off+8].try_into().unwrap());
    let rdlen = u16::from_be_bytes(buf[off+8..off+10].try_into().unwrap()) as usize;
    off += 10;
    if off + rdlen > buf.len() {
        return Err("RR parse: rdata length out of range".to_string());
    }
    let rdata_buf = &buf[off..off + rdlen];
    off += rdlen;

    let rdata = parse_rdata(rr_type, rdata_buf)?;
    let rr = DNSResourceRecord {
        name,
        rr_type,
        rr_class,
        ttl,
        rdata,
    };
    Ok((rr, off))
}

/// Parse RData for known types (A, NS, CNAME, MX, SOA).
fn parse_rdata(rr_type: u16, buf: &[u8]) -> Result<RData, String> {
    use dns_type::*;
    match rr_type {
        A => {
            if buf.len() != 4 {
                return Err("A RDATA must be 4 bytes".to_string());
            }
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            Ok(RData::A(addr))
        }
        NS => {
            let (nsname, _) = parse_domain_name(buf, 0)?;
            Ok(RData::NS(nsname))
        }
        CNAME => {
            let (cname, _) = parse_domain_name(buf, 0)?;
            Ok(RData::CNAME(cname))
        }
        MX => {
            if buf.len() < 2 {
                return Err("MX RDATA too short".to_string());
            }
            let pref = u16::from_be_bytes(buf[0..2].try_into().unwrap());
            let (exchange, _) = parse_domain_name(buf, 2)?;
            Ok(RData::MX(pref, exchange))
        }
        SOA => {
            // parse domain for MNAME, then RNAME, then 20 bytes of numeric fields
            let (mname, off1) = parse_domain_name(buf, 0)?;
            let (rname, off2) = parse_domain_name(buf, off1)?;
            let remain = &buf[off2..];
            if remain.len() < 20 {
                return Err("SOA RDATA needs 20 bytes after rnames".to_string());
            }
            let serial = u32::from_be_bytes(remain[0..4].try_into().unwrap());
            let refresh = u32::from_be_bytes(remain[4..8].try_into().unwrap());
            let retry = u32::from_be_bytes(remain[8..12].try_into().unwrap());
            let expire = u32::from_be_bytes(remain[12..16].try_into().unwrap());
            let minimum = u32::from_be_bytes(remain[16..20].try_into().unwrap());
            Ok(RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }
        _ => {
            // fallback
            Ok(RData::Unknown(buf.to_vec()))
        }
    }
}

// --------------- Building a DNS response (pack) --------------- //

fn build_dns_message(msg: &DNSMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header:
    buf.extend_from_slice(&msg.header.id.to_be_bytes());
    buf.extend_from_slice(&msg.header.flags.to_be_bytes());
    buf.extend_from_slice(&(msg.questions.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(msg.answers.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(msg.authorities.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(msg.additionals.len() as u16).to_be_bytes());

    // Questions
    for q in &msg.questions {
        write_domain_name(&mut buf, &q.qname);
        buf.extend_from_slice(&q.qtype.to_be_bytes());
        buf.extend_from_slice(&q.qclass.to_be_bytes());
    }

    // Answers
    for rr in &msg.answers {
        write_resource_record(&mut buf, rr);
    }

    // Authorities
    for rr in &msg.authorities {
        write_resource_record(&mut buf, rr);
    }

    // Additionals
    for rr in &msg.additionals {
        write_resource_record(&mut buf, rr);
    }

    buf
}

/// Write a domain name in uncompressed form (no pointer compression).
fn write_domain_name(buf: &mut Vec<u8>, name: &str) {
    if name == "." || name.is_empty() {
        // root
        buf.push(0);
        return;
    }
    // e.g. "www.example.com." -> ["www", "example", "com", ""]
    let mut labels: Vec<&str> = name.split('.').collect();
    // If name ends in a dot, the last split is empty => remove it
    if let Some(last) = labels.last() {
        if last.is_empty() {
            labels.pop();
        }
    }

    for label in labels {
        if label.len() > 63 {
            // invalid label, but let's just do a best attempt
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // terminator
}

/// Write a resource record to buffer.
fn write_resource_record(buf: &mut Vec<u8>, rr: &DNSResourceRecord) {
    write_domain_name(buf, &rr.name);
    buf.extend_from_slice(&rr.rr_type.to_be_bytes());
    buf.extend_from_slice(&rr.rr_class.to_be_bytes());
    buf.extend_from_slice(&rr.ttl.to_be_bytes());

    let rdata_bytes = build_rdata(rr);
    buf.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rdata_bytes);
}

/// Build the RDATA portion for a known RData type.
fn build_rdata(rr: &DNSResourceRecord) -> Vec<u8> {
    let mut out = Vec::new();
    match &rr.rdata {
        RData::A(addr) => {
            out.extend_from_slice(&addr.octets());
        }
        RData::NS(nsname) => {
            write_domain_name(&mut out, nsname);
        }
        RData::CNAME(cname) => {
            write_domain_name(&mut out, cname);
        }
        RData::MX(pref, ex) => {
            out.extend_from_slice(&pref.to_be_bytes());
            write_domain_name(&mut out, ex);
        }
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            write_domain_name(&mut out, mname);
            write_domain_name(&mut out, rname);
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        RData::Unknown(raw) => {
            out.extend_from_slice(raw);
        }
    }
    out
}

// --------- Basic Authoritative Data + Minimal Recursive Query --------- //

/// A Zone-like structure: domain -> list of RRs
#[derive(Debug)]
struct Zone {
    records: Vec<DNSResourceRecord>,
}

/// Our in-memory "zones": map from domain's apex to a `Zone`.
///
/// For demonstration, we put a single zone "example.com." plus some test RRs.
#[allow(clippy::derivable_impls)]
impl Default for Zone {
    fn default() -> Self {
        let records = vec![
            DNSResourceRecord {
                name: "example.com.".to_string(),
                rr_type: dns_type::SOA,
                rr_class: dns_class::IN,
                ttl: 3600,
                rdata: RData::SOA {
                    mname: "ns.example.com.".to_string(),
                    rname: "hostmaster.example.com.".to_string(),
                    serial: 2023010101,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1209600,
                    minimum: 3600,
                },
            },
            DNSResourceRecord {
                name: "example.com.".to_string(),
                rr_type: dns_type::NS,
                rr_class: dns_class::IN,
                ttl: 3600,
                rdata: RData::NS("ns.example.com.".to_string()),
            },
            DNSResourceRecord {
                name: "ns.example.com.".to_string(),
                rr_type: dns_type::A,
                rr_class: dns_class::IN,
                ttl: 3600,
                rdata: RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            },
            DNSResourceRecord {
                name: "example.com.".to_string(),
                rr_type: dns_type::A,
                rr_class: dns_class::IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)), // typical example.com IP
            },
            DNSResourceRecord {
                name: "mail.example.com.".to_string(),
                rr_type: dns_type::A,
                rr_class: dns_class::IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 55)),
            },
            DNSResourceRecord {
                name: "example.com.".to_string(),
                rr_type: dns_type::MX,
                rr_class: dns_class::IN,
                ttl: 300,
                rdata: RData::MX(10, "mail.example.com.".to_string()),
            },
        ];
        Zone { records }
    }
}

/// A simple "authoritative DB" that can store multiple zones indexed by apex.
#[derive(Debug, Default)]
struct AuthoritativeDb {
    zones: HashMap<String, Zone>,
}

impl AuthoritativeDb {
    fn new() -> Self {
        let mut db = AuthoritativeDb::default();
        // Add a single zone for example.com.
        db.zones.insert("example.com.".to_string(), Zone::default());
        db
    }

    /// Find records that match (qname, qtype) from the authoritative data.
    /// qtype=ANY => return all.
    fn lookup(&self, qname: &str, qtype: u16) -> Vec<DNSResourceRecord> {
        // Find which zone is relevant. We'll do naive approach:
        // if qname ends with zone apex => this zone
        for (apex, zone) in &self.zones {
            if qname.ends_with(apex) {
                let mut matched = Vec::new();
                for rr in &zone.records {
                    if rr.name.eq_ignore_ascii_case(qname) || qtype == dns_type::ANY {
                        // if qtype matches or ANY
                        if rr.rr_type == qtype || qtype == dns_type::ANY {
                            matched.push(rr.clone());
                        }
                    }
                }
                return matched;
            }
        }
        Vec::new()
    }
}

/// Attempt a minimal recursion: if not found in our zone, do a forward query
/// to an upstream server (e.g. 8.8.8.8) over UDP, parse response, pick answer.
fn recursive_lookup(qname: &str, qtype: u16) -> Vec<DNSResourceRecord> {
    // e.g. google's or cloudflare's DNS
    let upstream = "8.8.8.8:53";
    match dns_query_udp(qname, qtype, dns_class::IN, upstream) {
        Ok(msg) => {
            // gather answers that match exactly
            let mut result = Vec::new();
            for ans in msg.answers {
                if ans.name.eq_ignore_ascii_case(qname) && (ans.rr_type == qtype || qtype == dns_type::ANY) {
                    result.push(ans);
                }
            }
            result
        }
        Err(_) => Vec::new(),
    }
}

// --------------- Handling an incoming DNS query --------------- //

fn handle_query(db: &AuthoritativeDb, q: &DNSQuestion) -> Vec<DNSResourceRecord> {
    let local_matches = db.lookup(&q.qname, q.qtype);
    if !local_matches.is_empty() {
        return local_matches;
    } else {
        // Try recursion
        recursive_lookup(&q.qname, q.qtype)
    }
}

fn make_response(db: &AuthoritativeDb, req: &DNSMessage) -> DNSMessage {
    let mut resp = DNSMessage::new_response(req.header.id);
    // set QR=1 (response), RD same as request, RA=1, no error => RCODE=0
    let req_flags = req.header.flags;
    let is_recdesired = (req_flags & 0x0100) != 0; // RD bit
    let mut flags = 0x8000; // QR=1
    if is_recdesired {
        flags |= 0x0100; // RD=1
    }
    // RA=1
    flags |= 0x0080;

    resp.header.flags = flags;
    resp.header.qdcount = req.header.qdcount;
    resp.questions = req.questions.clone();

    // For each question, produce answers.
    let mut answers = Vec::new();
    for q in &resp.questions {
        let rrset = handle_query(db, q);
        answers.extend(rrset);
    }

    resp.answers = answers;
    resp.header.ancount = resp.answers.len() as u16;
    resp
}

// --------------- Minimal DNS Server (UDP) --------------- //

fn run_dns_server() -> std::io::Result<()> {
    let db = AuthoritativeDb::new();
    let sock = UdpSocket::bind("0.0.0.0:53")?;
    println!("DNS Server listening on udp 0.0.0.0:53 ...");
    let mut buf = [0u8; 512];

    loop {
        let (size, src) = sock.recv_from(&mut buf)?;
        if size == 0 {
            continue;
        }
        let req_data = &buf[..size];
        match parse_dns_message(req_data) {
            Ok(req_msg) => {
                let resp_msg = make_response(&db, &req_msg);
                let resp_data = build_dns_message(&resp_msg);
                let _ = sock.send_to(&resp_data, src);
            }
            Err(e) => {
                eprintln!("Failed to parse DNS query from {}: {}", src, e);
            }
        }
    }
}

// --------------- Minimal DNS Client subroutines (UDP) --------------- //

fn dns_query_udp(qname: &str, qtype: u16, qclass: u16, server: &str) -> Result<DNSMessage, String> {
    // build query
    let mut msg = DNSMessage::new_response(0x1234); // ID
    // flags: RD=1 => recursion desired
    msg.header.flags = 0x0100;
    msg.header.qdcount = 1;
    msg.questions.push(DNSQuestion {
        qname: if qname.ends_with('.') { qname.to_string() } else { format!("{}.", qname) },
        qtype,
        qclass,
    });
    let data = build_dns_message(&msg);
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    sock.send_to(&data, server).map_err(|e| e.to_string())?;

    let mut buf = [0u8; 512];
    let (size, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("recv_from error: {}", e))?;
    let resp = parse_dns_message(&buf[..size])?;
    Ok(resp)
}

// --------------- Main: either server or do a sample query --------------- //

fn main() {
    // For demonstration, we start the DNS server in the background (thread),
    // then do a test query from the same process. In real usage, you'd pick one.
    std::thread::spawn(|| {
        if let Err(e) = run_dns_server() {
            eprintln!("DNS server error: {}", e);
        }
    });

    // Sleep briefly to ensure server is up
    std::thread::sleep(Duration::from_millis(500));

    // Demo: do a query to our local server for example.com A
    println!("Client: Querying our local DNS server for example.com A...");
    match dns_query_udp("example.com", dns_type::A, dns_class::IN, "127.0.0.1:53") {
        Ok(resp) => {
            println!("Got response: {:#?}", resp);
        }
        Err(e) => {
            eprintln!("DNS client error: {}", e);
        }
    }

    println!("Press Ctrl+C to exit, or let the server run...");
    loop {
        std::thread::park();
    }
}
```
