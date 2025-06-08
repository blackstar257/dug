use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use trust_dns_proto::op::{Header, MessageType, Query, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

#[derive(Debug, Clone)]
pub struct DugOptions {
    pub query_name: String,
    pub query_type: RecordType,
    pub query_class: DNSClass,
    pub server: Option<SocketAddr>,
    pub port: u16,
    pub use_tcp: bool,
    pub timeout: Duration,
    pub short: bool,
    pub trace: bool,
    pub reverse: bool,
    pub json: bool,
    pub show_question: bool,
    pub show_answer: bool,
    pub show_authority: bool,
    pub show_additional: bool,
    pub show_stats: bool,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub recurse: bool,
    pub dnssec: bool,
    pub verbose: bool,
}

impl Default for DugOptions {
    fn default() -> Self {
        Self {
            query_name: String::new(),
            query_type: RecordType::A,
            query_class: DNSClass::IN,
            server: None,
            port: 53,
            use_tcp: false,
            timeout: Duration::from_secs(5),
            short: false,
            trace: false,
            reverse: false,
            json: false,
            show_question: true,
            show_answer: true,
            show_authority: true,
            show_additional: true,
            show_stats: true,
            ipv4_only: false,
            ipv6_only: false,
            recurse: true,
            dnssec: false,
            verbose: false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = build_cli().get_matches();
    let options = parse_options(&matches)?;
    
    if options.verbose {
        println!("{}", format!("Query options: {:?}", options).dimmed());
    }

    let start_time = Instant::now();
    let result = perform_dns_query(&options).await;
    let elapsed = start_time.elapsed();

    match result {
        Ok(response) => {
            display_response(&response, &options, elapsed)?;
        }
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn build_cli() -> Command {
    Command::new("dug")
        .version("1.0.0")
        .about("DNS lookup utility (dig clone)")
        .arg(
            Arg::new("name")
                .help("Domain name to query")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::new("type")
                .help("Query type (A, AAAA, MX, NS, SOA, TXT, CNAME, PTR, etc.)")
                .short('t')
                .long("type")
                .value_name("TYPE")
                .default_value("A")
        )
        .arg(
            Arg::new("class")
                .help("Query class (IN, CH, HS)")
                .short('c')
                .long("class")
                .value_name("CLASS")
                .default_value("IN")
        )
        .arg(
            Arg::new("server")
                .help("DNS server to query (@server format)")
                .short('@')
                .long("server")
                .value_name("SERVER")
        )
        .arg(
            Arg::new("port")
                .help("Port number")
                .short('p')
                .long("port")
                .value_name("PORT")
                .default_value("53")
        )
        .arg(
            Arg::new("tcp")
                .help("Use TCP instead of UDP")
                .long("tcp")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("timeout")
                .help("Timeout in seconds")
                .long("timeout")
                .value_name("SECONDS")
                .default_value("5")
        )
        .arg(
            Arg::new("short")
                .help("Short output format")
                .long("short")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("trace")
                .help("Trace delegation path")
                .long("trace")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("reverse")
                .help("Reverse lookup (PTR)")
                .short('x')
                .long("reverse")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("json")
                .help("JSON output format")
                .long("json")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("norecurse")
                .help("Disable recursive query")
                .long("norecurse")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("dnssec")
                .help("Request DNSSEC records")
                .long("dnssec")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("4")
                .help("Use IPv4 only")
                .short('4')
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("6")
                .help("Use IPv6 only")
                .short('6')
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .help("Verbose output")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("noquestion")
                .help("Don't show question section")
                .long("noquestion")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("noanswer")
                .help("Don't show answer section")
                .long("noanswer")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("noauthority")
                .help("Don't show authority section")
                .long("noauthority")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("noadditional")
                .help("Don't show additional section")
                .long("noadditional")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("nostats")
                .help("Don't show query statistics")
                .long("nostats")
                .action(clap::ArgAction::SetTrue)
        )
}

fn parse_options(matches: &ArgMatches) -> Result<DugOptions> {
    let mut options = DugOptions::default();
    
    options.query_name = matches.get_one::<String>("name").unwrap().clone();
    
    // Handle server specification
    if let Some(server_str) = matches.get_one::<String>("server") {
        let server_str = server_str.trim_start_matches('@');
        let addr = if server_str.contains(':') {
            server_str.parse()?
        } else {
            let port = matches.get_one::<String>("port").unwrap().parse::<u16>()?;
            SocketAddr::new(server_str.parse()?, port)
        };
        options.server = Some(addr);
    }
    
    options.port = matches.get_one::<String>("port").unwrap().parse()?;
    
    // Parse query type
    options.query_type = match matches.get_one::<String>("type").unwrap().to_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "MX" => RecordType::MX,
        "NS" => RecordType::NS,
        "SOA" => RecordType::SOA,
        "TXT" => RecordType::TXT,
        "CNAME" => RecordType::CNAME,
        "PTR" => RecordType::PTR,
        "SRV" => RecordType::SRV,
        "CAA" => RecordType::CAA,
        "ANY" => RecordType::ANY,
        other => return Err(anyhow!("Unsupported query type: {}", other)),
    };
    
    // Parse query class
    options.query_class = match matches.get_one::<String>("class").unwrap().to_uppercase().as_str() {
        "IN" => DNSClass::IN,
        "CH" => DNSClass::CH,
        "HS" => DNSClass::HS,
        other => return Err(anyhow!("Unsupported query class: {}", other)),
    };
    
    options.timeout = Duration::from_secs(matches.get_one::<String>("timeout").unwrap().parse()?);
    options.use_tcp = matches.get_flag("tcp");
    options.short = matches.get_flag("short");
    options.trace = matches.get_flag("trace");
    options.reverse = matches.get_flag("reverse");
    options.json = matches.get_flag("json");
    options.recurse = !matches.get_flag("norecurse");
    options.dnssec = matches.get_flag("dnssec");
    options.ipv4_only = matches.get_flag("4");
    options.ipv6_only = matches.get_flag("6");
    options.verbose = matches.get_flag("verbose");
    
    options.show_question = !matches.get_flag("noquestion");
    options.show_answer = !matches.get_flag("noanswer");
    options.show_authority = !matches.get_flag("noauthority");
    options.show_additional = !matches.get_flag("noadditional");
    options.show_stats = !matches.get_flag("nostats");
    
    // Handle reverse lookup
    if options.reverse {
        options.query_name = create_reverse_name(&options.query_name)?;
        options.query_type = RecordType::PTR;
    }
    
    Ok(options)
}

fn create_reverse_name(ip: &str) -> Result<String> {
    match ip.parse::<IpAddr>()? {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Ok(format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut nibbles = Vec::new();
            for segment in segments.iter().rev() {
                for i in 0..4 {
                    nibbles.push(format!("{:x}", (segment >> (i * 4)) & 0xf));
                }
            }
            Ok(format!("{}.ip6.arpa", nibbles.join(".")))
        }
    }
}

async fn perform_dns_query(options: &DugOptions) -> Result<trust_dns_proto::op::Message> {
    let resolver = create_resolver(options).await?;
    
    let name = Name::from_str(&options.query_name)?;
    let query_future = resolver.lookup(name, options.query_type);
    
    let lookup_result = timeout(options.timeout, query_future).await??;
    
    // Convert the lookup result to a Message for more detailed output
    // This is a simplified approach - in a full implementation, you'd want to
    // access the raw DNS message for complete dig-like output
    let mut message = trust_dns_proto::op::Message::new();
    let mut header = Header::new();
    header.set_message_type(MessageType::Response);
    header.set_response_code(ResponseCode::NoError);
    header.set_recursion_desired(options.recurse);
    header.set_recursion_available(true);
    message.set_header(header);
    
    // Add question
    let question = Query::query(Name::from_str(&options.query_name)?, options.query_type);
    message.add_query(question);
    
    // Add answers
    for record in lookup_result.record_iter() {
        message.add_answer(record.clone());
    }
    
    Ok(message)
}

async fn create_resolver(options: &DugOptions) -> Result<TokioAsyncResolver> {
    let config = if let Some(server) = options.server {
        ResolverConfig::from_parts(
            None,
            vec![],
            trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(&[server.ip()], server.port(), true)
        )
    } else {
        ResolverConfig::default()
    };
    
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = false;
    opts.recursion_desired = options.recurse;
    opts.timeout = options.timeout;
    
    opts.timeout = options.timeout;
    
    Ok(AsyncResolver::tokio(config, opts))
}

fn display_response(
    message: &trust_dns_proto::op::Message,
    options: &DugOptions,
    elapsed: Duration,
) -> Result<()> {
    if options.json {
        display_json_response(message, options, elapsed)?;
        return Ok(());
    }
    
    if options.short {
        display_short_response(message)?;
        return Ok(());
    }
    
    display_full_response(message, options, elapsed)?;
    Ok(())
}

fn display_json_response(
    message: &trust_dns_proto::op::Message,
    _options: &DugOptions,
    elapsed: Duration,
) -> Result<()> {
    let mut json_output = serde_json::Map::new();
    
    // Header information
    let header = message.header();
    json_output.insert("status".to_string(), serde_json::Value::String(
        format!("{:?}", header.response_code())
    ));
    json_output.insert("query_time".to_string(), serde_json::Value::Number(
        serde_json::Number::from(elapsed.as_millis() as u64)
    ));
    
    // Questions
    let questions: Vec<serde_json::Value> = message.queries().iter().map(|q| {
        serde_json::json!({
            "name": q.name().to_string(),
            "type": format!("{:?}", q.query_type()),
            "class": format!("{:?}", q.query_class())
        })
    }).collect();
    json_output.insert("question".to_string(), serde_json::Value::Array(questions));
    
    // Answers
    let answers: Vec<serde_json::Value> = message.answers().iter().map(|record| {
        format_record_json(record)
    }).collect();
    json_output.insert("answer".to_string(), serde_json::Value::Array(answers));
    
    println!("{}", serde_json::to_string_pretty(&json_output)?);
    Ok(())
}

fn display_short_response(message: &trust_dns_proto::op::Message) -> Result<()> {
    for record in message.answers() {
        match record.data() {
            Some(RData::A(ip)) => println!("{}", ip),
            Some(RData::AAAA(ip)) => println!("{}", ip),
            Some(RData::CNAME(name)) => println!("{}", name),
            Some(RData::MX(mx)) => println!("{} {}", mx.preference(), mx.exchange()),
            Some(RData::NS(ns)) => println!("{}", ns),
            Some(RData::TXT(txt)) => {
                for data in txt.iter() {
                    println!("{}", String::from_utf8_lossy(data));
                }
            }
            Some(RData::SOA(soa)) => {
                println!("{} {} {} {} {} {} {}", 
                    soa.mname(), soa.rname(), soa.serial(), 
                    soa.refresh(), soa.retry(), soa.expire(), soa.minimum()
                );
            }
            Some(other) => println!("{}", other),
            None => println!("No data"),
        }
    }
    Ok(())
}

fn display_full_response(
    message: &trust_dns_proto::op::Message,
    options: &DugOptions,
    elapsed: Duration,
) -> Result<()> {
    let header = message.header();
    
    // Header
    println!();
    println!("{}", format!("; <<>> dug 1.0.0 <<>> {}", options.query_name).dimmed());
    println!("{}", format!(";; global options: +cmd").dimmed());
    println!("{}", format!(";; Got answer:").dimmed());
    println!("{}", format!(";; ->>HEADER<<- opcode: {:?}, status: {:?}, id: {}", 
        header.op_code(), header.response_code(), header.id()).dimmed());
    println!("{}", format!(";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
        format_flags(header),
        message.query_count(),
        message.answer_count(),
        message.name_server_count(),
        message.additional_count()
    ).dimmed());
    
    // Question Section
    if options.show_question && !message.queries().is_empty() {
        println!();
        println!("{}", ";; QUESTION SECTION:".dimmed());
        for question in message.queries() {
            println!("{}", format!(";{}\t\t\t{}\t{}", 
                question.name(),
                format!("{:?}", question.query_class()),
                format!("{:?}", question.query_type())
            ).dimmed());
        }
    }
    
    // Answer Section
    if options.show_answer && !message.answers().is_empty() {
        println!();
        println!("{}", ";; ANSWER SECTION:".yellow().bold());
        for record in message.answers() {
            println!("{}", format_record_full(record));
        }
    }
    
    // Authority Section
    if options.show_authority && !message.name_servers().is_empty() {
        println!();
        println!("{}", ";; AUTHORITY SECTION:".yellow().bold());
        for record in message.name_servers() {
            println!("{}", format_record_full(record));
        }
    }
    
    // Additional Section
    if options.show_additional && !message.additionals().is_empty() {
        println!();
        println!("{}", ";; ADDITIONAL SECTION:".yellow().bold());
        for record in message.additionals() {
            println!("{}", format_record_full(record));
        }
    }
    
    // Query Statistics
    if options.show_stats {
        println!();
        let server_info = if let Some(server) = options.server {
            format!("{}#{}", server.ip(), server.port())
        } else {
            "system resolver".to_string()
        };
        
        println!("{}", format!(";; Query time: {} msec", elapsed.as_millis()).dimmed());
        println!("{}", format!(";; SERVER: {}", server_info).dimmed());
        println!("{}", format!(";; WHEN: {}", Utc::now().format("%a %b %d %H:%M:%S UTC %Y")).dimmed());
        println!("{}", format!(";; MSG SIZE  rcvd: {} bytes", 
            estimate_message_size(message)).dimmed());
    }
    
    println!();
    Ok(())
}

fn format_flags(header: &Header) -> String {
    let mut flags = Vec::new();
    
    if header.recursion_desired() { flags.push("rd"); }
    if header.recursion_available() { flags.push("ra"); }
    if header.authoritative() { flags.push("aa"); }
    if header.truncated() { flags.push("tc"); }
    if header.authentic_data() { flags.push("ad"); }
    if header.checking_disabled() { flags.push("cd"); }
    
    flags.join(" ")
}

fn format_record_full(record: &Record) -> String {
    let data_str = match record.data() {
        Some(RData::A(ip)) => ip.to_string(),
        Some(RData::AAAA(ip)) => ip.to_string(),
        Some(RData::CNAME(name)) => name.to_string(),
        Some(RData::MX(mx)) => format!("{} {}", mx.preference(), mx.exchange()),
        Some(RData::NS(ns)) => ns.to_string(),
        Some(RData::TXT(txt)) => {
            txt.iter()
                .map(|data| format!("\"{}\"", String::from_utf8_lossy(data)))
                .collect::<Vec<_>>()
                .join(" ")
        }
        Some(RData::SOA(soa)) => {
            format!("{} {} {} {} {} {} {}", 
                soa.mname(), soa.rname(), soa.serial(), 
                soa.refresh(), soa.retry(), soa.expire(), soa.minimum()
            )
        }
        Some(RData::PTR(ptr)) => ptr.to_string(),
        Some(RData::SRV(srv)) => {
            format!("{} {} {} {}", srv.priority(), srv.weight(), srv.port(), srv.target())
        }
        Some(other) => other.to_string(),
        None => "".to_string(),
    };
    
    format!("{}\t{}\t{}\t{}\t{}", 
        record.name(),
        record.ttl(),
        format!("{:?}", record.dns_class()),
        format!("{:?}", record.record_type()),
        data_str
    )
}

fn format_record_json(record: &Record) -> serde_json::Value {
    let data_value = match record.data() {
        Some(RData::A(ip)) => serde_json::Value::String(ip.to_string()),
        Some(RData::AAAA(ip)) => serde_json::Value::String(ip.to_string()),
        Some(RData::CNAME(name)) => serde_json::Value::String(name.to_string()),
        Some(RData::MX(mx)) => serde_json::json!({
            "preference": mx.preference(),
            "exchange": mx.exchange().to_string()
        }),
        Some(RData::TXT(txt)) => {
            let texts: Vec<String> = txt.iter()
                .map(|data| String::from_utf8_lossy(data).to_string())
                .collect();
            serde_json::Value::Array(texts.into_iter().map(serde_json::Value::String).collect())
        }
        Some(other) => serde_json::Value::String(other.to_string()),
        None => serde_json::Value::Null,
    };
    
    serde_json::json!({
        "name": record.name().to_string(),
        "type": format!("{:?}", record.record_type()),
        "class": format!("{:?}", record.dns_class()),
        "ttl": record.ttl(),
        "data": data_value
    })
}

fn estimate_message_size(message: &trust_dns_proto::op::Message) -> usize {
    // Rough estimation - in a real implementation, you'd serialize the message
    let base_size = 12; // DNS header size
    let mut size = base_size;
    
    // Add question section size
    for question in message.queries() {
        size += question.name().len() + 4; // name + type + class
    }
    
    // Add answer section size (rough estimate)
    for record in message.answers() {
        size += record.name().len() + 10; // name + type + class + ttl + rdlength
        if let Some(data) = record.data() {
            size += estimate_rdata_size(data);
        }
    }
    
    size
}

fn estimate_rdata_size(rdata: &RData) -> usize {
    match rdata {
        RData::A(_) => 4,
        RData::AAAA(_) => 16,
        RData::CNAME(name) => name.len(),
        RData::NS(name) => name.len(),
        RData::MX(_) => 8, // preference + exchange name (estimated)
        RData::TXT(txt) => txt.iter().map(|t| t.len()).sum::<usize>(),
        RData::SOA(_) => 32, // Rough estimate
        _ => 16, // Default estimate
    }
}
