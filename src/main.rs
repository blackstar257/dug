use anyhow::{Result, anyhow};
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use trust_dns_proto::op::{Header, Message, MessageType, Query, ResponseCode};
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
    pub tries: u32,
    pub retry: u32,
    pub short: bool,
    pub trace: bool,
    pub reverse: bool,
    pub show_question: bool,
    pub show_answer: bool,
    pub show_authority: bool,
    pub show_additional: bool,
    pub show_stats: bool,
    pub show_cmd: bool,
    pub show_comments: bool,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub recurse: bool,
    pub dnssec: bool,
    pub verbose: bool,
    pub batch_file: Option<String>,
    pub bind_address: Option<IpAddr>,
    pub keyfile: Option<String>,
    pub tsig_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub message: trust_dns_proto::op::Message,
    pub server_used: SocketAddr,
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
            tries: 3,
            retry: 2,
            short: false,
            trace: false,
            reverse: false,
            show_question: true,
            show_answer: true,
            show_authority: true,
            show_additional: true,
            show_stats: true,
            show_cmd: true,
            show_comments: true,
            ipv4_only: false,
            ipv6_only: false,
            recurse: true,
            dnssec: false,
            verbose: false,
            batch_file: None,
            bind_address: None,
            keyfile: None,
            tsig_key: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = build_cli().get_matches();
    let options = parse_options(&matches)?;

    // Handle batch file processing
    if let Some(batch_file) = &options.batch_file {
        return process_batch_file(batch_file).await;
    }

    if options.verbose {
        println!("{}", format!("Query options: {:?}", options).dimmed());
        if let Some(sys_dns) = get_system_dns_server() {
            println!("{}", format!("System DNS detected: {}", sys_dns).dimmed());
        }
    }

    let start_time = Instant::now();
    let result = perform_dns_query(&options).await;
    let elapsed = start_time.elapsed();

    match result {
        Ok(query_result) => {
            if !options.trace {
                display_response(&query_result, &options, elapsed)?;
            }
            // Trace mode displays output during execution, no need to display again
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
        .about("DNS lookup utility")
        .override_usage("dug [@server] [-b address] [-c class] [-f filename] [-k filename] [-p port#] [-q name] [-t type] [-x addr] [-y [hmac:]name:key] [-4] [-6] [name] [type] [class] [queryopt...]")
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .help("Print help information")
                .short('h')
                .action(clap::ArgAction::Help)
        )
        // Positional arguments that can be name, type, class, @server, or +options
        .arg(
            Arg::new("args")
                .help("Query arguments: [name] [type] [class] [@server] [+option...]")
                .num_args(0..)
                .value_name("ARGS")
        )
        // Standard dig flags
        .arg(
            Arg::new("bind_address")
                .help("Set source IP address of the query")
                .short('b')
                .value_name("ADDRESS")
        )
        .arg(
            Arg::new("class")
                .help("Set query class (IN, CH, HS)")
                .short('c')
                .value_name("CLASS")
        )
        .arg(
            Arg::new("batch_file")
                .help("Read lookup requests from file")
                .short('f')
                .value_name("FILENAME")
        )
        .arg(
            Arg::new("keyfile")
                .help("TSIG key file")
                .short('k')
                .value_name("FILENAME")
        )
        .arg(
            Arg::new("port")
                .help("Port number")
                .short('p')
                .value_name("PORT")
        )
        .arg(
            Arg::new("query_name")
                .help("Set query name")
                .short('q')
                .value_name("NAME")
        )
        .arg(
            Arg::new("type")
                .help("Set query type")
                .short('t')
                .value_name("TYPE")
        )
        .arg(
            Arg::new("reverse")
                .help("Reverse lookup")
                .short('x')
                .value_name("ADDR")
        )
        .arg(
            Arg::new("tsig_key")
                .help("TSIG key")
                .short('y')
                .value_name("[hmac:]name:key")
        )
        .arg(
            Arg::new("ipv4")
                .help("Use IPv4 only")
                .short('4')
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ipv6")
                .help("Use IPv6 only")
                .short('6')
                .action(clap::ArgAction::SetTrue)
        )
}

fn parse_options(matches: &ArgMatches) -> Result<DugOptions> {
    let mut options = DugOptions::default();

    // Get all positional arguments
    let args: Vec<String> = matches
        .get_many::<String>("args")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    // Parse arguments in order: [@server] [name] [type] [class] [+options...]
    let mut name_set = false;
    let mut type_set = false;
    let mut class_set = false;

    for arg in &args {
        if arg.starts_with('@') {
            // Server specification
            let server_str = arg.trim_start_matches('@');
            let addr = if server_str.contains(':') {
                server_str.parse()?
            } else {
                let port = options.port;
                SocketAddr::new(server_str.parse()?, port)
            };
            options.server = Some(addr);
        } else if arg.starts_with('+') {
            // Query options
            parse_query_option(&mut options, arg)?;
        } else if !name_set && !is_record_type(arg) && !is_record_class(arg) {
            // First non-option argument is the name
            options.query_name = arg.clone();
            name_set = true;
        } else if !type_set && is_record_type(arg) {
            // Record type
            options.query_type = parse_record_type(arg)?;
            type_set = true;
        } else if !class_set && is_record_class(arg) {
            // Record class
            options.query_class = parse_record_class(arg)?;
            class_set = true;
        } else if !name_set {
            // If we haven't set name yet, use this
            options.query_name = arg.clone();
            name_set = true;
        }
    }

    // Handle explicit flags
    if let Some(bind_addr) = matches.get_one::<String>("bind_address") {
        options.bind_address = Some(bind_addr.parse()?);
    }

    if let Some(class_str) = matches.get_one::<String>("class") {
        options.query_class = parse_record_class(class_str)?;
    }

    if let Some(filename) = matches.get_one::<String>("batch_file") {
        options.batch_file = Some(filename.clone());
    }

    if let Some(keyfile) = matches.get_one::<String>("keyfile") {
        options.keyfile = Some(keyfile.clone());
    }

    if let Some(port_str) = matches.get_one::<String>("port") {
        options.port = port_str.parse()?;
        // Update server port if server was already set
        if let Some(server) = options.server {
            options.server = Some(SocketAddr::new(server.ip(), options.port));
        }
    }

    if let Some(query_name) = matches.get_one::<String>("query_name") {
        options.query_name = query_name.clone();
    }

    if let Some(type_str) = matches.get_one::<String>("type") {
        options.query_type = parse_record_type(type_str)?;
    }

    if let Some(addr) = matches.get_one::<String>("reverse") {
        options.query_name = create_reverse_name(addr)?;
        options.query_type = RecordType::PTR;
        options.reverse = true;
    }

    if let Some(tsig) = matches.get_one::<String>("tsig_key") {
        options.tsig_key = Some(tsig.clone());
    }

    options.ipv4_only = matches.get_flag("ipv4");
    options.ipv6_only = matches.get_flag("ipv6");

    // Default query name to root if not set
    if options.query_name.is_empty() {
        options.query_name = ".".to_string();
        // Default to NS query for root
        if !type_set {
            options.query_type = RecordType::NS;
        }
    }

    Ok(options)
}

async fn process_batch_file(filename: &str) -> Result<()> {
    let content = std::fs::read_to_string(filename)?;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue; // Skip empty lines and comments
        }

        println!(
            "{}",
            format!("Processing line {}: {}", line_num + 1, line).dimmed()
        );

        // Parse the line as if it were command line arguments
        let args: Vec<&str> = line.split_whitespace().collect();
        if args.is_empty() {
            continue;
        }

        // Create a new matches structure for this line
        let batch_cmd = build_cli();
        let batch_matches = match batch_cmd
            .try_get_matches_from(std::iter::once("dug").chain(args.iter().cloned()))
        {
            Ok(matches) => matches,
            Err(e) => {
                eprintln!("Error parsing line {}: {}", line_num + 1, e);
                continue;
            }
        };

        let options = match parse_options(&batch_matches) {
            Ok(opts) => opts,
            Err(e) => {
                eprintln!("Error in line {}: {}", line_num + 1, e);
                continue;
            }
        };

        let start_time = Instant::now();
        let result = perform_dns_query(&options).await;
        let elapsed = start_time.elapsed();

        match result {
            Ok(query_result) => {
                display_response(&query_result, &options, elapsed)?;
            }
            Err(e) => {
                eprintln!("Query failed for line {}: {}", line_num + 1, e);
            }
        }

        println!(); // Add separation between queries
    }

    Ok(())
}

fn parse_query_option(options: &mut DugOptions, option: &str) -> Result<()> {
    let option = option.trim_start_matches('+');
    let (key, value) = if let Some(eq_pos) = option.find('=') {
        (&option[..eq_pos], Some(&option[eq_pos + 1..]))
    } else {
        (option, None)
    };

    let negated = key.starts_with("no");
    let key = if negated { &key[2..] } else { key };

    match key {
        "tcp" | "vc" => options.use_tcp = !negated,
        "short" => options.short = !negated,
        "trace" => options.trace = !negated,
        "recurse" | "recursive" => options.recurse = !negated,
        "dnssec" => options.dnssec = !negated,
        "question" => options.show_question = !negated,
        "answer" => options.show_answer = !negated,
        "authority" => options.show_authority = !negated,
        "additional" => options.show_additional = !negated,
        "stats" => options.show_stats = !negated,
        "cmd" => options.show_cmd = !negated,
        "comments" => options.show_comments = !negated,
        "all" => {
            let show = !negated;
            options.show_question = show;
            options.show_answer = show;
            options.show_authority = show;
            options.show_additional = show;
            options.show_stats = show;
            options.show_cmd = show;
            options.show_comments = show;
        }
        "time" => {
            if let Some(val) = value {
                options.timeout = Duration::from_secs(val.parse()?);
            }
        }
        "tries" => {
            if let Some(val) = value {
                options.tries = val.parse()?;
            }
        }
        "retry" => {
            if let Some(val) = value {
                options.retry = val.parse()?;
            }
        }
        _ => {} // Ignore unknown options for compatibility
    }

    Ok(())
}

fn is_record_type(s: &str) -> bool {
    matches!(
        s.to_uppercase().as_str(),
        "A" | "AAAA"
            | "MX"
            | "NS"
            | "SOA"
            | "TXT"
            | "CNAME"
            | "PTR"
            | "SRV"
            | "CAA"
            | "ANY"
            | "AXFR"
            | "IXFR"
    )
}

fn is_record_class(s: &str) -> bool {
    matches!(s.to_uppercase().as_str(), "IN" | "CH" | "HS")
}

fn parse_record_type(s: &str) -> Result<RecordType> {
    match s.to_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "MX" => Ok(RecordType::MX),
        "NS" => Ok(RecordType::NS),
        "SOA" => Ok(RecordType::SOA),
        "TXT" => Ok(RecordType::TXT),
        "CNAME" => Ok(RecordType::CNAME),
        "PTR" => Ok(RecordType::PTR),
        "SRV" => Ok(RecordType::SRV),
        "CAA" => Ok(RecordType::CAA),
        "ANY" => Ok(RecordType::ANY),
        other => Err(anyhow!("Unsupported query type: {}", other)),
    }
}

fn parse_record_class(s: &str) -> Result<DNSClass> {
    match s.to_uppercase().as_str() {
        "IN" => Ok(DNSClass::IN),
        "CH" => Ok(DNSClass::CH),
        "HS" => Ok(DNSClass::HS),
        other => Err(anyhow!("Unsupported query class: {}", other)),
    }
}

fn create_reverse_name(ip: &str) -> Result<String> {
    match ip.parse::<IpAddr>()? {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Ok(format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            ))
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

async fn perform_dns_query(options: &DugOptions) -> Result<QueryResult> {
    if options.trace {
        return perform_trace_query(options).await;
    }

    let (resolver, config) = create_resolver(options).await?;

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

    // Get the actual server that was used
    let server_used = get_server_used(&config, options);

    Ok(QueryResult {
        message,
        server_used,
    })
}

async fn perform_trace_query(options: &DugOptions) -> Result<QueryResult> {
    use trust_dns_resolver::AsyncResolver;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

    // Root servers - using a few key ones
    let root_servers = [
        "198.41.0.4",     // a.root-servers.net
        "199.9.14.201",   // b.root-servers.net
        "192.33.4.12",    // c.root-servers.net
        "199.7.91.13",    // d.root-servers.net
        "192.203.230.10", // e.root-servers.net
    ];

    let target_name = Name::from_str(&options.query_name)?;
    let query_type = options.query_type;

    // Start with root servers
    let mut current_servers = root_servers
        .iter()
        .map(|s| s.parse::<IpAddr>().unwrap())
        .collect::<Vec<_>>();

    // Build the path from root to target
    let mut path = Vec::new();
    let labels: Vec<&[u8]> = target_name.iter().collect();

    // Build query path: . -> com. -> google.com.
    path.push(Name::root());

    // Build intermediate names by taking successive labels from the end
    for i in 1..=labels.len() {
        let label_slice = &labels[labels.len() - i..];
        if let Ok(name) = Name::from_labels(label_slice.to_vec()) {
            path.push(name);
        }
    }

    let mut final_message = Message::new();
    let mut final_server = SocketAddr::new("127.0.0.1".parse().unwrap(), 53);

    // Trace through each level
    for (step, query_name) in path.iter().enumerate() {
        let is_final = step == path.len() - 1;
        let lookup_type = RecordType::NS; // We always query for NS records during tracing

        // Pick the first available server
        let server_ip = current_servers
            .first()
            .copied()
            .ok_or_else(|| anyhow!("No servers available for query"))?;
        let server_addr = SocketAddr::new(server_ip, 53);

        // Create resolver for this specific server
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
                &[server_ip],
                53,
                true,
            ),
        );

        let mut opts = ResolverOpts::default();
        opts.recursion_desired = false; // Important: no recursion for tracing
        opts.timeout = options.timeout;

        let resolver = AsyncResolver::tokio(config, opts);

        // Perform the query
        let start = Instant::now();
        let lookup_result = timeout(
            options.timeout,
            resolver.lookup(query_name.clone(), lookup_type),
        )
        .await??;
        let elapsed = start.elapsed();

        // Create message for this step
        let mut message = Message::new();
        let mut header = Header::new();
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        header.set_recursion_desired(false);
        header.set_recursion_available(false);
        message.set_header(header);

        // Add question
        let question = Query::query(query_name.clone(), lookup_type);
        message.add_query(question);

        // Add answers
        for record in lookup_result.record_iter() {
            message.add_answer(record.clone());
        }

        // Display this step immediately
        display_trace_step(&message, server_addr, elapsed)?;

        // Extract name servers for next level or prepare for final query
        current_servers.clear();
        for record in lookup_result.record_iter() {
            if let Some(RData::NS(ns_name)) = record.data() {
                // Resolve the NS name to IP
                if let Ok(ns_ips) = resolve_name_server(ns_name).await {
                    current_servers.extend(ns_ips);
                }
            }
        }

        // If this was the final domain and we have NS servers, do one more query for the actual record
        if is_final && !current_servers.is_empty() {
            // Now query the domain's own name servers for the requested record type
            let final_server_ip = current_servers
                .first()
                .copied()
                .ok_or_else(|| anyhow!("No servers available for final query"))?;
            let final_server_addr = SocketAddr::new(final_server_ip, 53);

            let final_config = ResolverConfig::from_parts(
                None,
                vec![],
                trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
                    &[final_server_ip],
                    53,
                    true,
                ),
            );

            let mut final_opts = ResolverOpts::default();
            final_opts.recursion_desired = false;
            final_opts.timeout = options.timeout;

            let final_resolver = AsyncResolver::tokio(final_config, final_opts);

            let final_start = Instant::now();
            let final_lookup = timeout(
                options.timeout,
                final_resolver.lookup(query_name.clone(), query_type),
            )
            .await??;
            let final_elapsed = final_start.elapsed();

            let mut final_msg = Message::new();
            let mut final_header = Header::new();
            final_header.set_message_type(MessageType::Response);
            final_header.set_response_code(ResponseCode::NoError);
            final_header.set_recursion_desired(false);
            final_header.set_recursion_available(false);
            final_msg.set_header(final_header);

            let final_question = Query::query(query_name.clone(), query_type);
            final_msg.add_query(final_question);

            for record in final_lookup.record_iter() {
                final_msg.add_answer(record.clone());
            }

            display_trace_step(&final_msg, final_server_addr, final_elapsed)?;

            final_message = final_msg;
            final_server = final_server_addr;
            break; // We're done
        }

        // If we don't have any servers, we can't continue
        if current_servers.is_empty() && !is_final {
            return Err(anyhow!("No name servers found for next level"));
        }
    }

    Ok(QueryResult {
        message: final_message,
        server_used: final_server,
    })
}

async fn resolve_name_server(ns_name: &Name) -> Result<Vec<IpAddr>> {
    // Simple resolution - in production you'd want more robust resolution
    let resolver = AsyncResolver::tokio_from_system_conf()?;
    let mut ips = Vec::new();

    // Try A record
    if let Ok(lookup) = resolver.lookup(ns_name.clone(), RecordType::A).await {
        for record in lookup.record_iter() {
            if let Some(RData::A(ip)) = record.data() {
                ips.push(IpAddr::V4(ip.0));
            }
        }
    }

    // Try AAAA record if we don't have IPv4 addresses
    if ips.is_empty() {
        if let Ok(lookup) = resolver.lookup(ns_name.clone(), RecordType::AAAA).await {
            for record in lookup.record_iter() {
                if let Some(RData::AAAA(ip)) = record.data() {
                    ips.push(IpAddr::V6(ip.0));
                }
            }
        }
    }

    Ok(ips)
}

fn display_trace_step(message: &Message, server_used: SocketAddr, elapsed: Duration) -> Result<()> {
    // Display answers
    for record in message.answers() {
        println!("{}", format_record_full(record));
    }

    // Display the source info
    let size_estimate = estimate_message_size(message);
    println!(
        "{}",
        format!(
            ";; Received {} bytes from {}#{} in {} ms",
            size_estimate,
            server_used.ip(),
            server_used.port(),
            elapsed.as_millis()
        )
        .dimmed()
    );
    println!(); // Empty line between steps

    Ok(())
}

async fn create_resolver(options: &DugOptions) -> Result<(TokioAsyncResolver, ResolverConfig)> {
    let config = if let Some(server) = options.server {
        ResolverConfig::from_parts(
            None,
            vec![],
            trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
                &[server.ip()],
                server.port(),
                true,
            ),
        )
    } else {
        // Use system DNS server if we can detect it, otherwise default
        if let Some(system_server) = get_system_dns_server() {
            ResolverConfig::from_parts(
                None,
                vec![],
                trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
                    &[system_server.ip()],
                    system_server.port(),
                    true,
                ),
            )
        } else {
            ResolverConfig::default()
        }
    };

    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = false;
    opts.recursion_desired = options.recurse;
    opts.timeout = options.timeout;

    let resolver = AsyncResolver::tokio(config.clone(), opts);
    Ok((resolver, config))
}

fn get_server_used(config: &ResolverConfig, options: &DugOptions) -> SocketAddr {
    if let Some(server) = options.server {
        return server;
    }

    // Get the first nameserver from the config
    if let Some(nameserver_config) = config.name_servers().first() {
        return nameserver_config.socket_addr;
    }

    // Fallback to reading system DNS configuration
    get_system_dns_server().unwrap_or_else(|| SocketAddr::new("127.0.0.1".parse().unwrap(), 53))
}

fn get_system_dns_server() -> Option<SocketAddr> {
    // Try macOS scutil first
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("scutil").arg("--dns").output() {
            if let Ok(content) = String::from_utf8(output.stdout) {
                for line in content.lines() {
                    if line.trim().starts_with("nameserver[0]") {
                        if let Some(ip_str) = line.split(':').nth(1) {
                            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                                return Some(SocketAddr::new(ip, 53));
                            }
                        }
                    }
                }
            }
        }
    }

    // Try to read system DNS configuration
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                if line.trim().starts_with("nameserver") {
                    if let Some(ip_str) = line.split_whitespace().nth(1) {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            return Some(SocketAddr::new(ip, 53));
                        }
                    }
                }
            }
        }
    }

    // Windows fallback - try common DNS servers or use a library
    #[cfg(windows)]
    {
        // For Windows, we could use the ipconfig crate or WinAPI
        // For now, return a common default
        return Some(SocketAddr::new("127.0.0.1".parse().unwrap(), 53));
    }

    None
}

fn display_response(
    query_result: &QueryResult,
    options: &DugOptions,
    elapsed: Duration,
) -> Result<()> {
    if options.short {
        display_short_response(&query_result.message)?;
        return Ok(());
    }

    display_full_response(
        &query_result.message,
        options,
        elapsed,
        query_result.server_used,
    )?;
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
                println!(
                    "{} {} {} {} {} {} {}",
                    soa.mname(),
                    soa.rname(),
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum()
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
    server_used: SocketAddr,
) -> Result<()> {
    let header = message.header();

    // Header
    if options.show_cmd {
        println!();
        println!(
            "{}",
            format!("; <<>> dug 1.0.0 <<>> {}", options.query_name).dimmed()
        );
        println!("{}", ";; global options: +cmd".to_string().dimmed());
    }

    if options.show_comments {
        println!("{}", ";; Got answer:".to_string().dimmed());
        println!(
            "{}",
            format!(
                ";; ->>HEADER<<- opcode: {:?}, status: {:?}, id: {}",
                header.op_code(),
                header.response_code(),
                header.id()
            )
            .dimmed()
        );
        println!(
            "{}",
            format!(
                ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
                format_flags(header),
                message.query_count(),
                message.answer_count(),
                message.name_server_count(),
                message.additional_count()
            )
            .dimmed()
        );
    }

    // Question Section
    if options.show_question && !message.queries().is_empty() {
        println!();
        if options.show_comments {
            println!("{}", ";; QUESTION SECTION:".dimmed());
        }
        for question in message.queries() {
            println!(
                "{}",
                format!(
                    ";{}\t\t\t{:?}\t{:?}",
                    question.name(),
                    question.query_class(),
                    question.query_type()
                )
                .dimmed()
            );
        }
    }

    // Answer Section
    if options.show_answer && !message.answers().is_empty() {
        println!();
        if options.show_comments {
            println!("{}", ";; ANSWER SECTION:".yellow().bold());
        }
        for record in message.answers() {
            println!("{}", format_record_full(record));
        }
    }

    // Authority Section
    if options.show_authority && !message.name_servers().is_empty() {
        println!();
        if options.show_comments {
            println!("{}", ";; AUTHORITY SECTION:".yellow().bold());
        }
        for record in message.name_servers() {
            println!("{}", format_record_full(record));
        }
    }

    // Additional Section
    if options.show_additional && !message.additionals().is_empty() {
        println!();
        if options.show_comments {
            println!("{}", ";; ADDITIONAL SECTION:".yellow().bold());
        }
        for record in message.additionals() {
            println!("{}", format_record_full(record));
        }
    }

    // Query Statistics
    if options.show_stats {
        println!();
        let server_info = format!(
            "{}#{}({})",
            server_used.ip(),
            server_used.port(),
            server_used.ip()
        );

        if options.show_comments {
            println!(
                "{}",
                format!(";; Query time: {} msec", elapsed.as_millis()).dimmed()
            );
            println!("{}", format!(";; SERVER: {}", server_info).dimmed());
            println!(
                "{}",
                format!(";; WHEN: {}", Utc::now().format("%a %b %d %H:%M:%S UTC %Y")).dimmed()
            );
            println!(
                "{}",
                format!(
                    ";; MSG SIZE  rcvd: {} bytes",
                    estimate_message_size(message)
                )
                .dimmed()
            );
        }
    }

    println!();
    Ok(())
}

fn format_flags(header: &Header) -> String {
    let mut flags = Vec::new();

    if header.recursion_desired() {
        flags.push("rd");
    }
    if header.recursion_available() {
        flags.push("ra");
    }
    if header.authoritative() {
        flags.push("aa");
    }
    if header.truncated() {
        flags.push("tc");
    }
    if header.authentic_data() {
        flags.push("ad");
    }
    if header.checking_disabled() {
        flags.push("cd");
    }

    flags.join(" ")
}

fn format_record_full(record: &Record) -> String {
    let data_str = match record.data() {
        Some(RData::A(ip)) => ip.to_string(),
        Some(RData::AAAA(ip)) => ip.to_string(),
        Some(RData::CNAME(name)) => name.to_string(),
        Some(RData::MX(mx)) => format!("{} {}", mx.preference(), mx.exchange()),
        Some(RData::NS(ns)) => ns.to_string(),
        Some(RData::TXT(txt)) => txt
            .iter()
            .map(|data| format!("\"{}\"", String::from_utf8_lossy(data)))
            .collect::<Vec<_>>()
            .join(" "),
        Some(RData::SOA(soa)) => {
            format!(
                "{} {} {} {} {} {} {}",
                soa.mname(),
                soa.rname(),
                soa.serial(),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum()
            )
        }
        Some(RData::PTR(ptr)) => ptr.to_string(),
        Some(RData::SRV(srv)) => {
            format!(
                "{} {} {} {}",
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target()
            )
        }
        Some(other) => other.to_string(),
        None => "".to_string(),
    };

    format!(
        "{}\t{}\t{:?}\t{:?}\t{}",
        record.name(),
        record.ttl(),
        record.dns_class(),
        record.record_type(),
        data_str
    )
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
        _ => 16,             // Default estimate
    }
}
