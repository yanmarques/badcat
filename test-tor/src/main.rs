use std::path::Path;

use tor::stream::Connection;

fn main() {
    let hs = tor::Tor::new(&Path::new("torrc").to_path_buf());

    tor::stream::listen_connections(8000, on_connection).unwrap();

    hs.stop().unwrap();
}

fn on_connection(conn: &mut Connection) {
    conn.write("PASSWORD\n".as_bytes());

    let mut user = Vec::<u8>::new();
    conn.read(&mut user);

    println!("recv passwd: {}", String::from_utf8_lossy(&user));
}