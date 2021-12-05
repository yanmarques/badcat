use std::error::Error;
use std::{collections::HashMap, sync::Mutex};
use std::{slice, thread, time};

use once_cell::sync::Lazy;

extern "C" {
    fn buf_new() -> *mut u8;
    fn buf_add(buf: *mut u8, string: *const u8, string_len: usize) -> i32;

    pub fn connection_get_by_global_id(global_id: u64) -> *mut u8;

    pub fn rust_hs_call_read_callback(conn: *mut u8);
    pub fn rust_hs_call_write_callback(conn: *mut u8);
    pub fn rust_hs_conn_end(conn: *mut u8);
}

static CONN_BUFFERS: Lazy<Mutex<HashMap<u64, Buffers>>> = Lazy::new(|| {
    let buffers = HashMap::new();
    Mutex::new(buffers)
});

static SERVERS: Lazy<Mutex<HashMap<u16, Server>>> = Lazy::new(|| {
    let servers = HashMap::new();
    Mutex::new(servers)
});

#[derive(Debug)]
pub struct Buffers {
    /// Input buffer used to send data. When empty, it means
    /// that data was sent.
    pub inbuf: Vec<u8>,

    /// Output buffer used to receive data. When not empty means that
    /// data is available.
    pub outbuf: Vec<u8>,
}

impl Buffers {
    pub fn new() -> Self {
        Buffers {
            inbuf: Vec::new(),
            outbuf: Vec::new(),
        }
    }
}

pub struct Server {
    /// Virtual port to listen on.
    pub port: u16,

    /// When a connection arrives, call this function.
    pub listener: fn(&mut Connection),
}

impl Server {
    pub fn handle(&self, global_id: u64) {
        let listener = self.listener;
        thread::spawn(move || {
            listener(&mut Connection::new(global_id));
        });
    }
}

/// An abstraction of reading/writing data to Tor's connection
/// Note that the whole implementation is not thread-safe.
pub struct Connection {
    /// It's the global_identifier of Tor's connection
    id: u64,

    /// Defines whether the connection is closed or not.
    /// Closing a connection manually will not close the
    /// underlying Tor connection. Although the connection
    /// may get closed when the underlying connection is closed.
    closed: bool,
}

impl Connection {
    pub fn new(global_identifier: u64) -> Self {
        Connection {
            id: global_identifier,
            closed: false,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    pub fn from_listener(global_identifier: u64) -> Self {
        Connection {
            id: global_identifier,
            closed: false,
        }
    }

    pub fn read(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.closed {
            return false;
        }

        let sleep = time::Duration::from_millis(200);

        loop {
            if let Some(conn) = self.get_tor_connection_or_close() {
                unsafe { rust_hs_call_write_callback(conn) };

                let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
                    panic!("problem accessing global connection buffers");
                });

                if let Some(buffer) = buffers.get_mut(&self.id) {
                    if buffer.outbuf.len() > 0 {
                        buf.extend(&buffer.outbuf);
                        buffer.outbuf.clear();
                        return true;
                    }
                }
            } else {
                return false;
            }

            thread::sleep(sleep);
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> bool {
        if self.closed {
            return false;
        }

        if let Some(conn) = self.get_tor_connection_or_close() {
            {
                let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
                    panic!("problem accessing global connection buffers");
                });

                if let Some(buffer) = buffers.get_mut(&self.id) {
                    buffer.inbuf.extend(buf);
                }
            }

            unsafe { rust_hs_call_read_callback(conn) };

            let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
                panic!("problem accessing global connection buffers");
            });

            if let Some(buffer) = buffers.get_mut(&self.id) {
                let buflen = buffer.inbuf.len();
                buffer.inbuf.clear();

                return buflen == 0;
            }
        }

        false
    }

    pub fn close(&mut self) {
        if let Some(conn) = self.get_tor_connection_or_close() {
            unsafe { rust_hs_conn_end(conn) }
        }
    }

    fn get_tor_connection_or_close(&mut self) -> Option<*mut u8> {
        let conn = unsafe { connection_get_by_global_id(self.id) };

        if conn as usize == 0 {
            self.closed = true;
            None
        } else {
            Some(conn)
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}
 
pub fn listen_connections(port: u16, listener: fn(&mut Connection)) -> Result<(), Box<dyn Error>> {
    let mut servers = SERVERS.lock().unwrap_or_else(|_| {
        panic!("problem accessing global servers");
    });

    if let Some(_) = servers.get(&port) {
        return Err(String::from("port already in use").into());
    }

    let server = Server { port, listener };

    servers.insert(port, server);

    Ok(())
}

pub fn write_buf(global_id: u64, buf: *const u8, buf_len: usize) {
    let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
        panic!("problem accessing global connections buffers");
    });

    if let Some(buffer) = buffers.get_mut(&global_id) {
        let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

        buffer.outbuf.extend(buf);
    } else {
        println!("WARN: recv buf from unknow connection: {:?}", global_id);
    }
}

pub fn conn_matches_port(port: u16) -> i32 {
    let servers = SERVERS.lock().unwrap_or_else(|_| {
        panic!("problem accessing global servers");
    });

    if servers.contains_key(&port) {
        1
    } else {
        0
    }
}

pub fn read_buf(global_id: u64) -> *const u8 {
    let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
        panic!("problem accessing global connections buffers");
    });

    if let Some(buffer) = buffers.get_mut(&global_id) {
        let buf = unsafe {
            let buf = buf_new();
            buf_add(buf, buffer.inbuf.as_ptr(), buffer.inbuf.len());

            buf
        };

        buffer.inbuf.clear();

        buf
    } else {
        println!("WARN: recv buf from unknow connection: {:?}", global_id);
        unsafe { buf_new() }
    }
}

pub fn register_conn(global_id: u64, port: u16) -> i32 {
    let servers = SERVERS.lock().unwrap_or_else(|_| {
        panic!("problem accessing global servers");
    });

    if let Some(server) = servers.get(&port) {
        // Executed inside a statement so CONN_BUFFERS are unlocked
        // before calling server.handle()
        {
            let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
                panic!("problem accessing global connections buffers");
            });

            if let None = buffers.get(&global_id) {
                // Allocate buffers for the connection
                let buffer = Buffers::new();
                buffers.insert(global_id, buffer);
            } else {
                println!("connection already send: {:?}", global_id);
                return 1;
            }
        }

        // Notify the server about a new connection
        server.handle(global_id);

        0
    } else {
        // TODO: add possibility for default handler
        println!("receive orphan connection, anyone is listening to them");
        -1
    }
}
