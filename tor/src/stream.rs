use std::error::Error;
use std::{collections::HashMap, sync::Mutex};
use std::{io, slice, thread, time};

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

static CONN_LOCK: Lazy<Mutex<HashMap<u16, Option<u64>>>> = Lazy::new(|| {
    let locks = HashMap::new();
    Mutex::new(locks)
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

pub trait ConnectionHandler<'l> {
    fn handle(conn: &'l mut Connection);
}

pub struct Server<> {
    /// Virtual port to listen on.
    port: u16,
}

impl Server {
    pub fn listen(port: u16) -> Result<Self, Box<dyn Error>> {
        let mut servers = SERVERS.lock().unwrap_or_else(|_| {
            panic!("problem accessing global servers");
        });
    
        if let Some(_) = servers.get(&port) {
            return Err(String::from("port already in use").into());
        }
    
        let server = Server { port };
    
        servers.insert(port, server);
    
        Ok(server)
    }

    pub fn incoming(&self) -> Connection {
        let sleep = time::Duration::from_millis(200);

        loop {
            if let Ok(mut locks) = CONN_LOCK.try_lock() {
                let mut connection: Option<Connection> = None;

                if let Some(option) = locks.get(&self.port) {
                    if let Some(conn_id) = option {
                        connection = Some(Connection::new(*conn_id, true));
                    }
                }

                if let Some(conn) = connection {
                    locks.insert(self.port, None);
                    return conn;
                }
            }

            thread::sleep(sleep);
        }
    }

    pub fn handle(&self, global_id: u64) {
        let mut locks = CONN_LOCK.lock().unwrap_or_else(|_| {
            panic!("problem accessing global servers");
        });
    
        locks.insert(self.port, Some(global_id));
    }
}

impl Copy for Server {}
impl Clone for Server {
    fn clone(&self) -> Self {
        Server {
            port: self.port,
        }
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

    auto_close: bool,
}

impl Connection {
    pub fn new(global_identifier: u64, auto_close: bool) -> Self {
        Connection {
            id: global_identifier,
            closed: false,
            auto_close,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    pub fn hold(&mut self) {
        self.auto_close = false;
    }

    pub fn clone(&self) -> Self {
        Connection {
            id: self.id,
            closed: self.closed,
            auto_close: self.auto_close,
        }
    }

    pub fn poll(&mut self, timeout: Option<time::Duration>) -> Result<bool, io::Error> {
        if self.closed {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }

        let has_timeout = timeout.is_some();
        let now = time::Instant::now();
        let sleep = time::Duration::from_millis(200);

        loop {
            {
                let buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
                    panic!("problem accessing global connection buffers");
                });

                if let Some(buffer) = buffers.get(&self.id) {
                    if buffer.outbuf.len() > 0 {
                        return Ok(true);
                    }

                    thread::sleep(sleep);
                }
            }

            if let Some(conn) = self.get_tor_connection_or_close() {
                unsafe { rust_hs_call_write_callback(conn) };
            } else {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }

            if has_timeout && now.elapsed() > timeout.unwrap() {
                return Ok(false);
            }
        }
    }

    pub fn close(&mut self) {
        println!("YAN: closing connection: {}", self.id);
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
        if self.auto_close {
            self.close();
        }
    }
}

impl io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        loop {
            // TODO: fix race condition to lock CONN_BUFFERS 
            if self.poll(None)? {
                let mut buffers = CONN_BUFFERS.lock().unwrap_or_else(|_| {
                    panic!("problem accessing global connection buffers");
                });

                if let Some(buffer) = buffers.get_mut(&self.id) {
                    let outbuf_len = buffer.outbuf.len();
                    let buf_len = buf.len();

                    let bytes_read = if outbuf_len < buf_len {
                        // Received LESS bytes than available buf

                        // Append to buf all received bytes
                        for (index, byte) in buffer.outbuf.iter().enumerate() {
                            buf[index] = *byte;
                        }

                        buffer.outbuf.clear();

                        outbuf_len
                    } else {
                        // Received MORE bytes than available buf

                        // Copy to buf a buffer with the same size
                        let eq_buf = &buffer.outbuf.clone()[..buf_len];
                        buf.copy_from_slice(eq_buf);

                        // Mark some outbuf data to be removed
                        buffer.outbuf.drain(..buf_len).for_each(drop);

                        buf_len
                    };

                    return Ok(bytes_read);   
                }
            }
        }
    }
}

impl io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if self.closed {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
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

                return Ok(buflen);
            }
        }

        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        //
        Ok(())
    }
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
