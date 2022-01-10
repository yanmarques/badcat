use std::io::{Read, Write};
use std::slice;
use std::time::Duration;

use badcat_lib::cmem;
use tor::{
    stream::{Connection, Server},
    Tor,
};

#[no_mangle]
pub unsafe extern "C" fn badcat_wait_conn(port: u16) -> u64 {
    if let Ok(server) = Server::listen(port) {
        let mut conn = server.incoming();
        conn.hold();
        conn.id()
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn badcat_read_conn(
    conn_id: u64,
    size: usize,
    buf_len: *mut usize,
) -> *const u8 {
    let mut conn = Connection::new(conn_id, false);

    let mut buf = Vec::<u8>::new();
    for _ in 0..size {
        buf.push(0);
    }

    match conn.read(&mut buf) {
        Ok(n) => {
            if n <= 0 {
                return 0 as *const u8;
            }

            if n < size {
                // resize buffer to the length of actually read bytes
                buf.drain(n..size).for_each(drop);
            }

            *buf_len = buf.len();

            // I could not just return `buf.as_ptr`, because C memory layout
            // would not expect such Vector pointer.
            // In order to return a char pointer, manually create the exact memory
            // layout C code expects. The code above is analogous to the following
            // C pseudo-code:
            //
            //      // Assume a `buf` variable of type `char[]`.
            //      // Assume a `buf_len` with the length of `buf`.
            //
            //      char *ptr = (char *) malloc(sizeof(buf));
            //      for (int index = 0; index < buf_len; index++) {
            //          *(ptr + index) = buf[index];
            //      }
            let raw_ptr = cmem::c_array::<u8>(buf);
            raw_ptr
        }
        Err(_) => 0 as *const u8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn badcat_poll_conn(conn_id: u64, timeout: u64) -> i32 {
    let mut conn = Connection::new(conn_id, false);

    match conn.poll(Some(Duration::from_secs(timeout))) {
        Ok(r) => {
            if r {
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn badcat_write_conn(conn_id: u64, buf: *const u8, buf_len: usize) -> usize {
    let mut conn = Connection::new(conn_id, false);

    let buf = slice::from_raw_parts(buf, buf_len);

    match conn.write(buf) {
        Ok(n) => n,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn badcat_start_tor() {
    Tor::threadless(vec!["tor", "-f", "torrc"]);
}

// extern "C" {
//     fn mainThread(argc: u32, argv: *const *const i8, so: bool) -> u32;
// }

// pub fn main() {
//     let argv1 = CString::new("abc").unwrap();

//     let argv = vec![argv1.as_ptr()];

//     unsafe {
//         mainThread(1, argv.as_ptr(), false);
//     }
// }
