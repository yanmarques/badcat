use std::ffi::CString;
use std::thread::{self, JoinHandle};
use std::path::PathBuf;

extern "C" {
    fn tor_main(argc: usize, argv: *const *const i8);
    fn tor_shutdown_event_loop_and_exit(exit_code: usize);
}

fn init_from_rc(torrc: &str) {
    let argv1 = CString::new("tor").unwrap();
    let argv2 = CString::new("-f").unwrap();
    let argv3 = CString::new(torrc).unwrap();

    let argv = vec![
        argv1.as_ptr(),
        argv2.as_ptr(),
        argv3.as_ptr(),
    ];

    unsafe {
        tor_main(argv.len(), argv.as_ptr());
    }
}

fn shutdown_with_code(exit_code: usize) {
    unsafe {
        tor_shutdown_event_loop_and_exit(exit_code);
    }
}

pub struct Tor {
    inner: JoinHandle<()>,
}

#[allow(dead_code)]
impl Tor {
    pub fn new(torrc: &PathBuf) -> Self {
        let torrc = String::from(torrc.to_str().unwrap());

        let inner = thread::spawn(move || {
            init_from_rc(&torrc);
        });

        Tor {
            inner, 
        }
    }

    pub fn stop(self) -> Result<(), Box<dyn std::error::Error>> {
        shutdown_with_code(0);
        self.inner.join().unwrap();
        Ok(())
    }
}