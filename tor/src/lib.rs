use std::ffi::CString;

extern "C" {
    fn tor_main(argc: usize, argv: *const *const i8);
}

pub fn start(torrc: &str) {
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