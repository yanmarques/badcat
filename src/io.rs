use std::{io, thread};

pub fn pipe_io<R, W>(mut r: R, mut w: W) -> thread::JoinHandle<()>
where R: io::Read + Send + 'static,
      W: io::Write + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = [0; 1024];

        loop {
            let len = match r.read(&mut buf) {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(_) => break
            };

            if let Err(_) = w.write(&buf[..len]) {
                break;
            }

            if let Err(_) = w.flush() {
                break;
            };
        }
    })
}