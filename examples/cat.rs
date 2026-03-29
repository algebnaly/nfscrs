use std::io::Write;

use nfscrs::{NFSClientBuilder, OpenOptions};

fn main() {
    let client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");

    let open_opt = OpenOptions::new().read(true);
    let mut opened_file = session
        .open_file(&"/note.md".try_into().unwrap(), open_opt)
        .unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let mut offset = 0;
    loop {
        let read_result = session.read(&mut opened_file, offset, 1024).unwrap();
        buf.extend(read_result.data.iter());
        if read_result.eof {
            break;
        }
        offset += read_result.data.len();
    }
    std::io::stdout().write(&buf).unwrap();
}
