use std::io::Write;

use nfscrs::NFSClientBuilder;


fn main() {
    let client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");

    let opening_file = session.open(&"/note.md".try_into().unwrap()).unwrap();
    let mut opened_file = session.open_confirm(opening_file).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let read_result = session.read(&mut opened_file, 1024).unwrap();
        buf.extend(read_result.data.iter());
        if read_result.eof {
            break;
        }
    }
    std::io::stdout().write(&buf).unwrap();
}
