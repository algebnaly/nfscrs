use nfscrs::NFSClientBuilder;
use nfscrs::OpenOptions;
use std::env;
use std::io::Read;

fn main() {
    let client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <arg1> <arg2>", args[0]);
        std::process::exit(1);
    }
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");

    let open_opt = OpenOptions::new().create(true).write(true);

    let opening_file = session
        .open(&format!("{}", args[2]).try_into().unwrap(), open_opt)
        .unwrap();
    let mut opened_file = session.open_confirm(opening_file).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .open(format!("{}", args[1]))
        .unwrap();
    let mut buf: [u8; 1024] = [0; 1024];
    loop {
        let count = f.read(&mut buf).unwrap();
        if count == 0 {
            break;
        }
        session.write(&mut opened_file, &buf[..count]).unwrap();
    }
}
