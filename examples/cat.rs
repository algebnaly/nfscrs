use nfscrs::NFSClientBuilder;

fn main() {
    let mut client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");
    
    session.open(&"/note.md".try_into().unwrap()).unwrap();
}
