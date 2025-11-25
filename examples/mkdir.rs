use nfscrs::NFSClientBuilder;

fn main() {
    let client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");
    session
        .mkdir(&"/a/b/c".parse().unwrap(), true, false)
        .unwrap();
}
