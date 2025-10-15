use nfscrs::NFSClientBuilder;

fn main() {
    let client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");
    let attr = session
        .get_attr(
            &"/".try_into().unwrap(),
            vec![2 | 4], // type and expire time
        )
        .unwrap();
    let r = attr.fetch_attr_raw(1).unwrap();
    println!("{:?}", r);
}
