use nfscrs::NFSClientBuilder;

fn main() {
    let mut client = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    client.test_null_call().unwrap();
    println!("test success!");
}
