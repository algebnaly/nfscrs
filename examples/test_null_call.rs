use std::net::IpAddr;

use nfscrs::NFSClientBuilder;

fn main() {
    let mut client = NFSClientBuilder::new(1000, 1000, "192.168.1.149:2049".parse().unwrap());
    client.test_null_call().unwrap();
    println!("test success!");
}
