use std::{path::Path, thread::sleep, time::Duration};

use nfscrs::{NFSClientBuilder, nfscrs_types::AbsolutePath};

fn main() {
    let mut client_builder = NFSClientBuilder::new(1000, 1000, "127.0.0.1:2049".parse().unwrap());
    let mut session = client_builder
        .establish_session()
        .expect("failed to establish session");
    // let attrs = session.test_get_attr().unwrap();
    let v = session
        .list_dir(&AbsolutePath::try_from(Path::new("/")).unwrap())
        .unwrap();
    for i in v{
        println!("{:?}", i);
    }
    // session.put_root_fh().unwrap();
    // let attrs = session.get_attr(vec![1]).unwrap();
    // println!("{:?}", attrs);
}
