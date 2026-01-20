use std::fmt::Formatter;

use onc_rpc::auth::AuthUnixParams;

pub enum AuthType {
    AuthUnix(AuthUnixParams<String>),
    AuthKerberos, //not implemented
}
impl std::fmt::Debug for AuthType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::AuthUnix(_) => f.write_str("AuthUnix"),
            AuthType::AuthKerberos => f.write_str("AuthKerberos"),
        }
    }
}
