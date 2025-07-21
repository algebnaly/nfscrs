use onc_rpc::auth::AuthUnixParams;
pub enum AuthType {
    AuthUnix(AuthUnixParams<String>),
    AuthKerberos, //not implemented
}
