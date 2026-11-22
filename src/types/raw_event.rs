//! Raw event bodies, one per [`RawEventKind`](super::RawEventKind).
//!
//! Each struct copies, field for field, the ingest struct of the same kind
//! in giganto-client (`giganto_client::ingest::{network, sysmon, netflow}`)
//! at tag `0.29.2`.
//!
//! `Debug` is derived on every struct except [`Http`], [`Ftp`], [`Ldap`]
//! and [`Radius`], whose credential fields are printed as `<redacted>`.

use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};

/// What a hand-written `Debug` prints in place of a credential field.
const REDACTED: &str = "<redacted>";

/// The `Conn` raw event body, copying giganto-client's `ingest::network::Conn`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conn {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
}

/// The `Dns` raw event body, copying giganto-client's `ingest::network::Dns`.
// The fields mirror giganto-client, which allows this lint on the same struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dns {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
}

/// The `MalformedDns` raw event body, copying giganto-client's `ingest::network::MalformedDns`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalformedDns {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub trans_id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query_count: u32,
    pub resp_count: u32,
    pub query_bytes: u64,
    pub resp_bytes: u64,
    pub query_body: Vec<Vec<u8>>,
    pub resp_body: Vec<Vec<u8>>,
}

/// The `Http` raw event body, copying giganto-client's `ingest::network::Http`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
}

/// `password` and `cookie` carry credentials captured from the
/// session, so they are redacted rather than derived; every other
/// field is printed as a derived `Debug` would print it.
impl fmt::Debug for Http {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Destructured so that a field added to the struct fails to
        // compile here until it is printed or redacted.
        let Self {
            orig_addr,
            orig_port,
            resp_addr,
            resp_port,
            proto,
            start_time,
            duration,
            orig_pkts,
            resp_pkts,
            orig_l2_bytes,
            resp_l2_bytes,
            method,
            host,
            uri,
            referer,
            version,
            user_agent,
            request_len,
            response_len,
            status_code,
            status_msg,
            username,
            password: _,
            cookie: _,
            content_encoding,
            content_type,
            cache_control,
            filenames,
            mime_types,
            body,
            state,
        } = self;
        f.debug_struct("Http")
            .field("orig_addr", orig_addr)
            .field("orig_port", orig_port)
            .field("resp_addr", resp_addr)
            .field("resp_port", resp_port)
            .field("proto", proto)
            .field("start_time", start_time)
            .field("duration", duration)
            .field("orig_pkts", orig_pkts)
            .field("resp_pkts", resp_pkts)
            .field("orig_l2_bytes", orig_l2_bytes)
            .field("resp_l2_bytes", resp_l2_bytes)
            .field("method", method)
            .field("host", host)
            .field("uri", uri)
            .field("referer", referer)
            .field("version", version)
            .field("user_agent", user_agent)
            .field("request_len", request_len)
            .field("response_len", response_len)
            .field("status_code", status_code)
            .field("status_msg", status_msg)
            .field("username", username)
            .field("password", &REDACTED)
            .field("cookie", &REDACTED)
            .field("content_encoding", content_encoding)
            .field("content_type", content_type)
            .field("cache_control", cache_control)
            .field("filenames", filenames)
            .field("mime_types", mime_types)
            .field("body", body)
            .field("state", state)
            .finish()
    }
}

/// The `Rdp` raw event body, copying giganto-client's `ingest::network::Rdp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rdp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub cookie: String,
}

/// The `Smtp` raw event body, copying giganto-client's `ingest::network::Smtp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Smtp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
}

/// The `Ntlm` raw event body, copying giganto-client's `ingest::network::Ntlm`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ntlm {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
}

/// The `Kerberos` raw event body, copying giganto-client's `ingest::network::Kerberos`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kerberos {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub cname: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub sname: Vec<String>,
}

/// The `Ssh` raw event body, copying giganto-client's `ingest::network::Ssh`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ssh {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
}

/// The `DceRpc` raw event body, copying giganto-client's `ingest::network::DceRpc`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DceRpc {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub context: Vec<DceRpcContext>,
    pub request: Vec<String>,
}

/// A nested record of a raw event body, copying giganto-client's `ingest::network::DceRpcContext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DceRpcContext {
    pub id: u16,
    pub abstract_syntax: u128,
    pub abstract_major: u16,
    pub abstract_minor: u16,
    pub transfer_syntax: u128,
    pub transfer_major: u16,
    pub transfer_minor: u16,
    pub acceptance: u16,
    pub reason: u16,
}

/// The `Ftp` raw event body, copying giganto-client's `ingest::network::Ftp`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ftp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
}

/// `password` carries the credential captured from the session, so
/// it is redacted rather than derived; every other
/// field is printed as a derived `Debug` would print it.
impl fmt::Debug for Ftp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Destructured so that a field added to the struct fails to
        // compile here until it is printed or redacted.
        let Self {
            orig_addr,
            orig_port,
            resp_addr,
            resp_port,
            proto,
            start_time,
            duration,
            orig_pkts,
            resp_pkts,
            orig_l2_bytes,
            resp_l2_bytes,
            user,
            password: _,
            commands,
        } = self;
        f.debug_struct("Ftp")
            .field("orig_addr", orig_addr)
            .field("orig_port", orig_port)
            .field("resp_addr", resp_addr)
            .field("resp_port", resp_port)
            .field("proto", proto)
            .field("start_time", start_time)
            .field("duration", duration)
            .field("orig_pkts", orig_pkts)
            .field("resp_pkts", resp_pkts)
            .field("orig_l2_bytes", orig_l2_bytes)
            .field("resp_l2_bytes", resp_l2_bytes)
            .field("user", user)
            .field("password", &REDACTED)
            .field("commands", commands)
            .finish()
    }
}

/// A nested record of a raw event body, copying giganto-client's `ingest::network::FtpCommand`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtpCommand {
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
}

/// The `Mqtt` raw event body, copying giganto-client's `ingest::network::Mqtt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mqtt {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
}

/// The `Ldap` raw event body, copying giganto-client's `ingest::network::Ldap`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ldap {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
}

/// `argument` carries the password of a simple bind captured from the
/// session, so it is redacted rather than derived; every other field
/// is printed as a derived `Debug` would print it.
impl fmt::Debug for Ldap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Destructured so that a field added to the struct fails to
        // compile here until it is printed or redacted.
        let Self {
            orig_addr,
            orig_port,
            resp_addr,
            resp_port,
            proto,
            start_time,
            duration,
            orig_pkts,
            resp_pkts,
            orig_l2_bytes,
            resp_l2_bytes,
            message_id,
            version,
            opcode,
            result,
            diagnostic_message,
            object,
            argument: _,
        } = self;
        f.debug_struct("Ldap")
            .field("orig_addr", orig_addr)
            .field("orig_port", orig_port)
            .field("resp_addr", resp_addr)
            .field("resp_port", resp_port)
            .field("proto", proto)
            .field("start_time", start_time)
            .field("duration", duration)
            .field("orig_pkts", orig_pkts)
            .field("resp_pkts", resp_pkts)
            .field("orig_l2_bytes", orig_l2_bytes)
            .field("resp_l2_bytes", resp_l2_bytes)
            .field("message_id", message_id)
            .field("version", version)
            .field("opcode", opcode)
            .field("result", result)
            .field("diagnostic_message", diagnostic_message)
            .field("object", object)
            .field("argument", &REDACTED)
            .finish()
    }
}

/// The `Tls` raw event body, copying giganto-client's `ingest::network::Tls`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
}

/// The `Smb` raw event body, copying giganto-client's `ingest::network::Smb`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Smb {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
}

/// The `Nfs` raw event body, copying giganto-client's `ingest::network::Nfs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nfs {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
}

/// The `Bootp` raw event body, copying giganto-client's `ingest::network::Bootp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bootp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
}

/// The `Dhcp` raw event body, copying giganto-client's `ingest::network::Dhcp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dhcp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub options: Vec<(u8, Vec<u8>)>,
}

/// The `Radius` raw event body, copying giganto-client's `ingest::network::Radius`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Radius {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
}

/// `user_passwd` and `chap_passwd` carry credentials captured
/// from the session, so they are redacted rather than derived; every other
/// field is printed as a derived `Debug` would print it.
impl fmt::Debug for Radius {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Destructured so that a field added to the struct fails to
        // compile here until it is printed or redacted.
        let Self {
            orig_addr,
            orig_port,
            resp_addr,
            resp_port,
            proto,
            start_time,
            duration,
            orig_pkts,
            resp_pkts,
            orig_l2_bytes,
            resp_l2_bytes,
            id,
            code,
            resp_code,
            auth,
            resp_auth,
            user_name,
            user_passwd: _,
            chap_passwd: _,
            nas_ip,
            nas_port,
            state,
            nas_id,
            nas_port_type,
            message,
        } = self;
        f.debug_struct("Radius")
            .field("orig_addr", orig_addr)
            .field("orig_port", orig_port)
            .field("resp_addr", resp_addr)
            .field("resp_port", resp_port)
            .field("proto", proto)
            .field("start_time", start_time)
            .field("duration", duration)
            .field("orig_pkts", orig_pkts)
            .field("resp_pkts", resp_pkts)
            .field("orig_l2_bytes", orig_l2_bytes)
            .field("resp_l2_bytes", resp_l2_bytes)
            .field("id", id)
            .field("code", code)
            .field("resp_code", resp_code)
            .field("auth", auth)
            .field("resp_auth", resp_auth)
            .field("user_name", user_name)
            .field("user_passwd", &REDACTED)
            .field("chap_passwd", &REDACTED)
            .field("nas_ip", nas_ip)
            .field("nas_port", nas_port)
            .field("state", state)
            .field("nas_id", nas_id)
            .field("nas_port_type", nas_port_type)
            .field("message", message)
            .finish()
    }
}

/// The `Icmp` raw event body, copying giganto-client's `ingest::network::Icmp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Icmp {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub id: u16,
    pub seq_num: u16,
    pub data_len: u16,
    pub payload: Vec<u8>,
}

/// The `ProcessCreate` raw event body, copying giganto-client's `ingest::sysmon::ProcessCreate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCreate {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub file_version: String,
    pub description: String,
    pub product: String,
    pub company: String,
    pub original_file_name: String,
    pub command_line: String,
    pub current_directory: String,
    pub user: String,
    pub logon_guid: String,
    pub logon_id: u32,
    pub terminal_session_id: u32,
    pub integrity_level: String,
    pub hashes: Vec<String>,
    pub parent_process_guid: String,
    pub parent_process_id: u32,
    pub parent_image: String,
    pub parent_command_line: String,
    pub parent_user: String,
}

/// The `FileCreateTime` raw event body, copying giganto-client's `ingest::sysmon::FileCreationTimeChanged`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCreateTime {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: i64,
    pub previous_creation_utc_time: i64,
    pub user: String,
}

/// The `NetworkConnect` raw event body, copying giganto-client's `ingest::sysmon::NetworkConnection`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnect {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub protocol: String,
    pub initiated: bool,
    pub source_is_ipv6: bool,
    pub source_ip: IpAddr,
    pub source_hostname: String,
    pub source_port: u16,
    pub source_port_name: String,
    pub destination_is_ipv6: bool,
    pub destination_ip: IpAddr,
    pub destination_hostname: String,
    pub destination_port: u16,
    pub destination_port_name: String,
}

/// The `ProcessTerminate` raw event body, copying giganto-client's `ingest::sysmon::ProcessTerminated`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTerminate {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
}

/// The `ImageLoad` raw event body, copying giganto-client's `ingest::sysmon::ImageLoaded`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageLoad {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub image_loaded: String,
    pub file_version: String,
    pub description: String,
    pub product: String,
    pub company: String,
    pub original_file_name: String,
    pub hashes: Vec<String>,
    pub signed: bool,
    pub signature: String,
    pub signature_status: String,
    pub user: String,
}

/// The `FileCreate` raw event body, copying giganto-client's `ingest::sysmon::FileCreate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCreate {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: i64,
    pub user: String,
}

/// The `RegistryValueSet` raw event body, copying giganto-client's `ingest::sysmon::RegistryValueSet`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValueSet {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_object: String,
    pub details: String,
    pub user: String,
}

/// The `RegistryKeyRename` raw event body, copying giganto-client's `ingest::sysmon::RegistryKeyValueRename`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryKeyRename {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_object: String,
    pub new_name: String,
    pub user: String,
}

/// The `FileCreateStreamHash` raw event body, copying giganto-client's `ingest::sysmon::FileCreateStreamHash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCreateStreamHash {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: i64,
    pub hash: Vec<String>,
    pub contents: String,
    pub user: String,
}

/// The `PipeEvent` raw event body, copying giganto-client's `ingest::sysmon::PipeEvent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeEvent {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub pipe_name: String,
    pub image: String,
    pub user: String,
}

/// The `DnsQuery` raw event body, copying giganto-client's `ingest::sysmon::DnsEvent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuery {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub query_name: String,
    pub query_status: u32,
    pub query_results: Vec<String>, // divided by ';'
    pub image: String,
    pub user: String,
}

/// The `FileDelete` raw event body, copying giganto-client's `ingest::sysmon::FileDelete`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDelete {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub user: String,
    pub image: String,
    pub target_filename: String,
    pub hashes: Vec<String>,
    pub is_executable: bool,
    pub archived: bool,
}

/// The `ProcessTamper` raw event body, copying giganto-client's `ingest::sysmon::ProcessTampering`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTamper {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub tamper_type: String, // type
    pub user: String,
}

/// The `FileDeleteDetected` raw event body, copying giganto-client's `ingest::sysmon::FileDeleteDetected`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeleteDetected {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub user: String,
    pub image: String,
    pub target_filename: String,
    pub hashes: Vec<String>,
    pub is_executable: bool,
}

/// The `Netflow5` raw event body, copying giganto-client's `ingest::netflow::Netflow5`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Netflow5 {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub next_hop: IpAddr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32, // milliseconds
    pub last: u32,  // milliseconds
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8, // Hex
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u8,
    pub sampling_rate: u16,
}

/// The `Netflow9` raw event body, copying giganto-client's `ingest::netflow::Netflow9`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Netflow9 {
    pub sequence: u32,
    pub source_id: u32,
    pub template_id: u16,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub contents: String,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::super::{RawEventBody, RawEventKind};
    use super::*;

    const HTTP_PASSWORD: &str = "http-password-secret";
    const HTTP_COOKIE: &str = "session=http-cookie-secret";
    const FTP_PASSWORD: &str = "ftp-password-secret";
    const LDAP_ARGUMENT: &str = "ldap-bind-password-secret";
    const RADIUS_USER_PASSWD: &[u8] = b"radius-user-passwd-secret";
    const RADIUS_CHAP_PASSWD: &[u8] = b"radius-chap-passwd-secret";

    /// The kinds and numbers the schema commits to.
    const TABLE: [(RawEventKind, u32); 36] = [
        (RawEventKind::Conn, 0),
        (RawEventKind::Dns, 1),
        (RawEventKind::Http, 3),
        (RawEventKind::Rdp, 4),
        (RawEventKind::Smtp, 6),
        (RawEventKind::Ntlm, 7),
        (RawEventKind::Kerberos, 8),
        (RawEventKind::Ssh, 9),
        (RawEventKind::DceRpc, 10),
        (RawEventKind::Ftp, 14),
        (RawEventKind::Mqtt, 15),
        (RawEventKind::Ldap, 16),
        (RawEventKind::Tls, 17),
        (RawEventKind::Smb, 18),
        (RawEventKind::Nfs, 19),
        (RawEventKind::Bootp, 21),
        (RawEventKind::Dhcp, 22),
        (RawEventKind::Radius, 23),
        (RawEventKind::MalformedDns, 24),
        (RawEventKind::Icmp, 25),
        (RawEventKind::ProcessCreate, 31),
        (RawEventKind::FileCreateTime, 32),
        (RawEventKind::NetworkConnect, 33),
        (RawEventKind::ProcessTerminate, 35),
        (RawEventKind::ImageLoad, 37),
        (RawEventKind::FileCreate, 41),
        (RawEventKind::RegistryValueSet, 43),
        (RawEventKind::RegistryKeyRename, 44),
        (RawEventKind::FileCreateStreamHash, 45),
        (RawEventKind::PipeEvent, 47),
        (RawEventKind::DnsQuery, 52),
        (RawEventKind::FileDelete, 53),
        (RawEventKind::ProcessTamper, 55),
        (RawEventKind::FileDeleteDetected, 56),
        (RawEventKind::Netflow5, 60),
        (RawEventKind::Netflow9, 61),
    ];

    /// Returns every `RawEventKind`, found by scanning the numbers the enum
    /// accepts rather than from a hand-kept list.
    fn scanned_kinds() -> Vec<RawEventKind> {
        (0..=u32::from(u16::MAX))
            .filter_map(|n| RawEventKind::try_from(n).ok())
            .collect()
    }

    #[test]
    fn kind_numbers_match_table() {
        for (kind, number) in TABLE {
            assert_eq!(u32::from(kind), number, "{kind:?}");
            assert_eq!(RawEventKind::try_from(number).ok(), Some(kind));
        }
        assert_eq!(
            scanned_kinds(),
            TABLE.iter().map(|(kind, _)| *kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn try_from_rejects_numbers_outside_the_subset() {
        for n in [2, 5, 11, 12, 13, 20, 26, 30, 62, 1000, u32::MAX] {
            assert!(RawEventKind::try_from(n).is_err(), "{n} was accepted");
        }
        let accepted = (0..=u32::from(u16::MAX))
            .filter(|n| RawEventKind::try_from(*n).is_ok())
            .count();
        assert_eq!(accepted, TABLE.len());
    }

    #[test]
    fn kind_serializes_as_number_in_json() {
        assert_eq!(
            serde_json::to_string(&RawEventKind::ProcessCreate).expect("serializes"),
            "31"
        );
        for (kind, number) in TABLE {
            let json = serde_json::to_string(&kind).expect("serializes");
            assert_eq!(json, number.to_string());
            let decoded: RawEventKind = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(decoded, kind);
        }
        assert!(serde_json::from_str::<RawEventKind>("2").is_err());
        assert!(serde_json::from_str::<RawEventKind>("\"ProcessCreate\"").is_err());
    }

    /// Checks one direction only: every kind here exists in giganto-client
    /// under the same number and name. Kinds only giganto-client has are not
    /// checked, so giganto-client adding a kind never breaks this crate.
    #[test]
    fn kinds_exist_in_giganto_client_with_same_number_and_name() {
        let kinds = scanned_kinds();
        assert_eq!(kinds.len(), 36);
        for kind in kinds {
            let number = u32::from(kind);
            let giganto = giganto_client::RawEventKind::try_from(number)
                .unwrap_or_else(|_| panic!("giganto-client has no kind numbered {number}"));
            assert_eq!(
                format!("{giganto:?}"),
                format!("{kind:?}"),
                "kind {number} is named differently in giganto-client"
            );
        }
    }
    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn v6(last: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
    }

    fn strings(prefix: &str) -> Vec<String> {
        vec![format!("{prefix}-1"), format!("{prefix}-2")]
    }

    fn s(value: &str) -> String {
        value.to_string()
    }

    #[allow(clippy::too_many_lines)] // One synthetic body per kind.
    pub(super) fn bodies() -> Vec<RawEventBody> {
        vec![
            RawEventBody::Conn(Conn {
                orig_addr: v4(1),
                orig_port: 46378,
                resp_addr: v6(2),
                resp_port: 80,
                proto: 6,
                conn_state: s("SF"),
                start_time: 1_700_000_000_000_000_000,
                duration: 1_234_567,
                service: s("http"),
                orig_bytes: 77,
                resp_bytes: 295,
                orig_pkts: 397,
                resp_pkts: 511,
                orig_l2_bytes: 21515,
                resp_l2_bytes: 27889,
            }),
            RawEventBody::Dns(Dns {
                orig_addr: v4(3),
                orig_port: 53001,
                resp_addr: v4(4),
                resp_port: 53,
                proto: 17,
                start_time: 1_700_000_000_000_000_001,
                duration: 42,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 80,
                resp_l2_bytes: 120,
                query: s("example.com"),
                answer: strings("answer"),
                trans_id: 0x1234,
                rtt: 1000,
                qclass: 1,
                qtype: 28,
                rcode: 3,
                aa_flag: true,
                tc_flag: false,
                rd_flag: true,
                ra_flag: false,
                ttl: vec![60, -1, 3600],
            }),
            RawEventBody::Http(Http {
                orig_addr: v4(5),
                orig_port: 50000,
                resp_addr: v4(6),
                resp_port: 8080,
                proto: 6,
                start_time: 1_700_000_000_000_000_002,
                duration: 7,
                orig_pkts: 3,
                resp_pkts: 4,
                orig_l2_bytes: 300,
                resp_l2_bytes: 400,
                method: s("POST"),
                host: s("example.org"),
                uri: s("/login"),
                referer: s("https://example.net/"),
                version: s("1.1"),
                user_agent: s("synthetic-agent"),
                request_len: 512,
                response_len: 1024,
                status_code: 302,
                status_msg: s("Found"),
                username: s("user"),
                password: s(HTTP_PASSWORD),
                cookie: s(HTTP_COOKIE),
                content_encoding: s("gzip"),
                content_type: s("text/html"),
                cache_control: s("no-cache"),
                filenames: strings("file"),
                mime_types: strings("mime"),
                body: vec![1, 2, 3],
                state: s("done"),
            }),
            RawEventBody::Rdp(Rdp {
                orig_addr: v4(7),
                orig_port: 50001,
                resp_addr: v4(8),
                resp_port: 3389,
                proto: 6,
                start_time: 3,
                duration: 4,
                orig_pkts: 5,
                resp_pkts: 6,
                orig_l2_bytes: 7,
                resp_l2_bytes: 8,
                cookie: s("mstshash=user"),
            }),
            RawEventBody::Smtp(Smtp {
                orig_addr: v4(9),
                orig_port: 50002,
                resp_addr: v4(10),
                resp_port: 25,
                proto: 6,
                start_time: 9,
                duration: 10,
                orig_pkts: 11,
                resp_pkts: 12,
                orig_l2_bytes: 13,
                resp_l2_bytes: 14,
                mailfrom: s("a@example.com"),
                date: s("Mon, 1 Jan 2024"),
                from: s("A"),
                to: s("B"),
                subject: s("hello"),
                agent: s("mailer"),
                state: s("sent"),
            }),
            RawEventBody::Ntlm(Ntlm {
                orig_addr: v4(11),
                orig_port: 50003,
                resp_addr: v4(12),
                resp_port: 445,
                proto: 6,
                start_time: 15,
                duration: 16,
                orig_pkts: 17,
                resp_pkts: 18,
                orig_l2_bytes: 19,
                resp_l2_bytes: 20,
                protocol: s("ntlmssp"),
                username: s("user"),
                hostname: s("host"),
                domainname: s("domain"),
                success: s("true"),
            }),
            RawEventBody::Kerberos(Kerberos {
                orig_addr: v4(13),
                orig_port: 50004,
                resp_addr: v4(14),
                resp_port: 88,
                proto: 17,
                start_time: 21,
                duration: 22,
                orig_pkts: 23,
                resp_pkts: 24,
                orig_l2_bytes: 25,
                resp_l2_bytes: 26,
                client_time: 27,
                server_time: 28,
                error_code: 6,
                client_realm: s("EXAMPLE.COM"),
                cname_type: 1,
                cname: strings("cname"),
                realm: s("EXAMPLE.COM"),
                sname_type: 2,
                sname: strings("sname"),
            }),
            RawEventBody::Ssh(Ssh {
                orig_addr: v4(15),
                orig_port: 50005,
                resp_addr: v4(16),
                resp_port: 22,
                proto: 6,
                start_time: 29,
                duration: 30,
                orig_pkts: 31,
                resp_pkts: 32,
                orig_l2_bytes: 33,
                resp_l2_bytes: 34,
                client: s("SSH-2.0-client"),
                server: s("SSH-2.0-server"),
                cipher_alg: s("aes256-gcm"),
                mac_alg: s("hmac-sha2-256"),
                compression_alg: s("none"),
                kex_alg: s("curve25519-sha256"),
                host_key_alg: s("ssh-ed25519"),
                hassh_algorithms: s("hassh-algs"),
                hassh: s("hassh"),
                hassh_server_algorithms: s("hassh-server-algs"),
                hassh_server: s("hassh-server"),
                client_shka: s("client-shka"),
                server_shka: s("server-shka"),
            }),
            RawEventBody::DceRpc(DceRpc {
                orig_addr: v4(17),
                orig_port: 50006,
                resp_addr: v4(18),
                resp_port: 135,
                proto: 6,
                start_time: 35,
                duration: 36,
                orig_pkts: 37,
                resp_pkts: 38,
                orig_l2_bytes: 39,
                resp_l2_bytes: 40,
                context: vec![
                    DceRpcContext {
                        id: 1,
                        abstract_syntax: u128::MAX - 1,
                        abstract_major: 2,
                        abstract_minor: 3,
                        transfer_syntax: 0x8a88_5d04_1ceb_11c9_9fe8_0800_2b10_4860,
                        transfer_major: 4,
                        transfer_minor: 5,
                        acceptance: 6,
                        reason: 7,
                    },
                    DceRpcContext {
                        id: 2,
                        abstract_syntax: 8,
                        abstract_major: 9,
                        abstract_minor: 10,
                        transfer_syntax: 11,
                        transfer_major: 12,
                        transfer_minor: 13,
                        acceptance: 14,
                        reason: 15,
                    },
                ],
                request: strings("request"),
            }),
            RawEventBody::Ftp(Ftp {
                orig_addr: v4(19),
                orig_port: 50007,
                resp_addr: v4(20),
                resp_port: 21,
                proto: 6,
                start_time: 41,
                duration: 42,
                orig_pkts: 43,
                resp_pkts: 44,
                orig_l2_bytes: 45,
                resp_l2_bytes: 46,
                user: s("anonymous"),
                password: s(FTP_PASSWORD),
                commands: vec![
                    FtpCommand {
                        command: s("RETR"),
                        reply_code: s("226"),
                        reply_msg: s("Transfer complete"),
                        data_passive: true,
                        data_orig_addr: v4(21),
                        data_resp_addr: v6(22),
                        data_resp_port: 20,
                        file: s("a.txt"),
                        file_size: 4096,
                        file_id: s("file-1"),
                    },
                    FtpCommand {
                        command: s("STOR"),
                        reply_code: s("550"),
                        reply_msg: s("Denied"),
                        data_passive: false,
                        data_orig_addr: v6(23),
                        data_resp_addr: v4(24),
                        data_resp_port: 2121,
                        file: s("b.txt"),
                        file_size: 1,
                        file_id: s("file-2"),
                    },
                ],
            }),
            RawEventBody::Mqtt(Mqtt {
                orig_addr: v4(25),
                orig_port: 50008,
                resp_addr: v4(26),
                resp_port: 1883,
                proto: 6,
                start_time: 47,
                duration: 48,
                orig_pkts: 49,
                resp_pkts: 50,
                orig_l2_bytes: 51,
                resp_l2_bytes: 52,
                protocol: s("MQTT"),
                version: 5,
                client_id: s("client"),
                connack_reason: 1,
                subscribe: strings("topic"),
                suback_reason: vec![0, 1, 128],
            }),
            RawEventBody::Ldap(Ldap {
                orig_addr: v4(27),
                orig_port: 50009,
                resp_addr: v4(28),
                resp_port: 389,
                proto: 6,
                start_time: 53,
                duration: 54,
                orig_pkts: 55,
                resp_pkts: 56,
                orig_l2_bytes: 57,
                resp_l2_bytes: 58,
                message_id: 59,
                version: 3,
                opcode: strings("bind"),
                result: strings("success"),
                diagnostic_message: strings("diag"),
                object: strings("cn=admin"),
                argument: vec![s(LDAP_ARGUMENT)],
            }),
            RawEventBody::Tls(Tls {
                orig_addr: v4(29),
                orig_port: 50010,
                resp_addr: v4(30),
                resp_port: 443,
                proto: 6,
                start_time: 60,
                duration: 61,
                orig_pkts: 62,
                resp_pkts: 63,
                orig_l2_bytes: 64,
                resp_l2_bytes: 65,
                server_name: s("example.com"),
                alpn_protocol: s("h2"),
                ja3: s("ja3"),
                version: s("TLSv1.3"),
                client_cipher_suites: vec![0x1301, 0x1302],
                client_extensions: vec![0, 10, 11],
                cipher: 0x1301,
                extensions: vec![43, 51],
                ja3s: s("ja3s"),
                serial: s("01"),
                subject_country: s("KR"),
                subject_org_name: s("Org"),
                subject_common_name: s("example.com"),
                validity_not_before: 66,
                validity_not_after: 67,
                subject_alt_name: s("www.example.com"),
                issuer_country: s("US"),
                issuer_org_name: s("CA"),
                issuer_org_unit_name: s("Unit"),
                issuer_common_name: s("CA Root"),
                last_alert: 40,
            }),
            RawEventBody::Smb(Smb {
                orig_addr: v4(31),
                orig_port: 50011,
                resp_addr: v4(32),
                resp_port: 445,
                proto: 6,
                start_time: 68,
                duration: 69,
                orig_pkts: 70,
                resp_pkts: 71,
                orig_l2_bytes: 72,
                resp_l2_bytes: 73,
                command: 5,
                path: s("\\\\host\\share"),
                service: s("A:"),
                file_name: s("doc.txt"),
                file_size: 74,
                resource_type: 75,
                fid: 76,
                create_time: 77,
                access_time: 78,
                write_time: 79,
                change_time: 80,
            }),
            RawEventBody::Nfs(Nfs {
                orig_addr: v4(33),
                orig_port: 50012,
                resp_addr: v4(34),
                resp_port: 2049,
                proto: 6,
                start_time: 81,
                duration: 82,
                orig_pkts: 83,
                resp_pkts: 84,
                orig_l2_bytes: 85,
                resp_l2_bytes: 86,
                read_files: strings("read"),
                write_files: strings("write"),
            }),
            RawEventBody::Bootp(Bootp {
                orig_addr: v4(35),
                orig_port: 68,
                resp_addr: v4(36),
                resp_port: 67,
                proto: 17,
                start_time: 87,
                duration: 88,
                orig_pkts: 89,
                resp_pkts: 90,
                orig_l2_bytes: 91,
                resp_l2_bytes: 92,
                op: 1,
                htype: 1,
                hops: 2,
                xid: 0xdead_beef,
                ciaddr: v4(37),
                yiaddr: v4(38),
                siaddr: v4(39),
                giaddr: v4(40),
                chaddr: vec![0, 1, 2, 3, 4, 5],
                sname: s("server"),
                file: s("boot.img"),
            }),
            RawEventBody::Dhcp(Dhcp {
                orig_addr: v4(41),
                orig_port: 68,
                resp_addr: v4(42),
                resp_port: 67,
                proto: 17,
                start_time: 93,
                duration: 94,
                orig_pkts: 95,
                resp_pkts: 96,
                orig_l2_bytes: 97,
                resp_l2_bytes: 98,
                msg_type: 5,
                ciaddr: v4(43),
                yiaddr: v4(44),
                siaddr: v4(45),
                giaddr: v4(46),
                subnet_mask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                router: vec![v4(47), v4(48)],
                domain_name_server: vec![v4(49), v6(50)],
                req_ip_addr: v4(51),
                lease_time: 86400,
                server_id: v4(52),
                param_req_list: vec![1, 3, 6],
                message: s("ok"),
                renewal_time: 43200,
                rebinding_time: 75600,
                class_id: vec![9, 8],
                client_id_type: 1,
                client_id: vec![7, 6, 5],
                options: vec![(53, vec![5]), (61, vec![1, 2, 3])],
            }),
            RawEventBody::Radius(Radius {
                orig_addr: v4(53),
                orig_port: 50013,
                resp_addr: v4(54),
                resp_port: 1812,
                proto: 17,
                start_time: 99,
                duration: 100,
                orig_pkts: 101,
                resp_pkts: 102,
                orig_l2_bytes: 103,
                resp_l2_bytes: 104,
                id: 105,
                code: 1,
                resp_code: 2,
                auth: s("auth"),
                resp_auth: s("resp-auth"),
                user_name: vec![b'u'],
                user_passwd: RADIUS_USER_PASSWD.to_vec(),
                chap_passwd: RADIUS_CHAP_PASSWD.to_vec(),
                nas_ip: v4(55),
                nas_port: 106,
                state: vec![1],
                nas_id: vec![2],
                nas_port_type: 15,
                message: s("accepted"),
            }),
            RawEventBody::MalformedDns(MalformedDns {
                orig_addr: v4(56),
                orig_port: 50014,
                resp_addr: v4(57),
                resp_port: 53,
                proto: 17,
                start_time: 107,
                duration: 108,
                orig_pkts: 109,
                resp_pkts: 110,
                orig_l2_bytes: 111,
                resp_l2_bytes: 112,
                trans_id: 113,
                flags: 0x8180,
                question_count: 1,
                answer_count: 2,
                authority_count: 3,
                additional_count: 4,
                query_count: 5,
                resp_count: 6,
                query_bytes: 114,
                resp_bytes: 115,
                query_body: vec![vec![1, 2], vec![3]],
                resp_body: vec![vec![4], vec![5, 6]],
            }),
            RawEventBody::Icmp(Icmp {
                orig_addr: v4(58),
                resp_addr: v6(59),
                proto: 1,
                start_time: 116,
                duration: 117,
                orig_pkts: 118,
                resp_pkts: 119,
                orig_l2_bytes: 120,
                resp_l2_bytes: 121,
                icmp_type: 8,
                icmp_code: 0,
                id: 122,
                seq_num: 123,
                data_len: 3,
                payload: vec![1, 2, 3],
            }),
            RawEventBody::ProcessCreate(ProcessCreate {
                agent_name: s("agent"),
                agent_id: s("agent-1"),
                process_guid: s("guid"),
                process_id: 1001,
                image: s("C:\\a.exe"),
                file_version: s("1.0"),
                description: s("desc"),
                product: s("product"),
                company: s("company"),
                original_file_name: s("a.exe"),
                command_line: s("a.exe -x"),
                current_directory: s("C:\\"),
                user: s("user"),
                logon_guid: s("logon-guid"),
                logon_id: 1002,
                terminal_session_id: 1,
                integrity_level: s("High"),
                hashes: strings("hash"),
                parent_process_guid: s("parent-guid"),
                parent_process_id: 1003,
                parent_image: s("C:\\parent.exe"),
                parent_command_line: s("parent.exe"),
                parent_user: s("parent-user"),
            }),
            RawEventBody::FileCreateTime(FileCreateTime {
                agent_name: s("agent"),
                agent_id: s("agent-2"),
                process_guid: s("guid"),
                process_id: 1004,
                image: s("C:\\b.exe"),
                target_filename: s("C:\\t.txt"),
                creation_utc_time: 124,
                previous_creation_utc_time: 125,
                user: s("user"),
            }),
            RawEventBody::NetworkConnect(NetworkConnect {
                agent_name: s("agent"),
                agent_id: s("agent-3"),
                process_guid: s("guid"),
                process_id: 1005,
                image: s("C:\\c.exe"),
                user: s("user"),
                protocol: s("tcp"),
                initiated: true,
                source_is_ipv6: false,
                source_ip: v4(60),
                source_hostname: s("src"),
                source_port: 50015,
                source_port_name: s("src-port"),
                destination_is_ipv6: true,
                destination_ip: v6(61),
                destination_hostname: s("dst"),
                destination_port: 443,
                destination_port_name: s("https"),
            }),
            RawEventBody::ProcessTerminate(ProcessTerminate {
                agent_name: s("agent"),
                agent_id: s("agent-4"),
                process_guid: s("guid"),
                process_id: 1006,
                image: s("C:\\d.exe"),
                user: s("user"),
            }),
            RawEventBody::ImageLoad(ImageLoad {
                agent_name: s("agent"),
                agent_id: s("agent-5"),
                process_guid: s("guid"),
                process_id: 1007,
                image: s("C:\\e.exe"),
                image_loaded: s("C:\\e.dll"),
                file_version: s("2.0"),
                description: s("desc"),
                product: s("product"),
                company: s("company"),
                original_file_name: s("e.dll"),
                hashes: strings("hash"),
                signed: true,
                signature: s("signer"),
                signature_status: s("Valid"),
                user: s("user"),
            }),
            RawEventBody::FileCreate(FileCreate {
                agent_name: s("agent"),
                agent_id: s("agent-6"),
                process_guid: s("guid"),
                process_id: 1008,
                image: s("C:\\f.exe"),
                target_filename: s("C:\\f.txt"),
                creation_utc_time: 126,
                user: s("user"),
            }),
            RawEventBody::RegistryValueSet(RegistryValueSet {
                agent_name: s("agent"),
                agent_id: s("agent-7"),
                event_type: s("SetValue"),
                process_guid: s("guid"),
                process_id: 1009,
                image: s("C:\\g.exe"),
                target_object: s("HKLM\\Key"),
                details: s("DWORD 1"),
                user: s("user"),
            }),
            RawEventBody::RegistryKeyRename(RegistryKeyRename {
                agent_name: s("agent"),
                agent_id: s("agent-8"),
                event_type: s("RenameKey"),
                process_guid: s("guid"),
                process_id: 1010,
                image: s("C:\\h.exe"),
                target_object: s("HKLM\\Old"),
                new_name: s("HKLM\\New"),
                user: s("user"),
            }),
            RawEventBody::FileCreateStreamHash(FileCreateStreamHash {
                agent_name: s("agent"),
                agent_id: s("agent-9"),
                process_guid: s("guid"),
                process_id: 1011,
                image: s("C:\\i.exe"),
                target_filename: s("C:\\i.txt:Zone.Identifier"),
                creation_utc_time: 127,
                hash: strings("hash"),
                contents: s("[ZoneTransfer]"),
                user: s("user"),
            }),
            RawEventBody::PipeEvent(PipeEvent {
                agent_name: s("agent"),
                agent_id: s("agent-10"),
                event_type: s("CreatePipe"),
                process_guid: s("guid"),
                process_id: 1012,
                pipe_name: s("\\pipe"),
                image: s("C:\\j.exe"),
                user: s("user"),
            }),
            RawEventBody::DnsQuery(DnsQuery {
                agent_name: s("agent"),
                agent_id: s("agent-11"),
                process_guid: s("guid"),
                process_id: 1013,
                query_name: s("example.com"),
                query_status: 9003,
                query_results: strings("result"),
                image: s("C:\\k.exe"),
                user: s("user"),
            }),
            RawEventBody::FileDelete(FileDelete {
                agent_name: s("agent"),
                agent_id: s("agent-12"),
                process_guid: s("guid"),
                process_id: 1014,
                user: s("user"),
                image: s("C:\\l.exe"),
                target_filename: s("C:\\l.txt"),
                hashes: strings("hash"),
                is_executable: true,
                archived: true,
            }),
            RawEventBody::ProcessTamper(ProcessTamper {
                agent_name: s("agent"),
                agent_id: s("agent-13"),
                process_guid: s("guid"),
                process_id: 1015,
                image: s("C:\\m.exe"),
                tamper_type: s("Image is replaced"),
                user: s("user"),
            }),
            RawEventBody::FileDeleteDetected(FileDeleteDetected {
                agent_name: s("agent"),
                agent_id: s("agent-14"),
                process_guid: s("guid"),
                process_id: 1016,
                user: s("user"),
                image: s("C:\\n.exe"),
                target_filename: s("C:\\n.txt"),
                hashes: strings("hash"),
                is_executable: true,
            }),
            RawEventBody::Netflow5(Netflow5 {
                src_addr: v4(62),
                dst_addr: v4(63),
                next_hop: v4(64),
                input: 1,
                output: 2,
                d_pkts: 3,
                d_octets: 4,
                first: 5,
                last: 6,
                src_port: 7,
                dst_port: 8,
                tcp_flags: 0x12,
                prot: 6,
                tos: 0x10,
                src_as: 9,
                dst_as: 10,
                src_mask: 24,
                dst_mask: 16,
                sequence: 11,
                engine_type: 1,
                engine_id: 2,
                sampling_mode: 1,
                sampling_rate: 100,
            }),
            RawEventBody::Netflow9(Netflow9 {
                sequence: 12,
                source_id: 13,
                template_id: 256,
                orig_addr: v4(65),
                orig_port: 50016,
                resp_addr: v6(66),
                resp_port: 53,
                proto: 17,
                contents: s("contents"),
            }),
        ]
    }

    #[test]
    fn debug_redacts_credentials() {
        let secrets = [
            format!("{HTTP_PASSWORD:?}"),
            format!("{HTTP_COOKIE:?}"),
            format!("{FTP_PASSWORD:?}"),
            format!("{LDAP_ARGUMENT:?}"),
            format!("{:?}", RADIUS_USER_PASSWD.to_vec()),
            format!("{:?}", RADIUS_CHAP_PASSWD.to_vec()),
        ];
        for body in bodies() {
            let rendered = format!("{body:?}");
            for secret in &secrets {
                assert!(!rendered.contains(secret.as_str()), "{rendered}");
            }
            let (has_credentials, kept) = match &body {
                RawEventBody::Http(_) => (true, r#"username: "user""#),
                RawEventBody::Ftp(_) => (true, r#"user: "anonymous""#),
                RawEventBody::Ldap(_) => (true, r#"object: ["cn=admin-1", "cn=admin-2"]"#),
                RawEventBody::Radius(_) => (true, "user_name: [117]"),
                _ => (false, ""),
            };
            assert_eq!(rendered.contains(REDACTED), has_credentials, "{rendered}");
            assert!(rendered.contains(kept), "{rendered}");
        }
    }
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod bincode_tests {
    use serde::{Serialize, de::DeserializeOwned};

    use super::super::{RawEventBody, RawEventKind};
    use super::tests::bodies;

    fn encode<T: Serialize>(value: &T) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("serialization should succeed")
    }

    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> T {
        let (value, len): (T, usize) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .expect("deserialization should succeed");
        assert_eq!(len, bytes.len());
        value
    }

    fn all_kinds() -> Vec<RawEventKind> {
        (0..=u32::from(u16::MAX))
            .filter_map(|n| RawEventKind::try_from(n).ok())
            .collect()
    }

    #[test]
    fn kind_serializes_as_number_in_bincode() {
        let kinds = all_kinds();
        assert_eq!(kinds.len(), 36);
        for kind in kinds {
            let bytes = encode(&kind);
            assert_eq!(bytes, encode(&u32::from(kind)), "{kind:?}");
            assert_eq!(decode::<RawEventKind>(&bytes), kind);
        }
        assert_eq!(
            encode(&RawEventKind::ProcessCreate),
            encode(&31_u32),
            "a kind must not encode as its declaration index"
        );
        assert!(
            bincode::serde::decode_from_slice::<RawEventKind, _>(
                &encode(&2_u32),
                bincode::config::standard(),
            )
            .is_err(),
            "2 is not a review-protocol kind"
        );
    }

    /// Returns the kind a body belongs to. The match has no wildcard, so a
    /// variant added to `RawEventBody` must be handled here.
    fn kind_of(body: &RawEventBody) -> RawEventKind {
        match body {
            RawEventBody::Conn(_) => RawEventKind::Conn,
            RawEventBody::Dns(_) => RawEventKind::Dns,
            RawEventBody::Http(_) => RawEventKind::Http,
            RawEventBody::Rdp(_) => RawEventKind::Rdp,
            RawEventBody::Smtp(_) => RawEventKind::Smtp,
            RawEventBody::Ntlm(_) => RawEventKind::Ntlm,
            RawEventBody::Kerberos(_) => RawEventKind::Kerberos,
            RawEventBody::Ssh(_) => RawEventKind::Ssh,
            RawEventBody::DceRpc(_) => RawEventKind::DceRpc,
            RawEventBody::Ftp(_) => RawEventKind::Ftp,
            RawEventBody::Mqtt(_) => RawEventKind::Mqtt,
            RawEventBody::Ldap(_) => RawEventKind::Ldap,
            RawEventBody::Tls(_) => RawEventKind::Tls,
            RawEventBody::Smb(_) => RawEventKind::Smb,
            RawEventBody::Nfs(_) => RawEventKind::Nfs,
            RawEventBody::Bootp(_) => RawEventKind::Bootp,
            RawEventBody::Dhcp(_) => RawEventKind::Dhcp,
            RawEventBody::Radius(_) => RawEventKind::Radius,
            RawEventBody::MalformedDns(_) => RawEventKind::MalformedDns,
            RawEventBody::Icmp(_) => RawEventKind::Icmp,
            RawEventBody::ProcessCreate(_) => RawEventKind::ProcessCreate,
            RawEventBody::FileCreateTime(_) => RawEventKind::FileCreateTime,
            RawEventBody::NetworkConnect(_) => RawEventKind::NetworkConnect,
            RawEventBody::ProcessTerminate(_) => RawEventKind::ProcessTerminate,
            RawEventBody::ImageLoad(_) => RawEventKind::ImageLoad,
            RawEventBody::FileCreate(_) => RawEventKind::FileCreate,
            RawEventBody::RegistryValueSet(_) => RawEventKind::RegistryValueSet,
            RawEventBody::RegistryKeyRename(_) => RawEventKind::RegistryKeyRename,
            RawEventBody::FileCreateStreamHash(_) => RawEventKind::FileCreateStreamHash,
            RawEventBody::PipeEvent(_) => RawEventKind::PipeEvent,
            RawEventBody::DnsQuery(_) => RawEventKind::DnsQuery,
            RawEventBody::FileDelete(_) => RawEventKind::FileDelete,
            RawEventBody::ProcessTamper(_) => RawEventKind::ProcessTamper,
            RawEventBody::FileDeleteDetected(_) => RawEventKind::FileDeleteDetected,
            RawEventBody::Netflow5(_) => RawEventKind::Netflow5,
            RawEventBody::Netflow9(_) => RawEventKind::Netflow9,
        }
    }

    #[test]
    fn every_body_round_trips_through_bincode() {
        let bodies = bodies();
        let mut covered: Vec<RawEventKind> = bodies.iter().map(kind_of).collect();
        covered.sort_unstable_by_key(|kind| u32::from(*kind));
        covered.dedup();
        assert_eq!(covered, all_kinds(), "one body per kind");
        assert_eq!(bodies.len(), covered.len());

        for body in bodies {
            let decoded: RawEventBody = decode(&encode(&body));
            assert_eq!(decoded, body);
        }
    }
}
