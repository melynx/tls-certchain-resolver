use std::sync::Arc;
use std::net::TcpStream;

use nom::AsBytes;
use oid_registry::{OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_PKIX_AUTHORITY_INFO_ACCESS};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;

use clap::Parser;
use x509_parser::prelude::*;

use log::{info, debug};

use pem_rfc7468::LineEnding;

#[derive(Parser, Debug)]
struct Args {
    /// TLS Server Connection String
    conn_string: String,

    /// Save certificate chain to file
    #[clap(short, long)]
    save_chain_path: Option<String>,
}

fn process_conn_string(conn_string: &str) -> (String, String) {
    let parts: Vec<&str> = conn_string.split(":").collect();
    let hostname = parts[0];
    let port = parts[1];
    (hostname.to_string(), port.to_string())
}

fn get_issuer_cert_der(cert: &X509Certificate<'_>) -> Option<Vec<u8>> {
    // get the Authority Information Access extension
    if let Some(ext) = cert.extensions_map().unwrap().get(&OID_PKIX_AUTHORITY_INFO_ACCESS) {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            let issuer_certs: Vec<Vec<u8>> = aia.iter().filter_map(|accessdesc| {
                if accessdesc.access_method != OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS {
                    return None;
                }

                match accessdesc.access_location {
                    GeneralName::URI(uri) => {
                        debug!("Fetching issuer cert from {}", uri);
                        let issuer_cert_der = reqwest::blocking::get(uri).unwrap().bytes().unwrap();
                        debug!("Done!");
                        let issuer_cert = X509Certificate::from_der(&issuer_cert_der).unwrap().1;
                        // checks that cert is signed by issuer_cert
                        match cert.verify_signature(Some(&issuer_cert.public_key())) {
                            Ok(_) => {
                                Some(issuer_cert_der.as_bytes().to_vec())
                            },
                            Err(_) => {
                                None
                            }
                        }
                    },
                    _ => {
                        None
                    }
                }
            }).collect();

            // at this point there should only be 1 issuer cert (1 PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS)
            // just in case there are multiple, we'll just return the first one
            return Some(issuer_certs[0].clone());
        }
    }

    None
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    let (hostname, port) = process_conn_string(&args.conn_string);
    let servername: ServerName = hostname.clone().try_into().unwrap();


    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into()
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), servername).unwrap();
    let mut sock = TcpStream::connect(&args.conn_string).unwrap();

    conn.complete_io(&mut sock).unwrap();
    info!("Connected to {}:{}", hostname, port);

    let mut resolve_chain_der: Vec<Vec<u8>> = Vec::new();
    let peer_certs_der = conn.peer_certificates().unwrap();

    // convert the peer_certs from der bytes to x509
    let peer_certs: Vec<X509Certificate<'_>> = peer_certs_der.iter().map(|cert| {
        resolve_chain_der.push(cert.as_bytes().to_vec());
        X509Certificate::from_der(&cert.as_bytes()).unwrap().1
    }).collect();

    info!("Received {} peer certificates from {}", peer_certs.len(), args.conn_string);

    if peer_certs.len() > 1 {
        // verify the chain
        for cert_pair in peer_certs.windows(2) {
            info!("Verifying certificate chain: {} -> {}", cert_pair[0].tbs_certificate.subject(), cert_pair[1].tbs_certificate.subject());
            assert_eq!(cert_pair[0].tbs_certificate.issuer(), cert_pair[1].tbs_certificate.subject());
            assert_eq!(cert_pair[0].verify_signature(Some(&cert_pair[1].public_key())), Ok(()));
        }
    }

    // check if last cert is self-signed
    if peer_certs.last().unwrap().tbs_certificate.subject() != peer_certs.last().unwrap().tbs_certificate.issuer() {
        info!("Last certificate is not self-signed, resolving issuer for the last certificate...");
        loop {
            let (_, last_cert) = X509Certificate::from_der(resolve_chain_der.last().unwrap()).unwrap();
            let issuer_cert_der = get_issuer_cert_der(&last_cert).unwrap();
            let issuer_cert = X509Certificate::from_der(&issuer_cert_der).unwrap().1;
            info!("Certificate resolved: {} -> {}", last_cert.tbs_certificate.subject(), issuer_cert.tbs_certificate.subject());
            resolve_chain_der.push(issuer_cert_der.clone());
            if issuer_cert.subject() == issuer_cert.issuer() {
                break;
            }
        }
    }

    // info!("Peer Certificates:");
    let certchain_pem_vec: Vec<String> = resolve_chain_der.iter().map(|der| {
        pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, &der).unwrap()
    }).collect();
    let certchain_pem = certchain_pem_vec.join("\n");

    match &args.save_chain_path {
        Some(file_path) => {
            std::fs::write(file_path, certchain_pem).unwrap();
            info!("Certificate chain saved to {}", file_path);
        },
        None => {
            println!("{}", certchain_pem);
        }
    }
}