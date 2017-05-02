
extern crate secstr;
extern crate regex;
extern crate base64;

pub use self::secstr::SecStr;
pub use std::io::{self,Read,BufReader,BufRead};
pub use std::fmt::Debug;
use self::regex::{Regex,Match};
use std::fmt::format;
use self::base64::{decode,encode};

pub type IdentityCallback<A,B> = fn(A) -> B;

#[derive(Debug)]
pub enum Identity {
    X509V3 { val : X509V3Identity }
}

#[derive(Debug)]
pub struct X509V3Identity {
    pub certificate : Vec<u8>,
    pub private_key : Vec<u8>,
    pub private_key_password : IdentityCallback<X509V3Identity, Option<SecStr>>,
    pub trust_store : Vec<Vec<u8>>
}

#[derive(Debug)]
pub enum X509V3Object {
    Certificate { val : Vec<u8> },
    PrivateKey { val : Vec<u8> },
    EncryptedPrivateKey { val : Vec<u8> },
    CertificateChain { val : Vec<Vec<u8>> }
}

#[derive(Debug)]
pub enum Xl4Error {
    Io(io::Error),
    PemFormatError,
    PemObjectError,
    InternalError(Option<String>)
}

#[derive(Debug)]
#[derive(PartialEq)]
enum PemType {
    Certificate,
    RsaPrivateKey,
    PrivateKey
}

impl From<io::Error> for Xl4Error {
    fn from(err: io::Error) -> Xl4Error {
        Xl4Error::Io(err)
    }
}

impl From<regex::Error> for Xl4Error {
    fn from(err: regex::Error) -> Xl4Error {
        Xl4Error::InternalError(Option::Some(format!("{:?}", err)))
    }
}

impl From<base64::DecodeError> for Xl4Error {
    fn from(err: base64::DecodeError) -> Xl4Error {
        Xl4Error::InternalError(Option::Some(format!("{:?}", err)))
    }
}

lazy_static! {
    static ref begin : Regex = Regex::new("").unwrap();
    static ref end : Regex = Regex::new("").unwrap();
}

fn pem_type_for_obj(o : &X509V3Object) -> PemType {

    match o {
        &X509V3Object::Certificate{val:_} | &X509V3Object::CertificateChain{val:_} => PemType::Certificate,
        &X509V3Object::PrivateKey{val:_} => PemType::PrivateKey,
        &X509V3Object::EncryptedPrivateKey{val:_} => PemType::RsaPrivateKey
    }

}

fn get_pem_type(m : Option<Match>) -> Result<PemType, Xl4Error> {

    if m == None {
        return Result::Err(Xl4Error::PemFormatError);
    }

    Result::Ok(
        match m.unwrap().as_str() {
            "CERTIFICATE" => PemType::Certificate,
            "RSA PRIVATE KEY" => PemType::RsaPrivateKey,
            "PRIVATE KEY" => PemType::PrivateKey,
            _ => return Result::Err(Xl4Error::PemFormatError)
        })

}

pub fn load_pem<T: Read>(input : T) -> Result<X509V3Object, Xl4Error> {

    let mut rdr = BufReader::new(input);
    let mut line = String::new();
    // $TODO: really, there is no streaming base64 decoding library for Rust?
    let mut base64_buf = String::new();
    let mut what : Option<X509V3Object> = None;
    let mut processing = None;

    loop {
        let sz = rdr.read_line(&mut line)?;
        if sz == 0 { break; }

        if processing.is_none() {

            match begin.captures(&line) {
                Some(x) => {

                    let mut care = true;
                    let which = || -> Result<PemType, Xl4Error> { get_pem_type(x.get(1)) };

                    // if we have a what, and it's not a certificate or chain,
                    // then let's just ignore the remainder of the file (as oppose to
                    // blowing a fuse).
                    match what {
                        None => {
                            processing = match which()? {
                                PemType::Certificate => Some(X509V3Object::Certificate {val:Vec::new()}),
                                PemType::PrivateKey => Some(X509V3Object::PrivateKey {val:Vec::new()}),
                                PemType::RsaPrivateKey => Some(X509V3Object::EncryptedPrivateKey {val:Vec::new()})
                            }
                        },
                        Some(X509V3Object::Certificate{val:_}) | Some(X509V3Object::CertificateChain {val:_}) => {
                            if which()? == PemType::Certificate {
                                processing = Some(X509V3Object::Certificate {val: Vec::new()});
                            }
                        },
                        _ => care = false
                    }

                }
                _ => {}
            }

        } else {

            match end.captures(&line) {
                Some(x) => {

                    let x = get_pem_type(x.get(1))?;
                    // we began one thing, but ending another?

                    let cur = processing.unwrap();

                    if x != pem_type_for_obj(&cur) {
                        return Result::Err(Xl4Error::PemFormatError);
                    }

                    let bin = decode(base64_buf.as_bytes())?;

                    match cur {
                        X509V3Object::PrivateKey {val:_} => what = Some(X509V3Object::PrivateKey { val : bin }),
                        X509V3Object::EncryptedPrivateKey {val:_} => what = Some(X509V3Object::EncryptedPrivateKey {val:bin}),
                        X509V3Object::Certificate {val:_} => {
                            match what {
                                None => what = Some(X509V3Object::Certificate {val:bin}),
                                Some(X509V3Object::Certificate {val:old}) => what = Some(X509V3Object::CertificateChain {val:vec![old,bin]}),
                                Some(X509V3Object::CertificateChain {val:mut cur}) => { cur.push(bin); what = Some(X509V3Object::CertificateChain{val:cur}); },
                                _ => return Result::Err(Xl4Error::InternalError(Option::Some(String::from("Can't be adding a certificate to a non-certificate object!"))))
                            }
                        },
                        _=>return Result::Err(Xl4Error::InternalError(Option::Some(String::from("Can't be processing anything else"))))
                    }

                    // give value back to processing. How else can we do that?
                    processing = Some(cur);

                }
                _ => {}
            }

        }

        line.clear();
    }

    match what {

        None => Result::Err(Xl4Error::PemFormatError),
        Some(t) => Result::Ok(t)

    }

}

