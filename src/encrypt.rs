use aes::cipher::{
    block_padding::Pkcs7, 
    BlockEncryptMut, 
    KeyInit
};
use base64::Engine;
use serde::Serialize;

use md5::{
    Md5, 
    Digest
};
use base64::prelude::*;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;

pub fn encrypt_data<S: Serialize>(data: S, token: &str) -> String {
    let mut hasher = Md5::new();
     
    hasher.update(token.as_bytes());

    let key = &base16ct::lower::encode_string(&hasher.finalize())[0..16];
    
    let enc_data = Aes128EcbEnc::new(key.as_bytes().into())
        .encrypt_padded_vec_mut::<Pkcs7>(serde_json::to_string(&data).unwrap().as_bytes());

    BASE64_STANDARD.encode(enc_data).replace("+", "%2B")
}
