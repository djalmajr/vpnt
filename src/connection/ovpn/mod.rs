//! OVPN: OpenVPN with a certificate whose private key stays in a PKCS#11
//! token. openvpn requests every TLS signature over the management channel
//! and the token produces it, so no pkcs11-helper sits in between.
pub mod management;
pub mod pkcs11;
mod private_dir;
pub mod session;
pub mod signing;

impl session::Signer for pkcs11::TokenKey {
    fn certificate(&mut self) -> Result<Vec<u8>, session::SignError> {
        pkcs11::TokenKey::certificate(self).map_err(sign_error)
    }

    fn sign(
        &mut self,
        padding: signing::Padding,
        data: &[u8],
    ) -> Result<Vec<u8>, session::SignError> {
        pkcs11::TokenKey::sign(self, padding, data).map_err(sign_error)
    }
}

fn sign_error(error: pkcs11::TokenError) -> session::SignError {
    match error {
        pkcs11::TokenError::Canceled => session::SignError::Canceled,
        pkcs11::TokenError::PinRequired => session::SignError::PinRequired,
        _ => session::SignError::Unavailable,
    }
}
