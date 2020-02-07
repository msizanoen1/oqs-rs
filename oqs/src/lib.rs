use std::ffi::{CStr, CString};

pub use failure::Error;
pub use liboqs_sys as ffi;

pub struct KeyEncap(*mut ffi::OQS_KEM);
pub struct Signature(*mut ffi::OQS_SIG);

impl Drop for KeyEncap {
    fn drop(&mut self) {
        unsafe {
            ffi::OQS_KEM_free(self.0);
        }
    }
}

impl Drop for Signature {
    fn drop(&mut self) {
        unsafe {
            ffi::OQS_SIG_free(self.0);
        }
    }
}

impl KeyEncap {
    pub fn new(name: &str) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|e| Error::from_boxed_compat(Box::new(e)))?;
        let raw = unsafe { ffi::OQS_KEM_new(cname.as_ptr()) };
        if raw.is_null() {
            failure::bail!("unknown key encapsulation mechanism: {}", name);
        }
        Ok(Self(raw))
    }

    pub fn length_public_key(&self) -> usize {
        unsafe { (*self.0).length_public_key as usize }
    }

    pub fn length_secret_key(&self) -> usize {
        unsafe { (*self.0).length_secret_key as usize }
    }

    pub fn length_ciphertext(&self) -> usize {
        unsafe { (*self.0).length_ciphertext as usize }
    }

    pub fn length_shared_secret(&self) -> usize {
        unsafe { (*self.0).length_shared_secret as usize }
    }

    /// Return public key and secret key.
    pub fn keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let mut public = vec![0; self.length_public_key()];
        let mut secret = vec![0; self.length_secret_key()];
        unsafe {
            if ffi::OQS_KEM_keypair(self.0, public.as_mut_ptr(), secret.as_mut_ptr())
                != ffi::OQS_STATUS_OQS_SUCCESS
            {
                panic!("internal error: keypair generation failed");
            }
        }
        (public, secret)
    }

    pub fn encaps(
        &self,
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
        public_key: &[u8],
    ) -> Result<(), Error> {
        if ciphertext.len() != self.length_ciphertext()
            || shared_secret.len() != self.length_shared_secret()
            || public_key.len() != self.length_public_key()
        {
            failure::bail!("invalid parameter length");
        }
        unsafe {
            if ffi::OQS_KEM_encaps(
                self.0,
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                public_key.as_ptr(),
            ) != ffi::OQS_STATUS_OQS_SUCCESS
            {
                failure::bail!("encapsulation failure");
            }
        }
        Ok(())
    }

    /// Return ciphertext and shared secret.
    pub fn encaps_to_vec(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut ciphertext = vec![0; self.length_ciphertext()];
        let mut shared_secret = vec![0; self.length_shared_secret()];
        self.encaps(&mut ciphertext, &mut shared_secret, public_key)?;
        Ok((ciphertext, shared_secret))
    }

    pub fn decaps(
        &self,
        shared_secret: &mut [u8],
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<(), Error> {
        if shared_secret.len() != self.length_shared_secret()
            || ciphertext.len() != self.length_ciphertext()
            || secret_key.len() != self.length_secret_key()
        {
            failure::bail!("invalid parameter length");
        }
        unsafe {
            if ffi::OQS_KEM_decaps(
                self.0,
                shared_secret.as_mut_ptr(),
                ciphertext.as_ptr(),
                secret_key.as_ptr(),
            ) != ffi::OQS_STATUS_OQS_SUCCESS
            {
                failure::bail!("decapsulation failure");
            }
        }
        Ok(())
    }

    pub fn decaps_to_vec(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut shared_secret = vec![0; self.length_shared_secret()];
        self.decaps(&mut shared_secret, &ciphertext, &secret_key)?;
        Ok(shared_secret)
    }

    pub fn method_name(&self) -> &str {
        unsafe { CStr::from_ptr((*self.0).method_name).to_str().unwrap() }
    }

    pub fn alg_version(&self) -> &str {
        unsafe { CStr::from_ptr((*self.0).alg_version).to_str().unwrap() }
    }
}

impl Signature {
    pub fn new(name: &str) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|e| Error::from_boxed_compat(Box::new(e)))?;
        let raw = unsafe { ffi::OQS_SIG_new(cname.as_ptr()) };
        if raw.is_null() {
            failure::bail!("unknown signature scheme: {}", name);
        }
        Ok(Self(raw))
    }
}
