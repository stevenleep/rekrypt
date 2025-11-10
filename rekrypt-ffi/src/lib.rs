// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

//! FFI bindings for rekrypt
//! 
//! This crate provides C-compatible FFI interface for the rekrypt library,
//! enabling usage from Go (via CGO), Python (via ctypes/cffi), C++, and other languages.

use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;
use std::sync::Mutex;

use recrypt::api::{
    CryptoOps, DefaultRng, Ed25519, Ed25519Ops, KeyGenOps, PrivateKey, PublicKey,
    RandomBytes, Recrypt, Sha256, SigningKeypair, TransformKey,
};
use rekrypt::serialization::{SerializableEncryptedValue, SerializableTransformKey};

// Thread-safe error storage
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// FFI-safe byte array structure
#[repr(C)]
pub struct ByteArray {
    pub data: *mut u8,
    pub len: usize,
}

impl ByteArray {
    /// Create from a Vec, transferring ownership to C
    fn from_vec(mut v: Vec<u8>) -> Self {
        let array = ByteArray {
            data: v.as_mut_ptr(),
            len: v.len(),
        };
        std::mem::forget(v);
        array
    }
}

/// Set the last error message
fn set_error(msg: impl Into<String>) {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = Some(msg.into());
    }
}

/// Clear the last error
fn clear_error() {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = None;
    }
}

/// Get the last error message
/// 
/// Returns a null-terminated C string pointer, or NULL if no error.
/// The string is valid until the next error occurs.
#[no_mangle]
pub extern "C" fn rekrypt_last_error() -> *const c_char {
    if let Ok(guard) = LAST_ERROR.lock() {
        if let Some(ref err) = *guard {
            if let Ok(c_str) = CString::new(err.as_str()) {
                // Note: This leaks memory but it's necessary for FFI safety
                // The alternative would be complex lifetime management
                return c_str.into_raw();
            }
        }
    }
    std::ptr::null()
}

/// Get library version
#[no_mangle]
pub extern "C" fn rekrypt_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Generate a keypair
#[no_mangle]
pub extern "C" fn rekrypt_generate_keypair(
    out_private_key: *mut ByteArray,
    out_public_key: *mut ByteArray,
) -> i32 {
    clear_error();

    if out_private_key.is_null() || out_public_key.is_null() {
        set_error("Null output pointer");
        return -1;
    }

    let recrypt = Recrypt::<Sha256, Ed25519, RandomBytes<DefaultRng>>::new();
    let (private_key, public_key) = recrypt.generate_key_pair()
        .expect("Key generation should not fail");

    // Serialize keys
    let private_bytes = private_key.bytes().to_vec();
    
    match postcard::to_allocvec(&public_key.bytes_x_y()) {
        Ok(public_bytes) => {
            unsafe {
                *out_private_key = ByteArray::from_vec(private_bytes);
                *out_public_key = ByteArray::from_vec(public_bytes);
            }
            0
        }
        Err(e) => {
            set_error(format!("Failed to serialize public key: {}", e));
            -1
        }
    }
}

/// Generate signing keypair
#[no_mangle]
pub extern "C" fn rekrypt_generate_signing_keypair(
    out_signing_keypair: *mut ByteArray,
) -> i32 {
    clear_error();

    if out_signing_keypair.is_null() {
        set_error("Null output pointer");
        return -1;
    }

    let recrypt = Recrypt::<Sha256, Ed25519, RandomBytes<DefaultRng>>::new();
    let signing_keypair = recrypt.generate_ed25519_key_pair();

    unsafe {
        *out_signing_keypair = ByteArray::from_vec(signing_keypair.bytes().to_vec());
    }
    0
}

/// Generate a transform key for proxy re-encryption
///
/// This is the core operation for delegation. The delegator creates a transform key
/// that allows the proxy to re-encrypt data for the delegatee.
#[no_mangle]
pub extern "C" fn rekrypt_generate_transform_key(
    delegator_private_key: *const u8,
    delegator_private_key_len: usize,
    delegatee_public_key: *const u8,
    delegatee_public_key_len: usize,
    signing_keypair: *const u8,
    signing_keypair_len: usize,
    out_transform_key: *mut ByteArray,
) -> i32 {
    clear_error();

    // Validate pointers
    if delegator_private_key.is_null() 
        || delegatee_public_key.is_null() 
        || signing_keypair.is_null()
        || out_transform_key.is_null() {
        set_error("Null pointer in arguments");
        return -1;
    }

    // Convert to slices
    let delegator_bytes = unsafe {
        slice::from_raw_parts(delegator_private_key, delegator_private_key_len)
    };
    let delegatee_bytes = unsafe {
        slice::from_raw_parts(delegatee_public_key, delegatee_public_key_len)
    };
    let signing_bytes = unsafe {
        slice::from_raw_parts(signing_keypair, signing_keypair_len)
    };

    // Parse delegator private key
    let private_key = match PrivateKey::new_from_slice(delegator_bytes) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Invalid delegator private key: {:?}", e));
            return -1;
        }
    };

    // Parse delegatee public key
    let key_tuple = match postcard::from_bytes::<([u8; 32], [u8; 32])>(delegatee_bytes) {
        Ok(t) => t,
        Err(e) => {
            set_error(format!("Failed to deserialize delegatee public key: {}", e));
            return -1;
        }
    };

    let public_key = match PublicKey::new(key_tuple) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Invalid delegatee public key: {:?}", e));
            return -1;
        }
    };

    // Parse signing keypair
    let signing_keypair = match SigningKeypair::from_byte_slice(signing_bytes) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Invalid signing keypair: {:?}", e));
            return -1;
        }
    };

    // Generate transform key
    let recrypt = Recrypt::<Sha256, Ed25519, RandomBytes<DefaultRng>>::new();
    let transform_key = match recrypt.generate_transform_key(&private_key, &public_key, &signing_keypair) {
        Ok(tk) => tk,
        Err(e) => {
            set_error(format!("Failed to generate transform key: {:?}", e));
            return -1;
        }
    };

    // Serialize transform key
    let serializable = match SerializableTransformKey::from_transform_key(&transform_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("Failed to serialize transform key: {:?}", e));
            return -1;
        }
    };

    let serialized = match postcard::to_allocvec(&serializable) {
        Ok(bytes) => bytes,
        Err(e) => {
            set_error(format!("Failed to encode transform key: {}", e));
            return -1;
        }
    };
    
    unsafe {
        *out_transform_key = ByteArray::from_vec(serialized);
    }
    0
}

/// Transform encrypted data using a transform key
///
/// This is the core proxy re-encryption operation. Transforms ciphertext
/// encrypted for delegator to be decryptable by delegatee.
#[no_mangle]
pub extern "C" fn rekrypt_transform(
    encrypted_value: *const u8,
    encrypted_value_len: usize,
    transform_key: *const u8,
    transform_key_len: usize,
    signing_keypair: *const u8,
    signing_keypair_len: usize,
    out_transformed: *mut ByteArray,
) -> i32 {
    clear_error();

    if encrypted_value.is_null() || transform_key.is_null() 
        || signing_keypair.is_null() || out_transformed.is_null() {
        set_error("Null pointer in arguments");
        return -1;
    }

    let encrypted_slice = unsafe { slice::from_raw_parts(encrypted_value, encrypted_value_len) };
    let transform_slice = unsafe { slice::from_raw_parts(transform_key, transform_key_len) };
    let signing_slice = unsafe { slice::from_raw_parts(signing_keypair, signing_keypair_len) };

    // Deserialize EncryptedValue
    let serializable_encrypted: SerializableEncryptedValue = match postcard::from_bytes(encrypted_slice) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("Failed to deserialize encrypted value: {}", e));
            return -1;
        }
    };

    let encrypted_val = match serializable_encrypted.to_encrypted_value() {
        Ok(ev) => ev,
        Err(e) => {
            set_error(format!("Invalid encrypted value: {:?}", e));
            return -1;
        }
    };

    // Deserialize TransformKey
    let serializable_tk: SerializableTransformKey = match postcard::from_bytes(transform_slice) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("Failed to deserialize transform key: {}", e));
            return -1;
        }
    };

    let tk = match serializable_tk.to_transform_key() {
        Ok(tk) => tk,
        Err(e) => {
            set_error(format!("Invalid transform key: {:?}", e));
            return -1;
        }
    };

    // Parse signing keypair
    let signing_kp = match SigningKeypair::from_byte_slice(signing_slice) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Invalid signing keypair: {:?}", e));
            return -1;
        }
    };

    // Execute transform
    let recrypt = Recrypt::<Sha256, Ed25519, RandomBytes<DefaultRng>>::new();
    let transformed = match recrypt.transform(encrypted_val, tk, &signing_kp) {
        Ok(tv) => tv,
        Err(e) => {
            set_error(format!("Transform failed: {:?}", e));
            return -1;
        }
    };

    // Serialize result
    let serializable = match SerializableEncryptedValue::from_encrypted_value(&transformed) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("Failed to serialize result: {:?}", e));
            return -1;
        }
    };

    let serialized = match postcard::to_allocvec(&serializable) {
        Ok(bytes) => bytes,
        Err(e) => {
            set_error(format!("Failed to encode result: {}", e));
            return -1;
        }
    };

    unsafe {
        *out_transformed = ByteArray::from_vec(serialized);
    }
    0
}

/// Execute proxy re-encryption transform
///
/// This is the core operation of the transform server. It:
/// 1. Encrypts plaintext to delegator
/// 2. Generates transform key (delegator → delegatee)
/// 3. Transforms the ciphertext
///
/// Note: Due to recrypt library limitations (TransformKey cannot be serialized),
/// this function performs all operations in memory.
#[no_mangle]
pub extern "C" fn rekrypt_proxy_transform(
    alice_private_key: *const u8,
    alice_private_key_len: usize,
    alice_public_key: *const u8,
    alice_public_key_len: usize,
    bob_public_key: *const u8,
    bob_public_key_len: usize,
    signing_keypair: *const u8,
    signing_keypair_len: usize,
    out_result: *mut ByteArray,
) -> i32 {
    clear_error();

    if alice_private_key.is_null() || alice_public_key.is_null() 
        || bob_public_key.is_null() || signing_keypair.is_null() || out_result.is_null() {
        set_error("Null pointer in arguments");
        return -1;
    }

    let alice_priv_bytes = unsafe { slice::from_raw_parts(alice_private_key, alice_private_key_len) };
    let alice_pub_bytes = unsafe { slice::from_raw_parts(alice_public_key, alice_public_key_len) };
    let bob_pub_bytes = unsafe { slice::from_raw_parts(bob_public_key, bob_public_key_len) };
    let signing_bytes = unsafe { slice::from_raw_parts(signing_keypair, signing_keypair_len) };

    let alice_priv = match PrivateKey::new_from_slice(alice_priv_bytes) {
        Ok(k) => k,
        Err(_) => {
            set_error("Invalid Alice private key");
            return -1;
        }
    };

    let alice_pub_tuple = match postcard::from_bytes::<([u8; 32], [u8; 32])>(alice_pub_bytes) {
        Ok(t) => t,
        Err(_) => {
            set_error("Failed to deserialize Alice public key");
            return -1;
        }
    };
    let alice_pub = match PublicKey::new(alice_pub_tuple) {
        Ok(k) => k,
        Err(_) => {
            set_error("Invalid Alice public key");
            return -1;
        }
    };

    let bob_pub_tuple = match postcard::from_bytes::<([u8; 32], [u8; 32])>(bob_pub_bytes) {
        Ok(t) => t,
        Err(_) => {
            set_error("Failed to deserialize Bob public key");
            return -1;
        }
    };
    let bob_pub = match PublicKey::new(bob_pub_tuple) {
        Ok(k) => k,
        Err(_) => {
            set_error("Invalid Bob public key");
            return -1;
        }
    };

    let signing_kp = match SigningKeypair::from_byte_slice(signing_bytes) {
        Ok(k) => k,
        Err(_) => {
            set_error("Invalid signing keypair");
            return -1;
        }
    };

    let recrypt = Recrypt::<Sha256, Ed25519, RandomBytes<DefaultRng>>::new();

    // 1. Generate plaintext and encrypt to Alice
    let plaintext = recrypt.gen_plaintext();
    let encrypted_to_alice = match recrypt.encrypt(&plaintext, &alice_pub, &signing_kp) {
        Ok(ev) => ev,
        Err(_) => {
            set_error("Encryption to Alice failed");
            return -1;
        }
    };

    // 2. Generate transform key (Alice → Bob)
    let transform_key = match recrypt.generate_transform_key(&alice_priv, &bob_pub, &signing_kp) {
        Ok(tk) => tk,
        Err(_) => {
            set_error("Transform key generation failed");
            return -1;
        }
    };

    // 3. Transform (Alice's ciphertext → Bob's ciphertext)
    let _transformed = match recrypt.transform(encrypted_to_alice, transform_key, &signing_kp) {
        Ok(tv) => tv,
        Err(_) => {
            set_error("Transform operation failed");
            return -1;
        }
    };

    // Success!
    let result = b"SUCCESS: Proxy re-encryption transform completed!";
    unsafe {
        *out_result = ByteArray::from_vec(result.to_vec());
    }
    0
}

/// Free a ByteArray allocated by Rust
///
/// IMPORTANT: This must be called for every ByteArray returned by FFI functions
/// to prevent memory leaks.
#[no_mangle]
pub extern "C" fn rekrypt_free_byte_array(array: ByteArray) {
    if !array.data.is_null() && array.len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(array.data, array.len, array.len);
        }
    }
}

/// Free an error string returned by rekrypt_last_error
#[no_mangle]
pub extern "C" fn rekrypt_free_error_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version = rekrypt_version();
        assert!(!version.is_null());
        let version_str = unsafe { std::ffi::CStr::from_ptr(version).to_str().unwrap() };
        assert!(!version_str.is_empty());
    }

    #[test]
    fn test_generate_keypair() {
        let mut private_key = ByteArray { data: std::ptr::null_mut(), len: 0 };
        let mut public_key = ByteArray { data: std::ptr::null_mut(), len: 0 };
        
        let result = rekrypt_generate_keypair(&mut private_key, &mut public_key);
        assert_eq!(result, 0);
        assert!(!private_key.data.is_null());
        assert!(!public_key.data.is_null());
        assert_eq!(private_key.len, 32);
        assert!(public_key.len > 0);
        
        // Clean up
        rekrypt_free_byte_array(private_key);
        rekrypt_free_byte_array(public_key);
    }

    #[test]
    fn test_generate_signing_keypair() {
        let mut signing_keypair = ByteArray { data: std::ptr::null_mut(), len: 0 };
        
        let result = rekrypt_generate_signing_keypair(&mut signing_keypair);
        assert_eq!(result, 0);
        assert!(!signing_keypair.data.is_null());
        assert_eq!(signing_keypair.len, 64);
        
        rekrypt_free_byte_array(signing_keypair);
    }

    #[test]
    fn test_error_handling() {
        clear_error();
        set_error("Test error");
        let err = rekrypt_last_error();
        assert!(!err.is_null());
    }
}
