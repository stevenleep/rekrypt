// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

package rekrypt

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rekrypt-ffi/lib -lrekrypt_ffi

#include <stdlib.h>

typedef struct {
    unsigned char* data;
    size_t len;
} ByteArray;

extern const char* rekrypt_version();
extern const char* rekrypt_last_error();
extern int rekrypt_transform(
    const unsigned char* encrypted_value, size_t encrypted_value_len,
    const unsigned char* transform_key, size_t transform_key_len,
    const unsigned char* signing_keypair, size_t signing_keypair_len,
    ByteArray* out_transformed
);
extern void rekrypt_free_byte_array(ByteArray array);
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

func Version() string {
	return C.GoString(C.rekrypt_version())
}

func LastError() string {
	if errPtr := C.rekrypt_last_error(); errPtr != nil {
		return C.GoString(errPtr)
	}
	return ""
}

func Transform(encryptedValue, transformKey, signingKeypair []byte) ([]byte, error) {
	if len(encryptedValue) == 0 || len(transformKey) == 0 || len(signingKeypair) == 0 {
		return nil, errors.New("empty input data")
	}

	var result C.ByteArray
	ret := C.rekrypt_transform(
		(*C.uchar)(unsafe.Pointer(&encryptedValue[0])), C.size_t(len(encryptedValue)),
		(*C.uchar)(unsafe.Pointer(&transformKey[0])), C.size_t(len(transformKey)),
		(*C.uchar)(unsafe.Pointer(&signingKeypair[0])), C.size_t(len(signingKeypair)),
		&result,
	)

	if ret != 0 {
		return nil, fmt.Errorf("transform failed: %s", LastError())
	}

	transformed := C.GoBytes(unsafe.Pointer(result.data), C.int(result.len))
	C.rekrypt_free_byte_array(result)
	return transformed, nil
}
