//go:build darwin && cgo

package vault

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static const char *relayKeychainService = "AI Relay 2.0";

static int relay_keychain_probe(void) {
	SecKeychainRef keychain = NULL;
	OSStatus status = SecKeychainCopyDefault(&keychain);
	if (status == errSecSuccess && keychain == NULL) return errSecNoSuchKeychain;
	if (status == errSecSuccess) CFRelease(keychain);
	return (int)status;
}

static int relay_keychain_read(const char *account, unsigned char **out, unsigned int *out_len) {
	UInt32 length = 0;
	void *data = NULL;
	OSStatus status = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(relayKeychainService), relayKeychainService,
		(UInt32)strlen(account), account, &length, &data, NULL);
	if (status != errSecSuccess) return (int)status;
	if (length > 0 && data == NULL) return -3;
	if (length > 65536) { SecKeychainItemFreeContent(NULL, data); return -2; }
	*out = malloc(length == 0 ? 1 : length);
	if (*out == NULL) { SecKeychainItemFreeContent(NULL, data); return -1; }
	if (length > 0) memcpy(*out, data, length);
	*out_len = length;
	SecKeychainItemFreeContent(NULL, data);
	return 0;
}

static int relay_keychain_write(const char *account, const unsigned char *payload, unsigned int payload_len) {
	SecKeychainItemRef item = NULL;
	UInt32 old_len = 0;
	void *old_data = NULL;
	OSStatus status = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(relayKeychainService), relayKeychainService,
		(UInt32)strlen(account), account, &old_len, &old_data, &item);
	if (old_data != NULL) SecKeychainItemFreeContent(NULL, old_data);
	if (status == errSecItemNotFound) {
		status = SecKeychainAddGenericPassword(NULL, (UInt32)strlen(relayKeychainService), relayKeychainService,
			(UInt32)strlen(account), account, payload_len, payload, NULL);
	} else if (status == errSecSuccess) {
		if (item == NULL) return errSecNoSuchKeychain;
		SecKeychainAttribute attribute = { kSecAccountItemAttr, (UInt32)strlen(account), (void *)account };
		SecKeychainAttributeList attributes = { 1, &attribute };
		status = SecKeychainItemModifyAttributesAndData(item, &attributes, payload_len, payload);
		CFRelease(item);
	}
	return (int)status;
}

static int relay_keychain_delete(const char *account) {
	UInt32 old_len = 0;
	void *old_data = NULL;
	SecKeychainItemRef item = NULL;
	OSStatus status = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(relayKeychainService), relayKeychainService,
		(UInt32)strlen(account), account, &old_len, &old_data, &item);
	if (old_data != NULL) SecKeychainItemFreeContent(NULL, old_data);
	if (status == errSecItemNotFound) return (int)status;
	if (status != errSecSuccess) return (int)status;
	if (item == NULL) return errSecNoSuchKeychain;
	status = SecKeychainItemDelete(item);
	CFRelease(item);
	return (int)status;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

const errSecItemNotFound = -25300

type darwinKeychainAPI struct{}

func OpenKeychain() (*Keychain, error) {
	if err := classifyKeychainProbeStatus(int(C.relay_keychain_probe())); err != nil {
		return nil, err
	}
	return &Keychain{api: darwinKeychainAPI{}}, nil
}

func (darwinKeychainAPI) read(account string) ([]byte, error) {
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	var out *C.uchar
	var length C.uint
	status := C.relay_keychain_read(ca, &out, &length)
	if status == errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != 0 {
		if status == -2 {
			return nil, errors.New("macOS Keychain payload exceeds limit")
		}
		return nil, classifyKeychainAPIStatus("read", int(status))
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(length)), nil
}

func (darwinKeychainAPI) write(account string, payload []byte) error {
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	var data *C.uchar
	if len(payload) > 0 {
		data = (*C.uchar)(unsafe.Pointer(&payload[0]))
	}
	if status := C.relay_keychain_write(ca, data, C.uint(len(payload))); status != 0 {
		return classifyKeychainAPIStatus("write", int(status))
	}
	return nil
}

func (darwinKeychainAPI) delete(account string) error {
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	status := C.relay_keychain_delete(ca)
	if status == errSecItemNotFound {
		return ErrNotFound
	}
	if status != 0 {
		return classifyKeychainAPIStatus("delete", int(status))
	}
	return nil
}

var _ Store = (*Keychain)(nil)
