package lifecycle

import (
	"os"
	"reflect"
)

// isNilLifecycleFileInfo also rejects a typed nil stored in an os.FileInfo
// interface. FileInfo values are normally returned by the operating system,
// but lower helpers accept the interface directly and must not dispatch a
// method on a malformed typed-nil implementation.
func isNilLifecycleFileInfo(info os.FileInfo) bool {
	if info == nil {
		return true
	}
	value := reflect.ValueOf(info)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
