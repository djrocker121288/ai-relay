package arpl

import "crypto/rand"

func cryptoRand(p []byte) (int, error) { return rand.Read(p) }
