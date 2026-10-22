package plan

import (
	"crypto/rand"
	"io"
)

func randReader() io.Reader { return rand.Reader }
