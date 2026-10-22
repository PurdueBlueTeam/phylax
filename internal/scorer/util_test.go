package scorer

import "fmt"

func sprint(v any) string { return fmt.Sprintf("%v %+v %#v", v, v, v) }
