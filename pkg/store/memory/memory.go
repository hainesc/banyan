package memory
import (
	"github.com/hainesc/banyan/pkg/store"
)
type Memory struct {
}

func NewMemory() *Memory {
	return &Memory{}
}
// Memory implements the Store interface
var _ store.Store = &Memory{}
