package actions

import (
	"context"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo"
	"github.com/PurdueBlueTeam/phylax/internal/devices/vyos"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// DeviceDirectory hands the device actions the adapters and the manifest
// intents for the devices the controller manages. The controller builds the
// Env for a device target (Env.Host is the device name); the actions never
// dial anything themselves.
type DeviceDirectory interface {
	Palo(ctx context.Context, device string) (*palo.Adapter, error)
	VyOS(ctx context.Context, device string) (*vyos.Adapter, error)
	PaloIntent(ctx context.Context, device string) (*render.PaloIntent, error)
	VyOSIntent(ctx context.Context, device string) (*render.VyOSIntent, error)
	// ConsoleAck reports that the Network role confirmed console access to the
	// device, which lets a lockout-risk change run on a device with no dead-man.
	ConsoleAck(ctx context.Context, device string) bool
}

// compile-time check that the adapters satisfy the runner's interface.
var (
	_ devices.Adapter = (*palo.Adapter)(nil)
	_ devices.Adapter = (*vyos.Adapter)(nil)
)
