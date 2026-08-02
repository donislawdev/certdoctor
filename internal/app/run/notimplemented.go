package run

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// notImplemented is what every layer answers until it is written.
//
// The reason is the one the plan names, and the status is the only one that can
// honestly stand for "we have not looked": reporting a pass here would be the
// product's central promise broken on the first day, and reporting a failure
// would be an accusation against a machine nobody examined.
//
// The detail line exists because the reason alone would mislead. The declared
// description of a probe error reads "the probe itself failed to run", which is
// not what happened - nothing ran, because nothing is written.
const notImplementedDetail = "not implemented"

// NotImplemented returns a full set of layer functions, one per declared layer,
// each answering that it has not been written.
//
// This is what makes the skeleton honest rather than empty. There is no moment
// in this program's life at which it claims to have checked something it has
// not, and there is no layer missing from the report just because its code is
// missing from the tree.
//
// Each entry disappears the day its layer is written. The map is built from the
// registry rather than listed by hand, so a ninth layer cannot be added and
// silently left without a row.
func NotImplemented() Layers {
	layers := make(Layers, len(layer.All))
	for _, id := range layer.All {
		layers[id] = func(context.Context) Answer {
			return Answer{
				Status: status.Unknown,
				Reason: status.ReasonProbeError,
				Detail: notImplementedDetail,
			}
		}
	}
	return layers
}
