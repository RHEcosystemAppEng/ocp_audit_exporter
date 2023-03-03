package collector

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Exporter namespace.
	namespace = "openshift_audit"
)

var logRE = regexp.MustCompile(`.+\.(\d+)$`)

func newDesc(subsystem, name, help string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, name),
		help, nil, nil,
	)
}
