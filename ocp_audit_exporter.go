package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/audit-exporter/collector"
)

var (
	exporterName = "openshift_audit_exporter"
	metricPath   = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9119")

	timeoutOffset = kingpin.Flag(
		"timeout-offset",
		"Offset to subtract from timeout in seconds.",
	).Default("0.25").Float64()
)

// scrapers lists all possible collection methods and if they should be enabled by default.
var scrapers = map[collector.Scraper]bool{
	collector.ScrapeLogginAttempts{}: true,
}

func filterScrapers(scrapers []collector.Scraper, collectParams []string) []collector.Scraper {
	filteredScrapers := scrapers

	// Check if we have some "collect[]" query parameters.
	if len(collectParams) > 0 {
		filters := make(map[string]bool)
		for _, param := range collectParams {
			filters[param] = true
		}

		for _, scraper := range scrapers {
			if filters[scraper.Name()] {
				filteredScrapers = append(filteredScrapers, scraper)
			}
		}
	}
	return filteredScrapers
}

func init() {
	prometheus.MustRegister(version.NewCollector("openshift_audit_exporter"))
}

func newHandler(metrics collector.Metrics, scrapers []collector.Scraper, logger log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var dsn string

		collect := r.URL.Query()["collect[]"]

		// Use request context for cancellation when connection gets closed.
		ctx := r.Context()
		// If a timeout is configured via the Prometheus header, add it to the context.
		if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
			timeoutSeconds, err := strconv.ParseFloat(v, 64)
			if err != nil {
				level.Error(logger).Log("msg", "Failed to parse timeout from Prometheus header", "err", err)
			} else {
				if *timeoutOffset >= timeoutSeconds {
					// Ignore timeout offset if it doesn't leave time to scrape.
					level.Error(logger).Log("msg", "Timeout offset should be lower than prometheus scrape timeout", "offset", *timeoutOffset, "prometheus_scrape_timeout", timeoutSeconds)
				} else {
					// Subtract timeout offset from timeout.
					timeoutSeconds -= *timeoutOffset
				}
				// Create new timeout context with request context as parent.
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds*float64(time.Second)))
				defer cancel()
				// Overwrite request with timeout context.
				r = r.WithContext(ctx)
			}
		}

		filteredScrapers := filterScrapers(scrapers, collect)

		registry := prometheus.NewRegistry()

		registry.MustRegister(collector.New(ctx, dsn, metrics, filteredScrapers, logger))

		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

func main() {
	// Generate ON/OFF flags for all scrapers.
	scraperFlags := map[collector.Scraper]*bool{}
	for scraper, enabledByDefault := range scrapers {
		defaultOn := "false"
		if enabledByDefault {
			defaultOn = "true"
		}

		f := kingpin.Flag(
			"collect."+scraper.Name(),
			scraper.Help(),
		).Default(defaultOn).Bool()

		scraperFlags[scraper] = f
	}

	// Parse flags.
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print(exporterName))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	// landingPage contains the HTML served at '/'.
	// TODO: Make this nicer and more informative.
	var landingPage = []byte(`<html>
<head><title>Openshift (OCP) audit exporter</title></head>
<body>
<h1>Openshift Audit Exporter</h1>
<p><a href='` + *metricPath + `'>Metrics</a></p>
</body>
</html>
`)

	level.Info(logger).Log("msg", fmt.Sprintf("Starting %s", exporterName), "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	// Register only scrapers enabled by flag.
	enabledScrapers := []collector.Scraper{}
	for scraper, enabled := range scraperFlags {
		if *enabled {
			level.Info(logger).Log("msg", "Scraper enabled", "scraper", scraper.Name())
			enabledScrapers = append(enabledScrapers, scraper)
		}
	}
	handlerFunc := newHandler(collector.NewMetrics(), enabledScrapers, logger)
	http.Handle(*metricPath, promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, handlerFunc))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(landingPage)
	})

	srv := &http.Server{}
	if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
