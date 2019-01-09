package gost

import (
	"io"
	"os"
	"time"

	"github.com/go-log/log"
)

// Reloader is the interface for objects that support live reloading.
type Reloader interface {
	Reload(r io.Reader) error
	Period() time.Duration
}

// Stoppable is the interface that indicates a Reloader can be stopped.
type Stoppable interface {
	Stop()
	Stopped() bool
}

// PeriodReload reloads the config configFile periodically according to the period of the Reloader r.
func PeriodReload(r Reloader, configFile string) error {
	if r == nil || configFile == "" {
		return nil
	}

	var lastMod time.Time
	for {
		if r.Period() < 0 {
			log.Log("[reload] stopped:", configFile)
			return nil
		}

		f, err := os.Open(configFile)
		if err != nil {
			return err
		}

		mt := lastMod
		if finfo, err := f.Stat(); err == nil {
			mt = finfo.ModTime()
		}

		if !lastMod.IsZero() && !mt.Equal(lastMod) {
			log.Log("[reload]", configFile)
			if err := r.Reload(f); err != nil {
				log.Logf("[reload] %s: %s", configFile, err)
			}
		}
		f.Close()
		lastMod = mt

		period := r.Period()
		if period == 0 {
			log.Log("[reload] disabled:", configFile)
			return nil
		}
		if period < time.Second {
			period = time.Second
		}
		<-time.After(period)
	}
}
