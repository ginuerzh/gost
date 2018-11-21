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

// PeriodReload reloads the config periodically according to the period of the reloader.
func PeriodReload(r Reloader, configFile string) error {
	var lastMod time.Time

	for {
		f, err := os.Open(configFile)
		if err != nil {
			return err
		}

		finfo, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		mt := finfo.ModTime()
		if !mt.Equal(lastMod) {
			log.Log("[reload]", configFile)
			r.Reload(f)
			lastMod = mt
		}
		f.Close()

		period := r.Period()
		if period <= 0 {
			log.Log("[reload] disabled:", configFile)
			return nil
		}
		if period < time.Second {
			period = time.Second
		}

		<-time.After(period)
	}
}
