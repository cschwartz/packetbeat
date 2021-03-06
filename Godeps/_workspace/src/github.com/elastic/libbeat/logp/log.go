// +build !windows

package logp

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
)

type Priority int

const (
	// From /usr/include/sys/syslog.h.
	// These are the same on Linux, BSD, and OS X.
	LOG_EMERG Priority = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

type Logger struct {
	toSyslog            bool
	toStderr            bool
	toFile              bool
	level               Priority
	selectors           map[string]bool
	debug_all_selectors bool

	logger  *log.Logger
	syslog  [LOG_DEBUG + 1]*log.Logger
	rotator *FileRotator
}

var _log Logger

func Debug(selector string, format string, v ...interface{}) {
	if _log.level >= LOG_DEBUG {
		if !_log.debug_all_selectors {
			selected := _log.selectors[selector]
			if !selected {
				return
			}
		}
		if _log.toSyslog {
			_log.syslog[LOG_INFO].Output(2, fmt.Sprintf(format, v...))
		}
		if _log.toStderr {
			_log.logger.Output(2, fmt.Sprintf("DBG  "+format, v...))
		}
		if _log.toFile {
			_log.rotator.WriteLine([]byte(fmt.Sprintf("DBG  "+format, v...)))
		}
	}
}

func IsDebug(selector string) bool {
	return _log.selectors[selector]
}

func msg(level Priority, prefix string, format string, v ...interface{}) {
	if _log.level >= level {
		if _log.toSyslog {
			_log.syslog[level].Output(2, fmt.Sprintf(format, v...))
		}
		if _log.toStderr {
			_log.logger.Output(2, fmt.Sprintf(prefix+format, v...))
		}
		if _log.toFile {
			_log.rotator.WriteLine([]byte(fmt.Sprintf(prefix+format, v...)))
		}
	}
}

func Info(format string, v ...interface{}) {
	msg(LOG_INFO, "INFO ", format, v)
}

func Warn(format string, v ...interface{}) {
	msg(LOG_WARNING, "WARN ", format, v)
}

func Err(format string, v ...interface{}) {
	msg(LOG_ERR, "ERR ", format, v)
}

func Critical(format string, v ...interface{}) {
	msg(LOG_CRIT, "CRIT ", format, v)
}

// WTF prints the message at CRIT level and panics immediately with the same
// message
func WTF(format string, v ...interface{}) {
	msg(LOG_CRIT, "CRIT ", format, v)
	panic(fmt.Sprintf(format, v...))
}

func Recover(msg string) {
	if r := recover(); r != nil {
		Err("%s. Recovering, but please report this: %s.", msg, r)
		Err("Stacktrace: %s", debug.Stack())
	}
}

// TODO: remove toSyslog and toStderr from the init function
func LogInit(level Priority, prefix string, toSyslog bool, toStderr bool, debugSelectors []string) {
	_log.toSyslog = toSyslog
	_log.toStderr = toStderr
	_log.level = level

	_log.selectors = make(map[string]bool)
	for _, selector := range debugSelectors {
		_log.selectors[selector] = true
		if selector == "*" {
			_log.debug_all_selectors = true
		}
	}

	if _log.toSyslog {
		for prio := LOG_EMERG; prio <= LOG_DEBUG; prio++ {
			_log.syslog[prio] = openSyslog(prio, prefix)
			if _log.syslog[prio] == nil {
				// syslog not available
				_log.toSyslog = false
				break
			}
		}
	}
	if _log.toStderr {
		_log.logger = log.New(os.Stdout, prefix, log.Lshortfile)
	}
}

func SetToStderr(toStderr bool, prefix string) {
	_log.toStderr = toStderr
	if _log.toStderr {
		_log.logger = log.New(os.Stdout, prefix, log.Lshortfile)
	}
}

func SetToSyslog(toSyslog bool, prefix string) {
	_log.toSyslog = toSyslog
	if _log.toSyslog {
		for prio := LOG_EMERG; prio <= LOG_DEBUG; prio++ {
			_log.syslog[prio] = openSyslog(prio, prefix)
		}
	}
}

func SetToFile(toFile bool, rotator *FileRotator) error {
	_log.toFile = toFile
	if _log.toFile {
		_log.rotator = rotator

		err := rotator.CreateDirectory()
		if err != nil {
			return err
		}
		err = rotator.CheckIfConfigSane()
		if err != nil {
			return err
		}
	}
	return nil
}
