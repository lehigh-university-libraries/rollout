package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"

	"github.com/google/shlex"
)

func Rollout(w http.ResponseWriter, r *http.Request) {
	err := setCustomArgs(r)
	if err != nil {
		slog.Error("Error setting custom args", "err", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	rolloutLockFile := os.Getenv("ROLLOUT_LOCK_FILE")
	if rolloutLockFile != "" && LockExists(rolloutLockFile, true) {
		slog.Error("Lock file exists. Not rolling out")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	err = rollout()
	if err != nil {
		slog.Error("Error running", "err", err)
		http.Error(w, "Script execution failed", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Rollout complete")
}

func GetRolloutCmdArgs() []string {
	args := os.Getenv("ROLLOUT_ARGS")
	if args == "" {
		args = "/rollout.sh"
	}
	rolloutArgs, err := shlex.Split(args)
	if err != nil {
		slog.Error("Error parsing ROLLOUT_ARGS", "args", args, "err", err)
		os.Exit(1)
	}

	return rolloutArgs
}

func setCustomArgs(r *http.Request) error {
	if r.Method == "GET" {
		return nil
	}

	var payload RolloutPayload
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&payload)
	if err != nil {
		return err
	}

	err = setEnvFromStruct(&payload)
	if err != nil {
		return err
	}

	return nil
}

func setEnvFromStruct(data interface{}) error {
	regex, err := regexp.Compile(`^[a-zA-Z0-9._\-:\/@]+$`)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}

	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if envTag, ok := field.Tag.Lookup("env"); ok {
			// For now all fields are strings
			value := v.Field(i).String()
			if value == "" {
				continue
			}
			if !regex.MatchString(value) {
				return fmt.Errorf("invalid input for environment variable %s:%s", envTag, value)
			}
			if err := os.Setenv(envTag, value); err != nil {
				return fmt.Errorf("could not set environment variable %s: %v", envTag, err)
			}
		}
	}
	return nil
}

func LockExists(filePath string, createOnNotExists bool) bool {
	if filePath == "" {
		return false
	}

	_, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			if !createOnNotExists {
				return false
			}
			err := os.WriteFile(filePath, []byte("rollout"), 0644)
			if err != nil {
				slog.Error("Failed to create rollout lock file", "error", err)
			}
			return false
		}
		slog.Error("Error reading rollout lock file", "error", err)
		return false
	}

	return true
}

func rollout() error {
	name := os.Getenv("ROLLOUT_CMD")
	if name == "" {
		name = "/bin/bash"
	}
	cmd := exec.Command(name, GetRolloutCmdArgs()...)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		CleanupLock()
		return fmt.Errorf("command: %s had stdout:%s stderr:%s", cmd.String(), stdOut.String(), stdErr.String())
	}

	CleanupLock()

	return nil
}

func CleanupLock() {
	rolloutLockFile := os.Getenv("ROLLOUT_LOCK_FILE")
	if !LockExists(rolloutLockFile, false) {
		return
	}

	err := os.Remove(rolloutLockFile)
	if err != nil {
		slog.Error("failed to remove rollout lock file", "err", err)
	}
}
