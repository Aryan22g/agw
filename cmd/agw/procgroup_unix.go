//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup puts the workload in a process group of its own, so the
// kill switch reaches everything it spawned and not just its first process.
func ownProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killGroup SIGKILLs the workload's whole process group. SIGKILL rather than
// SIGTERM: this is the kill switch, and a workload that is being cut off is
// exactly the one that should not get to run a handler first.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
