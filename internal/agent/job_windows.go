//go:build windows

package agent

import (
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Job Object CPU rate control, which x/sys does not export.
const (
	jobObjectCPURateControlEnable  = 0x1
	jobObjectCPURateControlHardCap = 0x4
)

// jobObjectCPURateControlInformation is JOBOBJECT_CPU_RATE_CONTROL_INFORMATION:
// the flags followed by the CpuRate/Weight union.
type jobObjectCPURateControlInformation struct {
	flags   uint32
	cpuRate uint32 // hundredths of a percent of the whole machine
}

var (
	jobMu     sync.Mutex
	jobHandle windows.Handle
)

// ApplyJobLimits puts the current process in a new Job Object with a
// per-process memory limit and an optional CPU hard cap. A process already in
// a job whose limits cannot be nested returns the OS error; the caller logs it
// and continues. A later call updates the existing Job Object's limits, so a
// signed config can raise the cap for the capture module's ring and hold. The
// job handle is deliberately never closed: closing the last handle to a job
// terminates its processes.
//
// shortcut: Windows behaviour is verified in the lab only (CI vets and builds
// for windows, it does not run Windows tests), upgrade when a Windows runner
// exists.
func ApplyJobLimits(l JobLimits) error {
	jobMu.Lock()
	defer jobMu.Unlock()
	if jobHandle != 0 {
		return setJobLimits(jobHandle, l)
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	if err := setJobLimits(job, l); err != nil {
		return err
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		return err
	}
	jobHandle = job
	return nil
}

func setJobLimits(job windows.Handle, l JobLimits) error {
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	// BREAKAWAY_OK lets the detached swap helper of agent.replace_binary and
	// agent.rename leave the job: a service stop must never take the helper
	// that restarts the agent down with it.
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	info.ProcessMemoryLimit = uintptr(l.MemoryBytes)
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	if l.CPUPercent > 0 {
		cpu := jobObjectCPURateControlInformation{
			flags:   jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
			cpuRate: uint32(l.CPUPercent) * 100 / uint32(runtime.NumCPU()),
		}
		if cpu.cpuRate == 0 {
			cpu.cpuRate = 1 // the API rejects 0 and this many cores has no share left
		}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
			return err
		}
	}
	return nil
}
