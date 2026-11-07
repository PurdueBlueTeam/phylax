//go:build windows

package agent

import (
	"runtime"
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

// ApplyJobLimits puts the current process in a new Job Object with a
// per-process memory limit and an optional CPU hard cap. A process already in
// a job whose limits cannot be nested returns the OS error; the caller logs it
// and continues. The job handle is deliberately never closed: closing the last
// handle to a job terminates its processes.
//
// shortcut: Windows behaviour is verified in the lab only (CI vets and builds
// for windows, it does not run Windows tests), upgrade when a Windows runner
// exists.
func ApplyJobLimits(l JobLimits) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
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
	return windows.AssignProcessToJobObject(job, windows.CurrentProcess())
}
