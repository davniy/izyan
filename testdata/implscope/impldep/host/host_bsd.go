//go:build freebsd || openbsd

package host

// Read is the BSD host-identity implementation. The advisory
// attributes the vulnerable implementation to the BSD/Solaris
// platforms: its body calls the kern.hostid sysctl, which is what the
// proposal's marker pins. Under the recorded Linux build target this
// file is deterministically excluded.
func Read() string { return sysctlString("kern.hostid") }

func sysctlString(name string) string { return name }
