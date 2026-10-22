// Package sandbox runs the decoy listeners in a separate, unprivileged child
// process (design: Deception, "Decoy services").
//
// The decoys parse hostile input all day. They are record-only and cannot run
// anything (internal/decoys has a source-level test for that), but defence in
// depth says a memory-safety or protocol-library bug in them must not land in
// a root process that also holds the agent's keys. So the agent (privileged,
// able to bind low ports) binds every listening socket, then starts a copy of
// its own binary with the sockets as inherited file descriptors. On Linux the
// child is started with the credentials of a nobody-like user (setuid, setgid,
// supplementary groups cleared) and sets no_new_privs as its first act; it
// never needs a privilege because the privileged operation, the bind, already
// happened in the parent. The child's events travel back to the parent as JSON
// lines on its stdout; its configuration (including the honeytoken registry)
// arrives on its stdin, never in argv or the environment. The stdin pipe stays
// open: when the parent dies the pipe closes and the child exits.
//
// On Windows the module runs the listeners in the agent process: see
// docs/deception.md for the restricted-token plan and why it is not done yet.
package sandbox
