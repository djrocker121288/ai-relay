# 2.0 resource scheduler

The v2 scheduler is an in-process, dependency-free admission component. It is
not connected to the 1.x gateway or agent and does not terminate operating
system processes.

`SetProjectQuota` limits a project's aggregate CPU, memory, GPU, and VRAM
allocations. A zero limit means unlimited for that resource. `Acquire` keeps
the existing immediate API; `AcquireQueued` waits with a caller-supplied
context. Queued work rotates across projects, then selects the highest
priority request in that project with FIFO tie-breaking. A request that is too
large does not block other projects whose work fits.

`Pressure` is an observation only. `normal` means at least 25% of each
configured usable resource remains, `constrained` means less than 25% remains,
and `critical` means a configured resource is exhausted. `ReclamationPlan`
returns cooperative candidates only; a supervisor must checkpoint, stop, and
explicitly `Release` an owner. The scheduler never evicts unrelated work.

Full-demand mode still requires explicit authorization and only removes the
configured host reserve from admission accounting. All state is protected by
one mutex, and release/cancellation dispatches queued work atomically.
