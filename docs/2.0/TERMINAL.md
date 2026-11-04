# P3 local terminal action contract

`internal/v2/terminal` is the bounded local action surface for 2.0. It is
isolated from 1.x consumers and accepts an executable plus argument vector;
there is no shell interpolation and no privilege or elevation path.

The trusted supervisor binds an executor to one repository root; requests
cannot choose or enlarge that boundary. The root and working directory are
resolved through filesystem symlinks, and the working directory must remain
inside the root. Unapproved `read` actions are limited to `pwd`, `true`,
`false`, and tightly parsed `cat`/`ls` invocations. Read paths must exist and
their resolved symlink targets must remain in the repository. Commands such as
`git`, `go`, `sed`, `printf`, and shells are not treated as intrinsically read
only. `write` and `execute` actions require an explicit approval flag. Loader,
PATH, Git, SSH, and model-runtime environment injection is rejected; only the
documented inert display/benchmark variables are accepted.

Every action has a bounded timeout (default two minutes, maximum ten minutes)
and per-stream output cap (default 256 KiB, maximum 1 MiB). Context cancellation
terminates the process group on Unix. Windows currently terminates the direct
child only; native Job Object containment remains part of the Windows release
gate and no child-tree guarantee is claimed yet. The result reports exit
status, cancellation, and truncation.

The package uses the repository's existing `agentcore` process helper rather
than adding an orchestration dependency. That helper is maintained in this
repository under the project license, has no additional transitive footprint,
and is replaceable behind the small runner call. No model, network, service,
or credential component is involved. Rollback is removal of this isolated v2
package and its documentation.

# Benchmark harness

`internal/v2/benchmark` runs an operator-supplied model command through the
same bounded action contract and emits JSON with model capability, status,
latency, bounded stdout/stderr, a prompt digest, output truncation, and resource
evidence. The `ai-relay-benchmark` command supplies a repeatable CLI without
embedding an Ollama dependency. It never pulls, deletes, or alters a model;
the operator selects an already-installed runtime/model after the documented
storage and hardware preflight. The loopback Ollama adapter additionally checks
`/api/tags` before generation, refuses remote origins and missing models, fixes
context/output/seed, records native token timings, and requests unload after a
run. Native evidence and selection guidance are in `docs/2.0/BENCHMARKS.md`.

When host probes are unavailable, resource evidence remains truthfully
`not collected; benchmark never changes model stores`. Native results and the
remaining Server 3 download-headroom gate are recorded separately rather than
being inferred from a cross-build or fixture.
