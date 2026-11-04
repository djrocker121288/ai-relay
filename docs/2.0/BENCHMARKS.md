# Local model benchmark evidence

Date: 2026-10-14

The P3 harness uses only the loopback Ollama API, first verifies that a model is
already present in `/api/tags`, fixes context/output/seed, disables thinking for
the coding response, bounds time and output, and requests immediate unload.
It refuses remote endpoints and missing models rather than pulling them. Both
model stores were unchanged, and `ollama ps` was empty after the runs.

## Fixed workload

Prompt SHA-256: `58323835f07651f666971822ef681e079f637695645589b0e4d0e1c70de54037`

> Return only Go source for package palindrome implementing func
> IsPalindrome(s string) bool. Compare Unicode runes and ignore case. Include
> required imports. No markdown.

Common settings: context 4096, maximum output 256 tokens, temperature 0, seed
42, loopback-only HTTP, maximum captured output 32 KiB.

| Host/model | License | Runtime result | Wall time | Generation | Output assessment |
|---|---|---:|---:|---:|---|
| Server 3 `MichelRosselli/bonsai-27b:Q1_0` (4.4 GB) | Apache-2.0 | completed | 6.320 s | 38.68 tokens/s | Returned plain Go, but included an unused `strings` import and silently skipped non-letters. It requires compile/test feedback before use. |
| M1 Mac `qwen2.5-coder:14b` (9.0 GB) | Apache-2.0 | timed out | 90 s bound | no response | Not a practical fit for this 8 GB host. An earlier 300 s bounded probe also returned no bytes. Preserve it, but do not select it for the Standard profile. |
| M1 Mac `qwen2.5-coder:7b` (4.7 GB) | Apache-2.0 | completed | 19.459 s | 11.66 tokens/s | Produced plausible Unicode-aware Go but disobeyed the no-markdown instruction and also skipped punctuation. It requires normalization plus compile/test feedback. |

“Completed” means the runtime returned successfully; it is not a claim that the
generated code passed a quality gate. Neither completed output exactly met the
contract. The current safe selection is therefore capability-dependent and
confidence-gated: the 7B coder is the viable Mac fallback, while Server 3's
preserved Bonsai model is much faster but must remain behind deterministic
validation and escalation. The 14B coder should be reconsidered only on a host
with materially more memory.

## Resource and safety observations

- Server 3: 20 logical CPUs, 33.3 GB RAM, RTX 3060 12 GB VRAM. A preliminary
  CLI run inherited the model's 262,144-token default and created a 23 GB
  working set. The direct adapter was added before accepting evidence and fixed
  context at 4096. Final runs unloaded cleanly; NVIDIA returned to 7 MiB and 0%.
- Mac: 8 logical CPUs, 8 GB unified RAM, approximately 5.3 GiB available to
  Metal. The 14B runner reported a 9.0 GB working set split across CPU/GPU and
  exceeded both bounded probes. The 7B runner completed and unloaded.
- Server 3 still has only about 6 GB root free. No model was downloaded,
  replaced, or deleted. The existing model referred to as the Skynet model was
  not found by that name; unrelated Skynet files/services were not inspected or
  changed.
