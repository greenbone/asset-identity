# Fuzzy C reference fixtures

`fuzzy_c_compat.jsonl` contains 78 independently captured expected outcomes:
14 named kernel cases and 64 generated cases (Python `random.Random(2002)`).
Expected values were produced by compiling and executing the unmodified sibling
`gvmd/src/manage_asset_keys.c`, calling `asset_keys_target_merge_decide`, and
capturing `candidate_score` bits for the selected candidate. The Go regression
test reads these data without compiling C or requiring GLib/cgo.

Reviewed source fingerprints:

- `manage_asset_keys.c`: `353ccca3d4fade09add6d7bcf4312099a57c19e650d4afe2f7f12f24e215638d`
- `manage_asset_keys.h`: `54d42f2fb741df93a3880f002061df34899ffb36b8a42cf2ee660043a4a05eb6`
- `manage_asset_keys_tests.c`: `85a787ec78833dec6c7e35425cb8817380aeee95a6ce266a52c047062315f23f`

The named cases correspond to source tests and documented kernel edges:
empty observation, no candidates, containing candidate, one/multiple subsets,
partial overlap, freshness, first-row ties, merge without observation intersection,
empty subsets, negative timestamps, weighted counts, duplicates within value sets,
and MAC-only versus IP/hostname-contained candidates. Go-compatible canonical
payloads replace any source-test placeholder strings with no supported syntax.

Each record includes canonical observation/candidate values, whole-second Unix
LastSeen, and C outputs. `SelectedIndex: -1` represents C's absent survivor (where
its raw selected index is otherwise the non-present zero sentinel).
`SelectedScoreBits` preserves the exact float32 bits; merge indices retain C order.
Tests separately derive the expected merge keys from these indices.

During Phase 2 verification, an additional temporary C/Go differential run covered
all 14 named plus 1,000 generated cases, with bit-exact selected scores. The
persistent regression set retains the first 64 generated cases to keep the data
small. The generation universe contains three canonical IPs, two hostnames, and
two MACs; generated observations and candidates independently include each value
with probability .5, with 0–5 candidate rows and LastSeen sampled from
`[-100, -1, 0, 10, 20, 20]`. Candidate keys are distinct. C's default accumulation
order is MAC, hostname, IP. Scope and caller-supplied eligibility are held equivalent;
separate Go tests exercise normalization, policy, scope, and caller-prepared views.

The internal kernel now fixes C float32 scoring, whole-second ranking, and
empty-subset behavior without a public compatibility profile. Applications own
input eligibility and independent merge safety. Nil fuzzy times compare as Unix
epoch zero; empty and duplicate keys are rejected before reconciliation. These
fixtures verify containment analysis, not merge authorization or arbitrary gvmd
input compatibility. The original C test suite was inspected; the standalone C
kernel, rather than the gvmd test runner, was executed for this comparison.
