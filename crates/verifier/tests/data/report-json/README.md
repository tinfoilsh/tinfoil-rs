# Golden files for the report's JSON form

Each file is one case of the JSON form that `VerificationReport::to_json`
and `serde::Serialize` write, the form that every Tinfoil SDK writes. The
files are copied unchanged from the Go SDK (tinfoil-go#346,
`verify/testdata/report-json`), so the descriptions name the Go tests that
wrote them; the cases are the same in every SDK.

- `description` says what the case shows.
- `vector`, when present, names a full-verification vector of the shared
  conformance suite, relative to its `vectors/` directory. The case's report
  is what verifying that vector gives, at the vector's verification time.
  `conformance/tests/report.rs` checks these cases when
  `TINFOIL_CONFORMANCE_VECTORS` is set.
- Without `vector`, the case is built from the same inputs as the Go test
  that its description names, and `src/report_json_tests.rs` checks it.
- `report` is the expected JSON form.

The report is compared with `report` as JSON values, not as bytes, and
without the step messages, which are each SDK's own text, and `metadata`,
which describes the run. Times are compared as instants.
