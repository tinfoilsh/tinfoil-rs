# Offline CPU regression fixture

`turin-public.json` is an unmodified subset of the public Tinfoil Go fixture
`verify/internal/quote/sev/testdata/inf17.json` at commit
`4e83c0ce632f` (Apache-2.0). It contains a static report, VCEK certificate, and
captured SEV policy. No live requests were made to obtain this fixture.

Tests separately check its AMD chain, report signature, and complete CPU
policy, including negative mutations. The fixture lacks a current CRL and
freshness witnesses; it cannot establish fresh, complete V3 attestation.
The production API always requires current CRL collateral and does not
expose a clock or trust-root override. No customer node documents are embedded
in the SDK.

`turin-amd-crl.der` was downloaded on 2026-10-18 from AMD's public
<https://kdsintf.amd.com/vcek/v1/Turin/crl>. Its signed validity window is
2026-09-22T07:39:31Z through 2026-11-09T01:00:00Z. CRL unit tests use an
internal test clock within and outside that window; production appraisal
always uses the current clock. This collateral is product-wide AMD public
data and contains no customer node quote or chip identity.
