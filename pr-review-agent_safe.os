#! PR-review agent — untrusted a pull request can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires commentPr — the pr-review agent sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant commentPr

type PrNote = Nit | Praise | QuestionN
type Decision = Comment(PrNote) | RequestChanges | ApprovePr

let raw = fetch<web>  # UNTRUSTED a pull request — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { commentPr(d) }  # act on the trusted decision only
