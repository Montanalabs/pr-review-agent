#! VULNERABLE pr-review-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant commentPr

let raw = fetch<web>
privileged { commentPr(raw) }  # tainted -> tool: REJECTED
