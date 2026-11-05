# Hosting platforms and fixed response headers

Some response headers can only be set by whoever serves the page. On a platform that offers no way to set them, a finding about that header is true and cannot be closed in place, and a report that only says the first half sends the reader looking for a setting that does not exist.

The engine knows this for GitHub Pages (`response_headers_fixed` on the `github-pages` vendor). The finding stays, because the exposure is real, and the report adds that the platform cannot close it here and names a fix that can be done. It applies only to rules a response header alone can satisfy: `PM-SEC-01` (HSTS). CSP and Referrer-Policy have a `<meta>` equivalent that works anywhere, so they are never excused.

## When a platform qualifies

All three, each from a source that can be cited:

1. **The platform does not send the header itself.** Measured, not assumed.
2. **The platform gives the site owner no way to set it.** Stated by the vendor, with a link.
3. **The engine can recognise the platform**, from a response header or from the host name.

If the platform sends the header itself, there is no finding and no constraint to explain. If the owner can set it, the finding is fixable and stays an ordinary finding.

## Measurements

One request per platform on 2026-11-04, with `curl -sI`. The table shows whether the platform itself sent `Strict-Transport-Security` and with what value.

| Platform | Site measured | Sent by the platform |
|----------|---------------|----------------------|
| Netlify | docs.netlify.com | yes, `max-age=31536000; includeSubDomains; preload` |
| Vercel | vercel.com | yes, `max-age=31536000; includeSubDomains; preload` |
| Cloudflare | developers.cloudflare.com | yes, `max-age=15552000; preload` |
| Wix | www.wix.com | yes, `max-age=31536000` |
| WordPress.com | en.blog.wordpress.com | yes, `max-age=31536000` |
| Read the Docs | docs.readthedocs.io | yes, `max-age=31536000; includeSubDomains; preload` |
| Substack | on.substack.com | yes, `max-age=31536000; includeSubDomains; preload` |
| Blogger | blogger.googleblog.com | yes, `max-age=86400; includeSubDomains` |
| Codeberg Pages | codeberg.page | yes, `max-age=63072000; includeSubDomains; preload` |
| Squarespace | www.squarespace.com | yes, `max-age=15552000` |
| GitLab Pages | pages.gitlab.io | **no** |

**What this does and does not show.** These are sites the vendors run themselves or well-known sites on their platform, not a sample of customers. They show that the platform can send the header, not that every customer site gets it. A one-site measurement can rule a platform in; it cannot rule it out for all customers.

## Candidates not added

**GitLab Pages** is the only measured platform that sent no HSTS. It is not added, because two of the three conditions are not established:

- The header is absent on one site (`pages.gitlab.io`), which is a single measurement.
- The only statement that headers cannot be set per project is an undated issue ([gitlab-org/gitlab-pages#50](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/50): "it is not possible to specify custom headers per project"). The user documentation does not mention headers either way. Its current status needs confirming with GitLab or on a project that uses Pages.
- A vendor entry needs the transfer basis (Data Privacy Framework, SCC or neither) for GitLab Inc., and that was not verifiable from the sources reached on that day. It must not be guessed: the report states the basis to the reader.

There is also no reliable header signature: the responses carry no `server` header, so detection would have to rely on the `gitlab.io` host name.

## Adding a platform

1. Measure: request a site that is really hosted there, from a clean network, and record the headers and the date.
2. Cite the vendor's own statement that headers cannot be set, with a link.
3. Add the vendor to `knowledge/vendors.yml` with `response_headers_fixed: true`, a comment holding the measurement and the date, and the detection (host or header signature in `analyze/context.py`).
4. Add the matching text to both locale catalogues and a test in `tests/test_platform_constraints.py` that fails when the flag is removed.

Where a fact cannot be established, record it here as a candidate with what is missing, as above.
