# Public Suffix List: deferred

`akdbx.link` gives each broker its own name, `<id>.akdbx.link`. Adding
`akdbx.link` to the private section of the [Public Suffix List][psl] (PSL)
would make browsers treat each broker name as a separate site (cookie and
storage isolation between different users' pages), and Let's Encrypt would
apply its "New Certificates per Registered Domain" limit to each broker name
instead of to the whole domain (its per-account limits stay the same).

The request is **deferred** (decided 2026-11-21). The PSL accepts private
entries only when:

- the domain registration has **more than 2 years** left on the day the
  request is opened, and the owner keeps more than 1 year left afterwards;
- the request does not exist solely to get around third-party rate limits (Let's
  Encrypt has its own rate limit request form, linked from its
  [rate limits page][le-form]);
- the project serves enough users (projects with fewer than thousands of
  users are usually declined).

Until then the relay protects the Let's Encrypt limit itself: new
registrations pause at the weekly certificate budget, and renewals continue
(see `PROTOCOL.md`, "Certificate budget").

## When the relay has real users

1. Extend the `akdbx.link` registration at the registrar so that more than
   2 years remain, and keep auto-renew on.
2. Prepare the PSL change, following the PSL [guidelines][psl-guidelines]:
   - in `public_suffix_list.dat`, inside `===BEGIN PRIVATE DOMAINS===`, a
     block sorted alphabetically by the organization name in its header,
     never at the end of the file:

     ```
     // akdbx : https://github.com/7bgsbm749g-boop/akdbx
     // Submitted by <maintainer> <<maintainer email>>
     akdbx.link
     ```
   - the PR description: why the entry is needed (separating different
     users' broker pages), example names (`<id>.akdbx.link`, random and
     assigned by the relay, one per registered broker), the number of
     brokers and users, the statement that more than 2 years of
     registration remain, and the commitment to keep the registration in
     good standing with more than one year left at all times.
3. Open the PR in `publicsuffix/list`, then add a DNS TXT record
   `_psl.akdbx.link` (DNS only) whose value is the PR's URL. Keep the record
   after the PR is merged.
4. Watch the PR and answer maintainer questions. After it is merged and a
   browser release picks it up, update this file.

Meanwhile, if the weekly certificate budget becomes a real limit, use the
Let's Encrypt rate limit request form ([rate limits page][le-form]) for `akdbx.link`.

[psl]: https://publicsuffix.org/
[psl-guidelines]: https://github.com/publicsuffix/list/wiki/Guidelines
[le-form]: https://letsencrypt.org/docs/rate-limits/
