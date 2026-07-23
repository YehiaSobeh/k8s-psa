# Conference Targets — Deadlines in August 2026

**Compiled:** July 20, 2026 · **Paper:** "Bridging the Enforcement Verification Gap" (k8s-psa) · **Branch:** `paper-publication`

> **Headline: you did NOT miss CloudCom.** The CloudCom 2026 deadline was **extended from July 15 to August 15, 2026** (verified on the live EasyChair CFP — abstract and paper share the same date). The ready 4-page PDF at `submissions/cloudcom2026-short/main.pdf` is back in play.

---

## Part 1 — Conferences from the IEEE conference database (conferences.ieee.org)

The IEEE conference search page (`conferences.ieee.org/conferences_events/conferences`) is a JavaScript app, so it was queried through its official backend API (`conference-api.ieee.org`). A sweep of the database for conferences with call-for-papers deadlines in August 2026 (search terms: cloud computing, security, kubernetes, container, software engineering, distributed systems, dependable, network management, trust) returned:

| CFP deadline (per IEEE DB) | Conference | Event date / location | URL | Assessment |
|---|---|---|---|---|
| Aug 8 | **IEEE PRDC 2026** — 31st Pacific Rim Int'l Symposium on Dependable Computing | Nov 18, Hong Kong | [prdc.dependability.org/PRDC2026](https://prdc.dependability.org/PRDC2026/index.html) | **Worth targeting** — CORE B, reputable dependability venue; the enforcement-gap finding fits its scope |
| Aug 31 (official CFP says **Aug 19** — trust the official site) | **IEEE/ACM UCC 2026** — 19th Int'l Conference on Utility and Cloud Computing | Dec 1–4, Florianópolis, Brazil | [ucc2026.ufsc.br/calls/call-for-papers](https://ucc2026.ufsc.br/calls/call-for-papers/) | **Strong target** — accepts 4-page short papers; "Security, Trust, Privacy" is a listed topic |
| Aug 1 | IEEE EdgeCom 2026 (Shanghai, Dec 19) | [cloud-conf.net/cscloud/2026/ssc](https://www.cloud-conf.net/cscloud/2026/ssc/index.html) | | Weak venue — skip |
| Aug 9 | ISPDS 2026 (Shanghai) | [ispds.org](https://www.ispds.org/) | | **Avoid** — low-tier / pay-to-publish style |
| Aug 17 | PCDS 2026 (Singapore) | [pcds.cc](https://pcds.cc/) | | **Avoid** — low-tier |
| Aug 29 | ICCSIS 2026 (Hangzhou) | [iccsis.org](https://www.iccsis.org/) | | **Avoid** — low-tier |
| Aug 30 | AIBDCC 2026 (Chengdu) | [aibdcc.net](https://www.aibdcc.net/) | | **Avoid** — low-tier |

**Registry confirmations** (venues from Part 2 that are also in the official IEEE database):

- CloudCom 2026 — event ID 71355, Paris, Oct 27–29
- IEEE/ACM UCC 2026 — event ID 71512, Florianópolis, Dec 1–4
- IEEE TPS-ISA 2026 — event ID 71711, San Jose, Nov 4–6

**Caveat on the IEEE database:** its `callForPapers` field is stale. For CloudCom it still shows June 29, while the live EasyChair submission system (organizer-maintained) shows the extended August 15 deadline. Deadlines must always be verified against each venue's official CFP page — which is what Part 2 does.

---

## Part 2 — Full list: high-rank conferences with deadlines in mid/late August 2026

Sources: each venue's official CFP page + [sec-deadlines.github.io](https://sec-deadlines.github.io/). Ordered by deadline; "fit" is an honest assessment for the paper as it stands (4–6 pages, single-node evaluation, two-runtime validation).

| Deadline | Conference | Rank / venue tier | Fit | URL |
|---|---|---|---|---|
| **Aug 15** | **IEEE CloudCom 2026** (Paris, Oct 27–29) | CORE C, established IEEE series | ★★★ Paper is already formatted; submit here | [easychair.org/cfp/cloudcom2026](https://easychair.org/cfp/cloudcom2026) |
| **Aug 15** | **IEEE TPS 2026** — Trust, Privacy & Security in Intelligent Systems (San Jose, Nov 4–6), Round 2 | IEEE CS co-located venue (with CIC/CogMI) | ★★☆ Strong topical fit; needs reformat, likely 8–10 pp full or short-paper track | [tps.ieee-cs.org/2026/call-for-papers](https://tps.ieee-cs.org/2026/call-for-papers/) |
| **Aug 17** | **NordSec 2026** (Aarhus, Nov 11–12) | Springer LNCS proceedings, respected European security conf, student-friendly | ★★★ Very realistic acceptance odds for a solid short-scope security paper | [nordsec2026.dk](http://nordsec2026.dk/) |
| **Aug 19** | **NDSS 2027**, fall cycle (Seoul, Mar 2027) | **CORE A\***, top-4 security | ★☆☆ Long shot — needs major extension; desk-reject risk very high at current scope | [ndss-symposium.org/ndss2027 CFP](https://www.ndss-symposium.org/ndss2027/submissions/call-for-papers/) |
| **Aug 19** | **IEEE/ACM UCC 2026** (Florianópolis, Dec 1–4) | Established IEEE/ACM cloud series | ★★★ Explicitly accepts **4-page short papers** — the CloudCom PDF fits with minimal rework | [ucc2026.ufsc.br/calls/call-for-papers](https://ucc2026.ufsc.br/calls/call-for-papers/) |
| **Aug 21** | **ACM ASIA CCS 2027**, round 1 (Macau, Jul 2027) | **CORE A** | ★☆☆ Needs full-paper extension (~12 pp, anonymous); more reachable than NDSS but still a stretch | [asiaccs2027.cityu.edu.mo](https://asiaccs2027.cityu.edu.mo/home/index.html) |
| **Aug 25** | **USENIX Security 2027**, cycle 1 (Denver, Aug 2027) | **CORE A\***, top-4 security | ★☆☆ Same as NDSS — only with the full Q1-scale extension | [usenix.org/conference/usenixsecurity27](https://www.usenix.org/conference/usenixsecurity27) |

### Notes

- **CCSW@CCS 2026** (the venue ladder's stretch target): [ccsw.io](https://ccsw.io/) still shows the 2025 edition — CFP not out yet as of Jul 20, 2026. Last year's deadline was late June, so 2026 dates could land anywhere; keep checking weekly.
- **CSCloud 2026** (Shanghai, Dec) has an Aug 1 deadline — slightly before the mid/late-August window and a weaker venue; left off the main list.
- Simultaneous submission of the same paper to two venues is prohibited everywhere — the ladder order matters.

### Recommendation

1. **Submit the ready PDF to CloudCom by Aug 15** (EasyChair: [easychair.org/conferences/?conf=cloudcom2026](https://easychair.org/conferences/?conf=cloudcom2026)).
2. Prepare **UCC 2026 (Aug 19)** as the immediate backup — 4-page short papers accepted, so nearly free effort.
3. **NordSec 2026 (Aug 17)** is the best middle option if a security-branded venue is preferred over a cloud one.
4. The A*/A venues (NDSS, ASIA CCS, USENIX Security) only make sense after the Q1-scale extension described in `PAPER_REPORT.md` §5 step 6.

Before submitting, remember the open checklist items in `PAPER_REPORT.md`: add the university name to the author block, run iThenticate via the university library, and make the k8s-psa GitHub repo public.
