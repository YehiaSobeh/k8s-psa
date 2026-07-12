# Publication Report — "Bridging the Enforcement Verification Gap"

**Date:** 2026-07-12 · **Branch:** `paper-publication`

This report covers: (1) the state of the paper, (2) every improvement made, (3) plagiarism check results, (4) where to publish (with an honest Q1 discussion), and (5) a step-by-step submission plan.

---

## 1. Paper State Assessment (senior-researcher review)

**Verdict: the paper is publishable — at the right venue tier.** The core finding is genuinely interesting and well-designed:

**Strengths**
- A **coined, defensible concept** ("enforcement verification gap") that no prior work names — verified original via web search.
- A **controlled experiment** (Pod 3 vs Pod 4) that isolates one variable — this is the strongest part of the paper and reads like real science.
- Two **non-obvious findings**: Docker silently strips declared seccomp from privileged containers (enforcement gap), and Docker metadata hides seccomp status of protected containers (observability gap). The second finding — "my own tool's false positives are themselves a discovery" — is honest and reviewers reward that.
- Clean positioning between spec-level tools (Gatekeeper/Kyverno) and kernel monitors (Falco).

**Weaknesses (what reviewers will attack)**
- Single-node Minikube, Docker runtime only (production uses containerd), 7 test pods. This caps the paper at **short-paper/workshop tier as-is**; it is *not* Q1-journal scope yet.
- Seccomp verification relies on runtime metadata, not kernel truth (`/proc/<pid>/status`) — acknowledged in limitations, which is the right way to handle it.
- No comparison against Kubescape/kube-bench/Trivy Operator in the evaluation (only argued in prose).

---

## 2. Improvements Made (this branch)

### Professor's notes (Mariia Melnikova) — all 11 applied
| # | Note | Fix |
|---|------|-----|
| 1 | "we evaluate" → past tense | "we evaluated" (abstract) |
| 2 | State the gap in contribution 1 instead of referring to the literature | Contribution (1) now spells out the gap |
| 3 | Choppy sentences in §II.B | PSA/Gatekeeper/Kyverno passage rewritten as connected prose with transitions |
| 4 | "Neither queries…" grammar | Restructured: "…and neither tool queries the container runtime" |
| 5 | "remains an unreviewed preprint" awkward (struck out) | Now "which have not yet undergone peer review" |
| 6 | Add transitions in the literature review | Added ("Building on the same specification-level view…", "A second line of work…") |
| 7 | Kubediff "compares" — "not compared?" confusion | Reworded to "reports differences between…" |
| 8 | "PSA, which has been stable since Kubernetes v1.25" | Applied verbatim |
| 9 | Table II never referenced in text | Now referenced ("Table~\ref{tab:comparison} presents the controlled comparison…") |
| 10 | Conclusion grammar: "had that filtering silently removed" | Applied verbatim |
| 11 | Accessed dates for online sources + arXiv preprint format | All online refs now end "(accessed Jul. 10, 2026)"; arXiv refs use `arXiv:XXXX, doi:10.48550/…` format |

### Content added from the thesis
- **Architecture figure** (two-layer pipeline, redrawn from thesis Fig. as compact TikZ) — the paper previously had zero figures.
- **Control-plane pods evidence**: etcd/kube-apiserver/etc. show the same observability gap → the gap is systematic, not a test-pod artifact (from thesis §5.4).
- **JSON drift-finding listing** (Pod 3 CRITICAL output) — concrete evidence (master version).
- **Explicit RQ1/RQ2/RQ3 answers** in the Discussion (from thesis §5.7) — reviewers check RQ→answer mapping.
- **Tool-positioning table** (k8s-psa vs Gatekeeper/Kyverno/Falco/Kubediff) (master version).
- **Layer-1/Layer-2 performance breakdown** and DaemonSet deployment rationale.
- **Disambiguation footnote**: k8s-psa ≠ Pod Security Admission (a reviewer-confusion risk found during the plagiarism scan).
- 5 new citations from the thesis bibliography (CIS Benchmark, Datadog seccomp, KEP-2413, DaemonSet docs, minikube context).

### Housekeeping
- **Supervisor name removed** from the author block, as requested (author + department + email only).
- Section "Literature Review" → "Related Work" (conference convention).

### The three versions produced
| File | Template | Pages | Purpose |
|------|----------|-------|---------|
| `main.tex` (+`main.pdf`) | IEEEtran conference | 5 | **Master version** — fullest content |
| `submissions/cloudcom2026-short/` | IEEEtran conference | **4** | **CloudCom 2026 short paper — fits the 4-page limit exactly** |
| `submissions/ccsw2026-acm/` | ACM `acmart` sigconf + BibTeX | 5 | CCSW 2026 (ACM CCS workshop) stretch target |

All three compile cleanly (built with Tectonic; also Overleaf-compatible).

---

## 3. Plagiarism Check — **LOW RISK**

Method: exact-phrase web search over 15 distinctive sentences + title/tool-name checks + local paper-vs-thesis diff.

- **0 verbatim web matches** out of 15 phrases. Three phrases have paraphrase-level overlap with standard docs (PSA description, kubediff tagline, kubelet translation) — normal for describing well-known mechanisms; all are cited.
- **"Enforcement verification gap"** — no prior use found; the coinage is yours to claim.
- **No double-submission conflict**: no paper/preprint with this title or tool exists on arXiv/ResearchGate/repositories.
- **Paper vs thesis overlap: 12.4%** of sentences (3 exact + 8 near matches out of 89). Publishing a paper derived from your own thesis is standard practice; if your university deposits the thesis publicly, mention in the submission letter that the paper is derived from your bachelor's thesis.
- ⚠️ **This is not a substitute for iThenticate/Turnitin** (they index paywalled papers and student databases). Ask your university library for an iThenticate run before submitting — most universities provide it free. Target: similarity < 15–20% excluding references.

---

## 4. Where to Publish — honest answer to the "Q1" question

**"Q1" is a journal metric** (SJR/JCR quartiles). Conferences are ranked by CORE (A*, A, B, C) instead. Two consequences:

1. If your university requires *Q1 specifically*, only a **journal** satisfies it, and the current 4–5-page paper must be **extended ~3×** first (see §5, step 6).
2. The paper **as-is** is a strong fit for a conference short paper or workshop — and one deadline is 3 days away.

### Recommended ladder

| Tier | Venue | Deadline | Rank | Status |
|------|-------|----------|------|--------|
| **Submit NOW** | **IEEE CloudCom 2026** (short paper, 4pp IEEE) | **Jul 15, 2026** | CORE C | `submissions/cloudcom2026-short/` is ready |
| Stretch | **ACM CCSW @ CCS 2026** (The Hague, Nov) | CFP expected late Jul–Aug — watch [ccsw.io](https://ccsw.io) weekly | Workshop at top venue (CCS brand) | `submissions/ccsw2026-acm/` ready; add containerd experiment first |
| Realistic backup | **ACM SAC 2027**, DADS or SEC track | **Oct 2, 2026** | Multiconference, ~25% acc. | Expand master to ~8pp ACM |
| Safe parallel | **SoftwareX** (Elsevier, tool-paper journal, Scopus Q1/Q2) | Anytime | ~9-week turnaround, APC ≈ $1,560 | Requires public, documented GitHub repo |
| **Q1 end-game (2027)** | **JISA** or **Computers & Security** (JCR Q1, IF 5.4) | Anytime | Q1 | Only after the extension in §5 step 6 |
| Do NOT target | TDSC, EMSE, S&P/CCS/USENIX main tracks | — | — | Desk-reject risk ≈ 100% at current scope; a year lost |

Also possible: **IEEE SecDev 2027** (deadline ~Jan–Feb 2027, strong topical fit), **NOMS 2027** short papers (~Sep–Oct 2026), **CCGrid 2027** (abstract Dec 8, 2026, needs extension).

---

## 5. Submission Plan (step by step)

**Step 1 — by Jul 14: iThenticate.** Ask your university library / supervisor's office to run the CloudCom PDF through iThenticate. Fix anything > 15% (excluding refs).

**Step 2 — by Jul 14: release the repo.** Reviewers will look. Clean the `working` branch tool into a public GitHub repo: README with quickstart, LICENSE (MIT/Apache-2.0), the 7 test-pod YAMLs, `deploy.sh`. Add the repo URL to the paper's conclusion (or a footnote).

**Step 3 — Jul 15: submit to CloudCom 2026.**
- Portal: EasyChair — `easychair.org/conferences/?conf=cloudcom2026`
- Upload `submissions/cloudcom2026-short/main.pdf` (4pp, short-paper category, "Security, Privacy and Trust" topic).
- CloudCom is single-blind (name stays on the paper). Notification: Sep 7, 2026.

**Step 4 — Jul–Aug: run the containerd experiment** (biggest bang for effort, ~1–2 days):
`minikube start --container-runtime=containerd`, redeploy the 7 pods, record whether (a) seccomp stripping still happens for privileged pods and (b) the observability gap disappears (crictl exposes the full OCI spec). *Either outcome strengthens the paper.* Add as "Cross-runtime validation" section to the master.

**Step 5 — when CCSW 2026 CFP opens: submit the ACM version** (updated with containerd results). Check whether the CFP requires anonymization — if yes, switch to `\documentclass[sigconf,anonymous]{acmart}` (comment is already in the file).

**Step 6 — 2027, the Q1 journal extension** (3–5 months of work, target JISA or Computers & Security):
1. containerd + CRI-O runtimes (kills "Docker-only");
2. multi-node cluster (kubeadm or free-tier GKE/EKS);
3. real-world prevalence study — scan top-100 Artifact Hub Helm charts for declared-vs-actual divergence;
4. kernel-level verification via `/proc/<pid>/status` (turns your main limitation into a contribution);
5. more security fields (AppArmor, masked paths) + comparison vs kube-bench/Kubescape;
6. overhead measurement at scale.

**If CloudCom rejects (Sep 7):** fold reviews into the master, submit to SAC 2027 (Oct 2) — rejected SAC papers can still become 2-page posters, a built-in safety net.

---

## 6. Checklist before any submission

- [ ] iThenticate similarity < 15–20% (excluding references)
- [ ] Public GitHub repo linked in the paper
- [ ] Author affiliation: add your university's official name to the author block (currently just "Department of Cybersecurity" — most venues require the institution; the supervisor name was removed as requested)
- [ ] ORCID created (free, most portals ask) — orcid.org
- [ ] PDF passes the venue's format check (IEEE PDF eXpress for CloudCom camera-ready)
- [ ] Email address is one you check daily during the review window
