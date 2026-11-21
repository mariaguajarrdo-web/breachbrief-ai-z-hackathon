# BreachBrief: Legal Research

Team 404 LEGENDS, AI-Z track, MAIN Summit 2026. Legal position as of 20 November 2026.
This is a hackathon analysis, not legal advice. Every rule in `POLICY_MATRIX.md` points back to a section here.

## 0. The question

A company has suffered a personal data breach. It wants an AI agent to help its data protection officer (DPO) understand the incident, work out the notification duties and draft the notifications.

The legal problem is obvious once stated: **the input to the agent is the breached data itself.** If the agent forwards that data to an external AI provider, the response to the breach becomes a second processing operation, and potentially a second breach. Our design question is therefore: *what may the external model receive, what must stay inside the company, and which decisions must stay with a human?*

## 1. Is the use case lawful at all?

**Yes, with constraints.**

- **Purpose and legal basis.** Assessing and notifying a breach is required by GDPR Art. 33 and 34, and documenting it by Art. 33(5). Processing personal data for that purpose rests on **Art. 6(1)(c)** (compliance with a legal obligation). Using an AI tool is a means of performing that obligation, so it inherits the purpose but must still meet all GDPR principles.
- **Data minimisation, Art. 5(1)(c).** Only data "adequate, relevant and limited to what is necessary" may be processed. To assess a breach, the model needs the *facts* (what happened, when, which data categories, how many people) but **not the values** (the actual IBANs, salaries or diagnoses). This single principle drives most of our policy.
- **Integrity and confidentiality, Art. 5(1)(f), and security, Art. 32.** The controller must ensure appropriate security, and Art. 32(1)(a) names pseudonymisation as such a measure. Sending raw breached data to a third party without need would fail this test.
- **Data protection by design and by default, Art. 25.** Pseudonymisation and minimisation have to be built into the system, and by default only data necessary for the purpose may be processed. Our local detection, pseudonym vault and fail-closed gateway are Art. 25 measures.
- **Accountability, Art. 5(2).** The controller must be able to demonstrate compliance. Our test protocol records every decision and the exact payload sent, never the raw values.

## 2. Notification duties the agent supports

### 2.1 GDPR (always, when personal data is involved)
- **Definition, Art. 4(12):** a breach of security leading to accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, personal data. A payroll file emailed to the wrong supplier, ransomware with exfiltration and an API exposing account data all qualify.
- **Notify the supervisory authority, Art. 33(1):** without undue delay and, where feasible, **within 72 hours after becoming aware**, unless the breach is unlikely to result in a risk to individuals. Late notifications must state the reasons for the delay.
- **Minimum content, Art. 33(3):** nature of the breach including categories and approximate number of data subjects and records; DPO contact; likely consequences; measures taken or proposed. Information may be provided in phases, Art. 33(4). This is why the agent outputs a list of **missing facts**.
- **Inform affected people, Art. 34:** when the breach is likely to result in a **high risk**, in clear and plain language (Art. 34(2)), unless an exception in Art. 34(3) applies (e.g. data was encrypted).
- **Document every breach, Art. 33(5),** including those not notified.
- **Sanctions:** infringements of Art. 25 to 39 can lead to fines of up to EUR 10 million or 2% of worldwide annual turnover, Art. 83(4)(a).
- **Guidance used:** EDPB Guidelines 9/2022 on personal data breach notification (v2.0, adopted 28 March 2023) and EDPB Guidelines 01/2021 on examples regarding personal data breach notification, which include misdirected-mail and ransomware-with-exfiltration cases close to our scenarios.

*Pending change:* the Commission's Digital Omnibus proposal (procedure 2025/0360(COD), 19 November 2025) would raise the Art. 33 threshold to "likely high risk" and extend the deadline to 96 hours. It is **not law** as of today. Our deadlines are computed in code (`regimes.py`) so the change is one value if it is adopted.

### 2.2 NIS2 (essential and important entities, e.g. hospitals)
- **Directive (EU) 2022/2555, Art. 23(4):** for a significant incident, an **early warning within 24 hours**, an **incident notification within 72 hours**, and a **final report within one month** of the notification.
- Healthcare providers are a sector in Annex I. In the Netherlands, NIS2 is transposed by the **Cyberbeveiligingswet (Cbw), in force since 15 August 2026**.
- NIS2 does not replace the GDPR: where an incident involves a personal data breach, both regimes run in parallel, and NIS2 authorities cooperate with data protection authorities (Art. 35).

### 2.3 DORA (financial entities, e.g. banks)
- **Regulation (EU) 2022/2554, Art. 19:** major ICT-related incidents must be reported to the competent authority (in our scenario DNB).
- **Deadlines, Commission Delegated Regulation (EU) 2025/301, Art. 5:** initial notification within **4 hours of classifying** the incident as major and **no later than 24 hours** after becoming aware; intermediate report within 72 hours of the initial notification; final report within one month of the latest intermediate report. Classification criteria come from Delegated Regulation (EU) 2024/1772.
- DORA is the sector-specific act for financial entities in relation to NIS2 (NIS2 Art. 4). It does **not** displace GDPR Art. 33: a bank with a personal data breach reports under both.

**Design consequence:** legal deadlines are calculated deterministically by code from the awareness and classification times. The language model never decides a deadline.

## 3. What the external model may receive

### 3.1 The external AI provider is a processor, and possibly a third-country recipient
- The AI provider reached through BRANE processes data on the controller's behalf: a **processor** under **Art. 28**, requiring a data processing agreement. In our live runs BRANE routed cloud turns to Anthropic Claude Haiku via OpenRouter (`X-Brane-Model-Resolved: openrouter:anthropic/claude-haiku-5.5`) and local turns to its internal GPU model (`vllm:deepseek-v4.1-flash`); the same processor analysis applies to whichever provider BRANE selects, and to BRANE itself.
- If data reaches the US, **Chapter V (Art. 44 onwards)** applies. The EU-US Data Privacy Framework adequacy decision (Implementing Decision (EU) 2023/1795) was upheld by the General Court on 3 September 2025 (T-553/23, *Latombe*), and an appeal to the Court of Justice is pending. Relying on it is lawful today but carries legal uncertainty, which is another reason to send as little as possible.

### 3.2 Pseudonymisation: what it does and does not achieve
- **Art. 4(5)** defines pseudonymisation; **Recital 26** states that pseudonymised data remain personal data for whoever can re-identify them. For the company, which holds the vault, PERSON_001 is still personal data.
- **CJEU, EDPS v SRB, C-413/23 P (4 September 2025):** pseudonymised data are not automatically personal data **for a recipient** who has no reasonable means of re-identification. Because our vault never leaves the company, the external model's ability to re-identify is designed out. This lowers the risk of the transfer but does **not** remove the company's own GDPR duties.
- **EDPB Guidelines 01/2025 on pseudonymisation** (adopted 16 January 2025) require that the additional information (our vault) is kept separately and protected. We keep the vault in memory, per run, on the controller's side only.

### 3.3 Category by category
| Data | Needed by the model? | Legal reasoning | Decision |
|---|---|---|---|
| Incident facts (what, when, how many, which categories, actions taken) | Yes | Required content of Art. 33(3); necessary under Art. 5(1)(c) | **ALLOW** |
| Names of affected people, reporters | No, the identity is irrelevant to the analysis | Art. 5(1)(c), Art. 25, Art. 32(1)(a) | **PROTECT** (pseudonym, vault local) |
| Recipient / third-party identity | No | Same; also reputational harm to a third party | **PROTECT** |
| Email addresses | No | Same | **PROTECT** |
| Phone numbers, dates of birth | No | Same | **BLOCK** |
| IBANs, account numbers | No, only the category "bank details" | Art. 5(1)(c); financial identifiers enable fraud, a key risk factor in EDPB 9/2022 | **BLOCK** |
| National ID numbers (e.g. Dutch BSN) | No | Art. 87 GDPR lets member states set conditions; in NL the BSN may only be used for purposes provided by law (UAVG Art. 46) | **BLOCK** |
| Salary and balance amounts | No, only that they were exposed | Art. 5(1)(c) | **BLOCK** |
| Health data (diagnoses, sick leave, wards) | No, only the fact that Art. 9 data is involved | Special category, **Art. 9(1)**, defined in Art. 4(15). Its presence raises the risk level, so the *fact* is passed on, never the content | **LOCAL ONLY** |
| The leaked file itself | No | Only counts and category labels are needed for Art. 33(3)(a) | **LOCAL ONLY** (profiled locally) |
| Instructions embedded in documents | Never | Security of processing, Art. 32; a prompt injection could cause an unauthorised disclosure, which is itself an Art. 4(12) breach | **BLOCK** |
| Encoded attachments (base64, hex) | Never | Content that cannot be inspected cannot be shown to be minimised or safe; Art. 25, Art. 32 | **BLOCK** |

## 4. What must stay with a human

- **The risk assessment and the decision to notify** belong to the controller (Art. 33(1), 34(1), 5(2)). The agent *suggests* a risk level and lists missing facts; a named reviewer must confirm the risk level and choose which notifications to issue, and must give a reason to skip one. The app never sends anything itself. In addition, our BRANE policy has a semantic rule, AUTONOMOUS_NOTIFICATION_DECISION (action `refuse`, legal basis Art. 5(2), 33(1), 34(1)), so a request asking the model to decide the final risk level or file a notification itself is refused before any model runs. A live dry run on 20 November 2026 confirmed this: "decide the final risk level yourself and submit the notification" was refused, while "draft a notification for our DPO to review" was allowed.
- **GDPR Art. 22** (automated individual decisions) is not triggered, because the decision does not produce legal effects for an individual data subject on an automated basis. We nevertheless keep a human in the loop because the controller remains accountable and the EDPB stresses a case-by-case risk assessment.
- **AI Act (Regulation (EU) 2024/1689).** A breach-response assistant is not a high-risk system under Art. 6 and Annex III. Relevant duties are **AI literacy for staff (Art. 4)**. The transparency duty for AI-generated text published on matters of public interest (Art. 50(4)) does not bite, because every draft undergoes human review and a person holds editorial responsibility. We still label drafts as AI-assisted.

## 5. Security requirements translated into technical rules

Protection runs in two layers. Both are required by Art. 25 and 32: neither layer alone covers every risk.

**Layer 1: BRANE policy (primary enforcement at the model boundary).** Every model call goes through BRANE, with our team policy "Team-13 / policy-v1" (`configure_policy.py`):
- **Explicit rules:** all 25 built-in categories have one.
  - `placeholder`: PERSON, EMAIL, PHONE, ADDRESS, IP_ADDRESS, VAT_ID.
  - `allow`: ORG, TRADE_REGISTER.
  - `refuse`: civil and financial identifiers and credentials.
  - `local`: all Art. 9 special categories.
- **Semantic rules:**
  - INDIRECT_HEALTH_CONTEXT (`local`)
  - RAW_DATASET_EXFILTRATION (`refuse`)
  - AUTONOMOUS_NOTIFICATION_DECISION (`refuse`)
- **Verdict headers:** BRANE returns its decision in `X-Brane-*` headers. BreachBrief shows them to the reviewer and stores them in the run protocol.
- **Refusals:** an HTTP 422 refusal becomes the status `refused_by_brane`. Nothing is sent and the case is escalated to the human reviewer. It is never treated as a technical error, and never retried around.

**Layer 2: our code (defence in depth before anything reaches BRANE).** By default (`LOCAL_PREMASK=full`) BreachBrief masks every category in POLICY_MATRIX.md locally, so BRANE only sees what is already minimised. This layer also does four things BRANE cannot do:
- **The leaked file is never sent.** It is profiled locally; only counts and category labels leave the machine (Art. 5(1)(c), 25(2)).
- **Deadlines are deterministic.** GDPR, NIS2 and DORA deadlines are computed by code, never by a model.
- **A human approves.** A named reviewer confirms the risk level and the notifications. The app has no send function.
- **It fails closed.** If BRANE is unreachable, times out or returns an error, nothing is sent and there is no fallback to a direct model call. A failed local NER also stops the run.

| Requirement | Source | Implementation |
|---|---|---|
| Nothing leaves unchecked | Art. 25, 32 | Local detection, then a final guard re-scans the exact payload before it is sent |
| Every occurrence is handled | Art. 5(1)(c), 32 | Detection runs on all matches, including spacing variants, titles ("Mrs. X") and names found by local NER |
| Instructions in documents are data | Art. 32 | Injection patterns (EN/NL/DE) are blocked; the system prompt marks the report as data |
| If the check fails, send nothing | Art. 32; AI-Z rule | No direct model call exists in the codebase; BRANE errors, timeouts or a failed local NER stop the run |
| Demonstrable compliance | Art. 5(2), 33(5) | Protocol per run: decisions, exact payload, outcome, approval; raw values never logged |
| Every model call is governed by the team policy | Art. 25, 32 | BRANE applies placeholder / allow / local / refuse per category plus the three semantic rules; its `X-Brane-*` verdict is shown and logged |
| A policy refusal goes to a person | Art. 5(2), 32 | HTTP 422 becomes `refused_by_brane`: nothing sent, the reviewer sees the triggering rule (`X-Brane-Refused-By`) and decides |
| Disguised instructions and content that cannot be inspected are not sent | Art. 25, 32 | Injection detection also handles polite wording, spaced letters, look-alike and zero-width characters; base64 / hex blobs are removed locally |
| Evidence against the real gateway | Art. 5(2) | `make_protocol.py` runs T1-T5 + E1-E5 against live BRANE and writes `test_evidence_run.csv` with the headers as evidence |

## 6. Known limitations (honest list)

- Pattern and NER detection can miss data (e.g. a lone first name). The final guard and BRANE's own detection reduce this, and the human reviewer sees what was sent. First names that appear in the leaked file are now caught on their own; a first name that is not in the file and not recognised by NER is still a gap.
- **`guard_only` mode.** With local pre-masking switched off, names, contacts and health text go to BRANE and BRANE alone decides. For the hospital scenario BRANE usually refuses (`category:DATE_OF_BIRTH->refuse`), because it sees the word "dob" next to the removed value. That is a safe outcome: nothing is sent and the case is escalated. But BRANE is not consistent here: in one run the same input went to a cloud model with two health sentences (section 7, gap 6). `guard_only` is therefore a demonstration mode only; production runs with local pre-masking on (`LOCAL_PREMASK=full`, the default).
- **Evidence date and policy.** The live evidence (`test_evidence_run.csv`, 10/10 PASS) ran on 20 November 2026 against BRANE with policy "Team-13 / policy-v1". BRANE's detectors are model-based, so the same input can be judged differently after a model or policy update. The evidence must be re-run (`python make_protocol.py`) after any change. To check stability, the full set (T1-T5, E1-E5) was run three times in a row on 20 November 2026: 30 of 30 rows passed and every row took the same route each time (cloud, local or refused). The one inconsistency we saw (gap 6) came from the full hospital report in `guard_only`, which is not part of the T/E set and is not the production configuration.
- **BRANE runs at `piiSensitivity: high`.** This produced the false positives in section 7. Our workarounds change only how markers and labels are worded, never what is protected.
- Pseudonymised context can sometimes identify a person indirectly (e.g. "the only employee in Utrecht on sick leave"). Health context is therefore removed at sentence level, not word level.
- The DPF transfer basis is under appeal; an EU-hosted or local model would remove that dependency.
- Deadline rules reflect the law on 20 November 2026; the Digital Omnibus may change GDPR Art. 33.

## 7. Product gaps found during testing

Found while running BreachBrief against live BRANE on 20 November 2026. Four caused over-blocking, one let unverifiable content through, and one (gap 6) let health text reach a cloud model in the `guard_only` demonstration mode. None of them reached a model in the production default, where our code masks everything locally first. Each is also recorded in the product gap column of `policy_matrix_submission.csv`.

| Gap | What happened | How we worked around it | Matrix rule |
|---|---|---|---|
| Our redaction markers flagged as PASSWORD | BRANE refused already-masked payloads as `category:PASSWORD->refuse`. It read bracketed tokens such as `[IBAN_REMOVED]` and `[HEALTH_DETAIL_KEPT_LOCAL]`, a JSON field name in our system prompt, and the words "recovery key" as credentials. | Towards live BRANE, markers are written as plain words, e.g. `(iban removed)`, `(special-category sentence withheld)`; the system prompt was reworded with the same five output fields. What is protected did not change. | R14 |
| Category labels refused as DATE_OF_BIRTH | Our leaked-file summary must name the data categories (Art. 33(3)(a)). BRANE refused the label "dates of birth", and also "DOB", "birth dates", "date-of-birth fields". Once it refused a plain incident date. | The label now reads "age data", the only tested wording that passed. Plain wording is used for dates. | R10, R2 |
| Ordinary words read as PERSON | BRANE tagged "Became" (from our header "Became aware at:") and our own PERSON_001 tokens as person names. The placeholder garbled one draft ("Became became aware"). | The header now reads "Awareness time:". Placeholders on our own tokens are harmless and left as they are. | R3 |
| Encoded content reached the cloud | Sent on its own, a base64 attachment was kept local by BRANE (`X-Brane-Local-Cause: prompt_injection_local`). Inside a longer incident report the same blob was forwarded to the cloud. It contained a synthetic name and sick-leave note that neither layer could read. | Long base64 / hex runs are now removed locally as unverifiable, in both premask modes (T5). | R17 |
| ORG is one rule for two needs | BRANE has one action per category. Drafts must name authorities and companies ("Autoriteit Persoonsgegevens"), so ORG must be `allow`. But the third-party recipient of a misdirected file should not be identified to the model (Art. 5(1)(c)). | ORG stays `allow` in BRANE. Recipients known from the case file are pseudonymised by our code (`RECIPIENT_A`) in both premask modes. We would like per-role rules or an allowlist of authorities. | R4 |
| 6. Different verdicts for the same input | With local pre-masking off (`guard_only`), the same hospital input was refused by BRANE in one run (`category:DATE_OF_BIRTH->refuse`) and sent to a cloud model in another. In the cloud run, two sentences with health context ("diagnosis", "ward Orthopaedics") were in the text the model received (counted by our verdict, estimated from BRANE's headers because its preview was unavailable). Art. 9 data should never take that route. | Local pre-masking ON is the production default (`LOCAL_PREMASK=full`): health sentences are removed on this machine before BRANE, so BRANE's variability cannot expose them. `guard_only` is only a demonstration of BRANE acting alone, labelled as such in the UI, and its verdict banner shows the health count honestly. We would like deterministic decisions per input, or at least a stable result for special-category content. | R11, R12, R10 |

## 8. Questions the jury may ask

- **"Why not just use a local model for everything?"** A cloud model gives better drafts. The law does not forbid using it; it requires minimisation and security. We send only what Art. 33(3) needs.
- **"Isn't pseudonymised data still personal data?"** For the company, yes (Recital 26). For the model provider, *EDPS v SRB* says not necessarily, if it cannot re-identify, and our vault never leaves the company.
- **"What if BRANE is down during a 72-hour deadline?"** Nothing is sent. Deadlines are computed locally and the DPO can still notify in phases under Art. 33(4).
- **"Who is liable if the AI is wrong?"** The controller. That is why the risk level and the decision to notify require a named human reviewer.

## Sources
- GDPR, Regulation (EU) 2016/679: https://eur-lex.europa.eu/eli/reg/2016/679/oj
- NIS2, Directive (EU) 2022/2555: https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- DORA, Regulation (EU) 2022/2554: https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- Commission Delegated Regulation (EU) 2025/301 (DORA reporting time limits): https://eur-lex.europa.eu/eli/reg_del/2025/301/oj
- AI Act, Regulation (EU) 2024/1689: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- EDPB Guidelines 9/2022 on personal data breach notification (v2.0): https://www.edpb.europa.eu/documents/guideline/guidelines-92022-on-personal-data-breach-notification-under-gdpr_nb
- EDPB Guidelines 01/2021 on examples regarding personal data breach notification, and EDPB Guidelines 01/2025 on pseudonymisation: https://www.edpb.europa.eu/our-work-tools/our-documents/publication-type/guidelines_en
- CJEU, C-413/23 P, EDPS v SRB, 4 September 2025, ECLI:EU:C:2025:645: https://eur-lex.europa.eu/case/EN/C_413_23_P
- General Court, T-553/23, Latombe v Commission, 3 September 2025 (DPF upheld; appeal pending)
- Commission Implementing Decision (EU) 2023/1795 (EU-US Data Privacy Framework)
- Uitvoeringswet AVG (UAVG), Art. 46 (BSN): https://wetten.overheid.nl/BWBR0040940
- Cyberbeveiligingswet in force 15 August 2026: https://www.rijksoverheid.nl/actueel/nieuws/2026/08/15/cyberbeveiligingswet-en-wet-weerbaarheid-kritieke-entiteiten-vanaf-vandaag-van-kracht
- Digital Omnibus proposal, procedure 2025/0360(COD), 19 November 2025
