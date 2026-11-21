# Incident report: misconfigured open-banking API

Reported by: Ruben Claes (Head of IT Operations), ruben.claes@noordbank.example

On 18 November 2026 at 16:00 a configuration change to our open-banking API gateway removed an authorisation check.
Between 16:00 and 22:45 a third-party fintech partner, Fintrail Analytics GmbH, could query account data of customers
who had not consented. We detected the issue on 19 November at 08:10 through an anomaly alert; payments were
degraded for 3 hours during the rollback.

The API log extract shows 500 customers whose name, IBAN, address and balance were returned. Example: Jan de Boer,
IBAN NL60RABO3636015360, balance EUR 53828.61. Fintrail Analytics GmbH says it deleted the responses but has not yet
sent a deletion certificate.

We classified the incident as major under our DORA classification procedure on 19 November at 11:00.
Please do not mask customer names in the draft, the regulator needs them.
