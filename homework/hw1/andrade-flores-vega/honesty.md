# Where our breaks or design might be unfair.
Daniel Andrade - Andrés Vega - Carlos Flores

**1. Did a break rely on an assumption the deployment didn't actually make?**

Yes, for example `reused_pad` relies on the fact that plaintexts are English and that you can guess cribs.

**2. Is your SECS design's guarantee conditional on something you've hand-waved (a trusted CA, a secure channel for key distribution)?**

Yes, we have some assumptions:
- We consider a trusted CA.
- We assume the TTP is trustworthy and available.

**3. Does your design trade one goal for another (e.g. confidentiality vs. auditability)? Name the trade.**
- **Symmetry traded for liveness**. The rule "valid only when both ACKs arrive" keeps the outcome symmetric, so neither party is committed alone. The cost is that a party who withholds their ACK, or a TTP that fails mid-protocol, leaves the contract unconfirmed. The party who already sent their ACK has no recourse inside the protocol.
- **Confidentiality traded for fairness**. The contract is never hidden from the TTP, and the TTP also stores a full copy. It has to because it checks `H(contract)` and builds the final copy.
