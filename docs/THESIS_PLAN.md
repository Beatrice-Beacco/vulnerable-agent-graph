# Piano di tesi — Reference monitor verificabile per LangGraph

**Vincoli:** 4 mesi (~17 settimane) · elaborato in inglese · base: prototipo in `agent-graph/`.
**Titolo proposto:** *A Verifiable Reference Monitor for LLM Multi-Agent Graphs: Integrity Label Propagation and Cedar Policy Enforcement in LangGraph*

## Context

L'IPI si propaga nei grafi multi-agente perché l'agente compromesso è un *confused deputy*: le policy sull'identità non bastano, serve autorizzare in base a integrità/provenienza dei dati. Contributi: (1) propagazione delle label in un grafo con stato condiviso, (2) reducer LangGraph come join del reticolo con prova, (3) policy Cedar analizzate con SymCC, più (c) mediazione completa per costruzione. Con 4 mesi: niente Lean, port TAMAS solo parziale.

**Research questions:** RQ1 le label sopravvivono a reducer/rami/routing/persistenza? · RQ2 si può dimostrare il contenimento e quali bug di policy trova l'analisi? · RQ3 trade-off security/utility (ASR statico e adattivo + utility) · RQ4 overhead.

**Convenzione:** ogni step ha un ID `<Fase><n>` (es. `B3`), ogni sotto-attività `<ID>.<k>` (es. `B3.2`). Spuntare la sotto-attività quando fatta; spuntare lo step quando il criterio **Done** è soddisfatto. Gli step sono in ordine di dipendenza.

---

## FASE A — Fondamenta (sett. 1–2)

- [ ] **A1 — Letture mirate e spike di fattibilità** (sett. 1)
  - [ ] A1.1 Leggere FIDES, CaMeL, Progent, AgentDojo, TAMAS, paper Cedar/SymCC, Prompt Infection (Lee & Tiwari), EchoLeak
  - [ ] A1.2 Installare `cedar-policy-symcc` + cvc5 (WSL/Docker se serve) e verificare supporto a `Long`, `Set`, `Record`
  - [ ] A1.3 Far girare AgentDojo con un elemento di pipeline custom
  - [ ] A1.4 Verificare disponibilità codice/dati TAMAS
  - [ ] A1.5 Scrivere nota di fattibilità (1 pagina) e concordare benchmark col relatore
  - **Done:** scelta benchmark approvata.

- [ ] **A2 — Threat model e TCB** (sett. 2, prima del codice)
  - [ ] A2.1 Definire attaccante: controlla dati esterni (email, allegati, web, output tool terzi), conosce sistema e policy; variante agente bizantino
  - [ ] A2.2 Definire TCB: runtime Python/LangGraph, `lgmonitor`, Cedar/cedarpy, policy+schema, codice dei nodi (controllato da lint), tool. Fuori TCB: LLM, dati esterni, output agenti
  - [ ] A2.3 Fissare proprietà: integrità dei sink critici (confidenzialità = stretch)
  - **Done:** bozza Cap. 3.

- [ ] **A3 — Definizioni formali del reticolo** (sett. 2)
  - [ ] A3.1 Label `ℓ = (i, P)`, `i ∈ Trusted < Internal < Untrusted`, `P ⊆ Sources`, join `(max, ∪)`
  - [ ] A3.2 Definire `lift(r)(⟨v₁,ℓ₁⟩,⟨v₂,ℓ₂⟩) = ⟨r(v₁,v₂), ℓ₁⊔ℓ₂⟩`
  - [ ] A3.3 Enunciare: monotonia, order-independence nei superstep, omomorfismo, taint soundness
  - **Done:** definizioni ed enunciati scritti.

---

## FASE B — Propagazione delle etichette (sett. 3–5)

- [ ] **B1 — Package `lgmonitor/` e tipi base**
  - [ ] B1.1 Creare `lgmonitor/labels.py` con `Label`, `join`, `Labeled[T]`
  - [ ] B1.2 Sostituire `Integrity`/`TaintedValue`/`join_integrity`/`taint_policy` in `agent-graph/state.py`
  - [ ] B1.3 `tests/test_labels.py` con hypothesis (associatività, commutatività, idempotenza)
  - **Done:** test verdi.

- [ ] **B2 — Reducer lifted**
  - [ ] B2.1 `lgmonitor/reducers.py`: `lift(reducer)`, varianti `operator.add`, `add_messages`, `LastValue`
  - [ ] B2.2 Rimuovere `merge_tainted` (`agent-graph/state.py:33-64`: scarta la label se `left.value` vuoto; concatenazione non ACI)
  - [ ] B2.3 Aggiornare `GraphState` con soli reducer lifted; aggiungere canali mancanti (es. `database_status`, `agents/database.py:75`)
  - [ ] B2.4 Test di regressione: fallisce con `merge_tainted`, passa con `lift`
  - **Done:** regressione verde.

- [ ] **B3 — Prove dei teoremi sui reducer**
  - [ ] B3.1 Prove su carta degli enunciati di A3.3
  - [ ] B3.2 `tests/test_reducers.py`: property-based su monotonia, omomorfismo, order-independence (permutazioni di update concorrenti)
  - **Done:** bozza Cap. 4 sez. "Reducers" + test verdi.

- [ ] **B4 — Label automatiche su LLM e tool**
  - [ ] B4.1 `lgmonitor/llm_taint.py`: wrapper di `agent-graph/llm.py`, label output = join del contesto letto
  - [ ] B4.2 `lgmonitor/tools.py`: label output = join(label argomenti, label sorgente); `tools/email.py` → `Untrusted, {email:<sender>}`
  - [ ] B4.3 Eliminare etichettatura manuale nei nodi (`agents/triage.py:70-89` e analoghi)
  - **Done:** i nodi restituiscono valori grezzi e le label sono corrette sullo scenario CRM.

- [ ] **B5 — Flussi impliciti e persistenza**
  - [ ] B5.1 `lgmonitor/pc.py`: pc-label per funzioni di routing (`graph.py:55-69`), `Command(goto)`, `Send`
  - [ ] B5.2 Join delle scritture con la pc-label nei nodi raggiunti
  - [ ] B5.3 `tools/crm.py`: persistere la label col record e restituirla in lettura
  - **Done:** routing dipendente dall'email → ramo scelto etichettato Untrusted.

- [ ] **B6 — Scenari per RQ1**
  - [ ] B6.1 Migrare `agent-graph/` in `scenarios/crm/`
  - [ ] B6.2 Creare `scenarios/map_reduce/` (con `Send`) e `scenarios/subgraph/`
  - [ ] B6.3 Script di confronto reducer naive vs lifted (conteggio taint perso)
  - **Done:** tabella RQ1.

---

## FASE C — Mediazione e policy (sett. 6–8)

- [ ] **C1 — Mediazione completa: `secure_compile`**
  - [ ] C1.1 `lgmonitor/mediation.py`: avvolgere nodi, edge condizionali, tool, modello prima di `compile()`
  - [ ] C1.2 Scritture su canali condivisi come richieste Cedar `Action::"write_channel"`
  - [ ] C1.3 Verifica runtime su `graph.get_graph()` (marker del monitor su ogni nodo/edge)
  - [ ] C1.4 Sostituire `builder.compile()` in `agent-graph/graph.py:101`
  - **Done:** un nodo non avvolto fa fallire `secure_compile`.

- [ ] **C2 — Lint anti-bypass**
  - [ ] C2.1 `lgmonitor/lint.py` (AST): rifiuta import diretti di tool/client HTTP nei nodi
  - [ ] C2.2 Esporre i tool solo come capability del monitor
  - **Done:** grafo di test con bypass rifiutato.

- [ ] **C3 — Schema Cedar e policy sui dati**
  - [ ] C3.1 `lgmonitor/cedar/schema.cedarschema`: `Agent`, `Tool`/`Channel` (`critical`, `sink_kind`), `DataSource`; context `taint`, `pc_taint`, `provenance`
  - [ ] C3.2 Policy di contenimento sul taint in `lgmonitor/cedar/policies/`:
    ```cedar
    forbid (principal, action, resource is Tool)
    when { resource.critical }
    unless { context.taint <= 0 && context.pc_taint <= 0 };
    ```
  - [ ] C3.3 Policy di least privilege per identità + `Action::"endorse"`
  - [ ] C3.4 Rimuovere `utils/tool_taints.py` ed eliminare il `permit` quasi universale di `engine/schema.py`
  - **Done:** policy validate contro lo schema.

- [ ] **C4 — Engine e middleware**
  - [ ] C4.1 `lgmonitor/cedar/engine.py` (da `engine/engine.py`): richiesta tipata, validazione schema, niente debug print
  - [ ] C4.2 Riscrivere `security/authorization_middleware.py` e `security/security_context.py`: contesto fornito dal monitor
  - [ ] C4.3 Eliminare l'unwrap della tupla (`agents/database.py:45-52`, middleware `:47-49`)
  - [ ] C4.4 Smoke test CRM: `data/malicious_email.txt` → `delete_customer` bloccato; ramo `internal_ops` → consentito
  - **Done:** 🏁 **M1** — monitor end-to-end, meeting relatore.

- [ ] **C5 — Verifica simbolica delle policy**
  - [ ] C5.1 `lgmonitor/analysis/` (Rust, `cedar-policy-symcc` + cvc5) con CLI `check --spec <P> policies/`
  - [ ] C5.2 P1 containment: permit su sink critico ⇒ `taint` e `pc_taint` Trusted
  - [ ] C5.3 P2 nessun endorsement verso sink critici senza HITL
  - [ ] C5.4 P3 refinement tra versioni delle policy
  - [ ] C5.5 P4 non vacuità (non always-deny sui task benigni)
  - [ ] C5.6 Riproduzione dei controesempi con cedarpy
  - **Done:** P1–P4 valide.

- [ ] **C6 — Mutation testing delle policy (RQ2) e teorema end-to-end**
  - [ ] C6.1 Generatore di mutanti (rimozione `unless`, off-by-one, permit larghi, action errate)
  - [ ] C6.2 Confronto rilevamento: SymCC vs test unitari vs run dei benchmark; tempi di analisi
  - [ ] C6.3 Teorema: label sound (B) + mediazione completa (C1–C2) + P1 ⇒ nessun dato non fidato raggiunge sink critici
  - **Done:** tabella RQ2 + bozza Cap. 5.

---

## FASE D — Utility (sett. 9)

- [ ] **D1 — Meccanismi di recupero utility** (`lgmonitor/endorse.py`)
  - [ ] D1.1 Handle opachi + LLM quarantinato senza tool per i dati untrusted
  - [ ] D1.2 Structured output a dominio chiuso + validator come endorsement sotto policy
  - [ ] D1.3 HITL con `interrupt()` sulle negazioni su sink critici
  - [ ] D1.4 Adattare `agents/email.py`, `agents/triage.py`, `agents/database.py`
  - **Done:** task benigni completati senza violare P1.

---

## FASE E — Harness di valutazione (sett. 10–11)

- [ ] **E1 — AgentDojo su LangGraph** (`bench/agentdojo_lg/`)
  - [ ] E1.1 Elemento di pipeline che esegue grafo multi-agente protetto da `secure_compile`
  - [ ] E1.2 Integrare 2–3 suite
  - [ ] E1.3 Sanity check senza difesa vs numeri pubblicati
  - **Done:** run pilota coerente.

- [ ] **E2 — Port parziale TAMAS** (`bench/tamas_lg/`, timebox 2 sett.)
  - [ ] E2.1 Port di 1–2 domini
  - [ ] E2.2 Tutti e 6 i tipi d'attacco, incluso agente bizantino
  - [ ] E2.3 (Fallback) vettori TAMAS riprodotti in `scenarios/`
  - **Done:** istanze eseguibili sul monitor.

- [ ] **E3 — Baseline e attacchi**
  - [ ] E3.1 Baseline: nessuna difesa · Cedar solo identità · spotlighting/sandwich · HITL puro
  - [ ] E3.2 Numeri Progent/CaMeL/FIDES dai paper (rerun solo se immediato)
  - [ ] E3.3 Attacchi statici dei benchmark
  - [ ] E3.4 Attaccante adattivo LLM (PAIR/TAP-like) contro endorser, LLM quarantinato, routing, write-then-read, agente bizantino
  - [ ] E3.5 (Stretch) GCG su modello open-weights locale
  - [ ] E3.6 Config fissata: 1 modello principale + 1 di controllo, seed/temperatura, ≥3 run
  - **Done:** 🏁 **M2** — harness completo.

---

## FASE F — Esperimenti (sett. 12–14)

- [ ] **F1 — Run completi**
  - [ ] F1.1 Benign utility, utility under attack, ASR, falsi blocchi, invocazioni HITL
  - [ ] F1.2 Overhead: latenza, token, tempo Cedar/decisione
  - **Done:** dati RQ3–RQ4 raccolti.

- [ ] **F2 — Ablation e analisi**
  - [ ] F2.1 Ablation: senza reducer lifted · senza pc-label · senza endorser · solo identità
  - [ ] F2.2 Grafici e intervalli di confidenza
  - [ ] F2.3 Threats to validity
  - **Done:** bozza Cap. 7.

---

## FASE G — Scrittura e consegna (sett. 15–17)

- [ ] **G1 — Elaborato completo**
  - [ ] G1.1 Cap. 1 Introduction
  - [ ] G1.2 Cap. 2 Background (LangGraph, IFC/Biba, reference monitor, Cedar+SymCC, IPI) — iniziato in sett. 1–3
  - [ ] G1.3 Rifinire Cap. 3–5 (bozze da A2, B3, C6)
  - [ ] G1.4 Cap. 6 Implementation
  - [ ] G1.5 Rifinire Cap. 7 (bozza da F2)
  - [ ] G1.6 Cap. 8 Related Work, Cap. 9 Limitations & Future Work, Cap. 10 Conclusion
  - **Done:** 🏁 **M3** (fine sett. 16) — draft completo al relatore.

- [ ] **G2 — Artefatto e discussione** (sett. 17)
  - [ ] G2.1 Aggiornare `README.md` e `requirements.txt`
  - [ ] G2.2 Script unico per rilanciare esperimenti e analisi
  - [ ] G2.3 Correzioni del relatore
  - [ ] G2.4 Slide di discussione
  - **Done:** consegna.

---

## Rischi

| ID | Rischio | Mitigazione |
|---|---|---|
| R1 | SymCC non supporta lo schema / non gira su Windows | Spike A1.2; WSL/Docker; context ridotto a `Long` + `Set<String>` |
| R2 | Port TAMAS troppo costoso | Timebox E2, fallback E2.3 |
| R3 | Utility crolla con la regola LLM conservativa | D1 anticipabile; ablation F2.1 |
| R4 | Costo chiamate LLM | Subset suite, caching esecuzioni benign |
| R5 | Scope creep | Confidenzialità, Lean, GCG solo stretch |

## Verifica

- [ ] V1 `pytest tests/` verde (reticolo, reducer, regressioni prototipo, bypass di mediazione)
- [ ] V2 `lgmonitor analysis check` valida P1–P4 e trova i mutanti violanti
- [ ] V3 Smoke test CRM (C4.4) verde a ogni modifica
- [ ] V4 Sanity check AgentDojo senza difesa (E1.3) prima di ogni misura
