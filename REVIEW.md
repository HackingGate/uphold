# Review

Read this when reviewing a change to this repository. It carries the part of
each principle that no rule here can decide -- the judgment -- and nothing that
a rule already refuses.

Do NOT re-enforce the static rules. They run on every change and they run
first; repeating their findings costs a reviewer's attention and buys a second
opinion nobody asked for. The rules already active here are:

- `catalog-reference-current`
- `catalog-tests`
- `catalog-validate`
- `hook-pins-resolve`
- `no-stale-hook-pins`
- `prevent-ai-author`
- `prevent-public-push`
- `workflow-declares-permissions`

Everything below is a constraint whose remainder is a judgment. For each, the
claim is what it asserts, the scope says when it binds, and the questions are
what to ask of a change.

## Complete Mediation
Authority must be verified on every access to a protected object or effect, on every path that can reach it, and not only on the path the designer had in mind.

**Applies when**
- A protected effect is reachable through more than one interface, tier, or tool.
- Caching, delegation, or convenience wrappers can shortcut an earlier authorization decision.
- New surfaces are added over time to a system whose checks were written for the original surface.

**Ask**
- What are all the paths that reach this effect, including manual, scripted, and agent-driven ones?
- Which of those paths meets the control, and what evidence shows it?
- When a new interface is added, does it inherit the check or does someone have to remember to add it?
- Is the same rule body reached from every seam, or has it been reimplemented per seam?

## Defense in Depth
Protect critical assets and actions with multiple controls that fail differently and cover prevention, detection, containment, and recovery.

**Applies when**
- Consequences justify more than one control.
- Controls can be made meaningfully independent.
- Detection and recovery matter in addition to prevention.

**Ask**
- How does each layer fail differently?
- Which layer detects failure of another?
- Can the layers be tested independently and end to end?

## End-to-End Principle
Functions requiring application-level knowledge should be implemented or verified end to end, even when lower layers provide performance or reliability assistance.

**Applies when**
- The guarantee depends on application semantics.
- Intermediate layers cannot observe all relevant state.
- Lower-layer checks can be treated as optimization rather than proof.

**Ask**
- Which layer has enough context to prove the actual objective?
- Is a lower-layer guarantee being mistaken for end-to-end correctness?
- What evidence reaches the endpoint after partial failure?

## Enforcement Needs a Trigger
A constraint becomes machine enforcement only when it is expressed as a decidable predicate over an observable subject, bound to a condition that fires it and to evidence it emits when it fires. A constraint that cannot say when it applies or what it saw is guidance, and must be shipped and read as guidance.

**Applies when**
- A constraint is about to be added to a linter, hook, policy file, alert rule, or a prompt assembled for a model.
- A rule's payload is prose rather than a match, a diff, or a state comparison.
- Someone proposes carrying design guidance in a runtime configuration.
- A reviewing tier is proposed for the part of a constraint no predicate captures, and the question is what stops it becoming the always-emitted prose this record refuses.

**Ask**
- What input is this rule known to match, and is that input checked in?
- What event causes this rule to run, and over which files or subjects?
- What does it print when it refuses, and can the reader locate the cause from that alone?
- If this rule can never fire, what in the system would reveal that?
- For the part that cannot be mechanized, where does it live so that whoever builds the check reads it?

## Fail Fast and Explicitly
When continuing cannot satisfy the contract safely, detect the condition at the earliest reliable boundary and return an explicit failure with evidence.

**Applies when**
- The violated condition can be detected reliably.
- Continuing would corrupt state, mislead callers, or increase recovery cost.
- A caller can handle or escalate the failure.

**Ask**
- Is the failure detected at the boundary that owns the invariant?
- Would continuing preserve a truthful and safe contract?
- Does the error include enough evidence for recovery?

## Graceful Degradation
When a dependency or resource fails, retain a clearly identified subset of safe and useful behavior rather than presenting total failure or false success.

**Applies when**
- A useful subset can be served without violating safety or truthfulness.
- The degraded state can be detected and communicated.
- Recovery and reconciliation are defined.

**Ask**
- Which capabilities remain safe and truthful without this dependency?
- How is degraded mode visible to users and operators?
- What state must be reconciled after recovery?

## High Cohesion, Low Coupling
Components should contain behavior that belongs to one coherent responsibility and depend on other components through the smallest necessary contracts.

**Applies when**
- Responsibilities and change patterns can be identified.
- Dependencies can be narrowed without duplicating authority.
- The boundary corresponds to a meaningful lifecycle or ownership unit.

**Ask**
- Which responsibility unifies this component?
- Which dependencies are essential rather than convenient?
- Do recent changes repeatedly cross this boundary?

## Information Hiding
Module boundaries should conceal design decisions likely to change, exposing only the stable information required by clients.

**Applies when**
- A representation, algorithm, policy, or external dependency is likely to change.
- Clients can operate through a smaller stable contract.
- The hidden decision has a coherent owner.

**Ask**
- Which design decision is this boundary hiding?
- What client knowledge would cause ripple effects if exposed?
- Is diagnostic visibility preserved without making internals part of the contract?

## Informed Consent for Consequential Actions
An effect that is hard to reverse and falls outside what the invoked operation denotes requires that the specific effects be disclosed in terms the user can evaluate, that declining be possible without abandoning the rest of the work, and that the recorded approval bound the action to what was shown.

**Applies when**
- The effects land on data or systems the user owns and the tool does not.
- Reversal is impossible, lossy, or needs knowledge the user does not have.
- The effects are not entailed by the operation the user asked for.
- A person is present to answer, or a prior approval specific to this action was recorded.
- The action is taken on the user's behalf by an agent or automation they cannot watch.

**Ask**
- What exactly will change, and would the user recognise it from this description?
- Can the user decline this part and still get the rest of what they asked for?
- Is the previewed plan produced by the same code that applies it?
- What does this do when no one is there to answer -- refuse, or proceed?
- When the set of effects grows in a later version, what makes it ask again rather than reuse the old approval?

## Least Astonishment
An operation should confine its effects to what its name and context already denote to the people who invoke it, and any effect beyond that must be visible at the point of use rather than discoverable only afterwards.

**Applies when**
- The user brings an expectation from a convention, a neighbouring tool, or an earlier version of this one.
- The operation touches state the user owns and the tool does not.
- The surprising effect is paid for by the user rather than by the author.
- Discovery happens after the fact, when the cheap moment to object has passed.

**Ask**
- What does the name of this operation promise, and what does it actually touch?
- Which of these effects would a user learn about only after they had happened?
- If this changes a default, what does a user who upgrades without reading anything experience?
- Is the extra behavior disclosed where the decision is made, or only in documentation the user reads later?
- Whose expectation is being matched, and what is the evidence that they hold it?

## Make Illegal States Unrepresentable
Where practical, encode invariants in constructors, types, schemas, or state machines so downstream code receives only valid states.

**Applies when**
- The invariant is stable and can be expressed in the representation.
- Construction passes through a controlled boundary.
- Invalid states do not need to be preserved for diagnosis or migration.

**Ask**
- Which invalid combinations recur in checks or incidents?
- Can the invariant be enforced once at construction?
- Does the representation include real transitional states rather than pretending they do not exist?

## Separate Mechanism from Policy
Implement stable mechanisms that provide capability, and express changeable policy separately so decisions can evolve without rewriting the machinery.

**Applies when**
- The same capability serves multiple policies or environments.
- Rules change more often than the underlying mechanism.
- Policy can be represented explicitly and reviewed.

**Ask**
- Which behavior is stable capability and which is changeable rule?
- Who is authorized to change the policy?
- Can invalid policy be rejected before execution?

## Observability
A system should emit structured, correlated evidence sufficient to explain relevant state transitions, decisions, dependencies, latency, and failures without reproducing every incident.

**Applies when**
- The system has distributed execution, asynchronous work, agents, or external dependencies.
- Operators need to distinguish failure modes.
- Evidence can be emitted without violating privacy or security.

**Ask**
- Which failure modes can current telemetry distinguish?
- Can one user-level operation be followed across model and tool calls?
- What sensitive information must be redacted or omitted?

## Parameterize, Do Not Enumerate
If two units of code differ only in a constant, they are one unit with an unextracted parameter. Naming the constant in the identifier moves it out of the type system and into the namespace, where the count grows as the product of the value sets rather than their sum, nothing forces the copies to stay consistent, and the next value needs an author instead of a caller.

**Applies when**
- Two or more units differ only by a literal, an enum member, a key, or a path.
- A unit's name encodes an argument rather than the operation.
- A general method exists in a library and the surface exposing it does not accept the same range.
- A one-off helper is about to be written for scaffolding, a probe, a fixture, or a script.

**Ask**
- What differs between these units, and is it only a value?
- Does the name contain an argument? If the value moved into the signature, what would the name become?
- Does the layer underneath already accept the range this layer does not, and why does the narrowing exist?
- If the next value is needed tomorrow, does someone call this or edit it?
- If this is deliberately one case of many, where is that written, and what refuses the second copy?

## Psychological Acceptability
Protection mechanisms must be easy enough to apply correctly and routinely that the user's mental model of the protection matches what the mechanism actually does; otherwise compliance decays and the mechanism's real coverage falls to zero.

**Applies when**
- The control sits on a path a person or agent traverses many times a day.
- Bypassing is possible and cheaper than complying.
- The control produces failures on legitimate work, not only on the case it targets.

**Ask**
- How often will this fire on legitimate work, and what does the person do next?
- Is the cheapest response to a failure a fix, or turning the check off?
- Is there a scoped way in for a tree that does not yet comply, such as a baseline or a ratchet?
- Six months from now, what evidence would show this is still enabled everywhere it was installed?

## Optimize for Reversible Decisions
For uncertain, noncritical choices, favor designs and commitments whose consequences can be observed and reversed at acceptable cost before scaling them.

**Applies when**
- The decision is uncertain and can be staged.
- Rollback or migration can be designed explicitly.
- Delay has its own opportunity cost.

**Ask**
- What exactly would rollback restore?
- Which consequences are irreversible outside the system boundary?
- What evidence will trigger consolidation or reversal?

## Separation of Concerns
Organize a system so distinct concerns can be understood, changed, tested, and governed independently where their real dependencies permit it.

**Applies when**
- Concerns have different change drivers, owners, policies, or test strategies.
- A boundary can be introduced without duplicating core truth.
- Interactions can be made explicit through contracts.

**Ask**
- What distinct reasons would cause this component to change?
- Which concern owns each invariant?
- Does the proposed boundary reduce or merely relocate coupling?

## Single Authoritative Source
Each authoritative fact should have one explicitly designated ownership and update authority, while replicas, caches, and derived views remain subordinate to that authority.

**Applies when**
- The same fact is represented in multiple services, stores, reports, or workflows.
- Conflicting updates would be materially expensive or unsafe.
- A responsible owner can be assigned at an appropriate domain boundary.

**Ask**
- Which component owns the canonical meaning and writes?
- Can every copy explain its source and refresh policy?
- What happens when the authority is unavailable?

## Unix Composability
Prefer small, focused mechanisms connected through stable, inspectable interfaces so that complex behavior can be assembled rather than embedded in one indivisible program.

**Applies when**
- A domain can be decomposed into transformations or tools with stable boundaries.
- Intermediate results are useful to inspect, store, or reuse.
- The operational cost of composition remains lower than the cost of integration.

**Ask**
- Is each component focused on one coherent transformation or capability?
- Can outputs be inspected and consumed without private knowledge?
- Would combining these components preserve a stronger transaction or invariant?
