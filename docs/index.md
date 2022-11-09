# Chronicle

Chronicle records provenance information of any physical or digital asset on a
distributed ledger to ensure that it is tamper-proof; and is available with
Hyperledger Sawtooth as its default backing ledger, with support for other
industry-leading distributed ledgers in the pipeline and a useful [in-memory
mode](building#in-memory-version) for rapid development of provenance
applications.

Chronicle is built on the W3C's PROV Ontology specification, which provides a
foundation to implement provenance applications in various domains that can
represent, exchange, and integrate provenance information generated by multiple
parties, in different systems, and under diverse contexts.

Chronicle leverages the data query and manipulation language GraphQL, providing
a comprehensive description of, and easy access to all provenance data from a
single endpoint. Alternatively, there is a command-line interface (CLI) for
integration with enterprise legacy systems.

Chronicle is a domain-agnostic offering, however, it is [easily
configurable](domain_modelling) to enable users to capture provenance
information for a range of applications or use cases such as the traceability of
artwork, critical infrastructure, food items, medical devices, precious metals,
or real estate, just to mention a few.

Chronicle is powered by our blockchain platform Sextant, to facilitate its
deployment and ongoing management, as well as its integration with enterprise
systems. Our flexible deployment options include multi-cloud, on-premise, and
hybrid environments, leveraging the industry-leading container orchestration
tool Kubernetes.