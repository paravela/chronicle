# Querying Provenance

Currently Chronicle has 4 root queries.

```graphql
type Query {
    activityTimeline(activityTypes: [ActivityType!]!, forEntity: [EntityID!]!, from: DateTime, to: DateTime, namespace: ID, after: String, before: String, first: Int, last: Int): ActivityConnection!
    agentsByType(agentType: AgentType!, namespace: String, after: String, before: String, first: Int, last: Int): AgentConnection!
    agentById(id: AgentID!, namespace: String): Agent
    entityById(id: EntityID!, namespace: String): Entity
}
```

The majority of the work for provenance retrieval will be with the [activity
timeline](#activity-timeline) query.

Familiarizing yourself with GraphQL is necessary to make good use of Chronicle.
Chronicle makes extensive use of
[relay cursors](https://relay.dev/graphql/connections.htm) and [union types](https://www.apollographql.com/docs/apollo-server/schema/unions-interfaces/).

## Activity timeline

### Parameters

#### activityTypes

A list of ActivityTypes to filter the returned timeline by, leaving this empty
will return all activity types. The `PROV_ACTIVITY` activity type can be used to
return activities that are not currently specified in the Chronicle domain.

```graphql
enum ActivityType {
  PROV_ACTIVITY
  PUBLISHED
  QUESTION_ASKED
  RESEARCHED
  REVISED
}

```

#### forEntity

A list of EntityIDs to filter activities by - leaving this empty will return all
activity types.

#### from

The time in RFC3339 format to return activities from. Not specifying this will
return all activity types before the time specified in [to](#to).

#### to

The time in RFC3339 format to return activities until. Nor specifying this will
return all activity types after the time specified in [from](#from).

#### after

Relay cursor control, returning a page after the cursor you supply to this
argument - for forwards pagination.

#### before

Relay cursor control, returning items before the cursor you supply to this
argument - for reverse pagination.

#### first

An integer controlling page size for forward pagination. Defaults to 20

#### last

An integer controlling page size for reverse pagination. Defaults to 20

## agentsByType

## agentById

## entityById

## Returned objects

### Entity subtypes

All Chronicle Entity subtypes follow a similar pattern, we will use the Guidance
entity from our example domain as a sample.

```graphql
type Guidance {
  id: EntityID!
  namespace: Namespace!
  external_id: String!
  type: DomaintypeID
  evidence: EvidenceReference
  wasGeneratedBy: [Activity!]!
  wasDerivedFrom: [Entity!]!
  hadPrimarySource: [Entity!]!
  wasRevisionOf: [Entity!]!
  wasQuotedFrom: [Entity!]!
  titleAttribute: TitleAttribute
  versionAttribute: VersionAttribute
}

```

#### Entity: id

The EntityID of the entity. This is derived from external_id, but clients should
not attempt to synthesize it themselves.

#### Entity: namespace

The Namespace of the entity, only of interest for Chronicle domains that span
multiple namespaces.

#### Entity: external_id

The external_id of the entity, determined when defined.

#### Entity: type

A DomainTypeID derived from the Entity subtype. The built-in GraphQL field
`__TypeName` should be used for union queries.

#### Entity: evidence

See [chronicle evidence](#chronicle-evidence)

#### Entity: wasGeneratedBy

A list of the Activities that generated this entity. See
[generation](provenance_concepts#generation).

#### Entity: wasRevisionOf

A list of the Entities that this entity is a revision of. See
[revision](provenance_concepts#revision). This currently only returns the
immediate entity that the current entity is derived from and will require
recursive enumeration to retrieve a deep hierarchy.

#### Entity: wasQuotedFrom

A list of the Entities that this entity was quoted from. See
[quotation](provenance_concepts#quotation). This currently only returns the
immediate entity that the current entity is derived from and will require
recursive enumeration to retrieve a deep hierarchy.

#### Entity: wasDerivedFrom

A list of the Entities that this entity is derived from. See
[derivation](provenance_concepts#derivation). This currently only returns
the immediate entity that the current entity is derived from and will require
recursive enumeration to retrieve a deep hierarchy.

### Attributes

Attribute values for the attributes associated with the entity subtype, as
determined by the [domain model](domain_modelling).

### Activity subtypes

```graphql
type Published {
  id: ActivityID!
  namespace: Namespace!
  external_id: String!
  started: DateTime
  ended: DateTime
  type: DomaintypeID
  wasAssociatedWith: [Association!]!
  used: [Entity!]!
  versionAttribute: VersionAttribute
}
```

#### Activity: id

The EntityID of the entity. This is derived from external_id, but clients
should not attempt to synthesize it themselves.

#### Activity: namespace

The Namespace of the entity, only of interest for Chronicle domains that span
multiple namespaces.

#### Activity: external_id

The external_id of the entity, determined when defined.

#### Activity: type

A DomainTypeID derived from the Entity subtype. the built-in GraphQL field
`__TypeName` should be used for union queries