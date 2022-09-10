use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, ID,
};

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use common::prov::{ActivityId, AgentId, DomaintypeId, EntityId, NamePart};
use diesel::{debug_query, prelude::*, sqlite::Sqlite};
use tracing::{debug, instrument};

use crate::chronicle_graphql::cursor_query::{project_to_nodes, Cursorize};

use crate::{
    chronicle_graphql::{Activity, GraphQlError, Store},
    persistence::schema::generation,
};

use super::{Agent, Entity, TimelineOrder};

#[allow(clippy::too_many_arguments)]
#[instrument(skip(ctx))]
pub async fn activity_timeline<'a>(
    ctx: &Context<'a>,
    activity_types: Vec<DomaintypeId>,
    for_agent: Vec<AgentId>,
    for_entity: Vec<EntityId>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    order: Option<TimelineOrder>,
    namespace: Option<ID>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> async_graphql::Result<Connection<i32, Activity, EmptyFields, EmptyFields>> {
    use crate::persistence::schema::{
        activity, agent, association, delegation, entity, namespace::dsl as nsdsl, usage,
    };

    let store = ctx.data_unchecked::<Store>();

    let mut connection = store.pool.get()?;
    let ns = namespace.unwrap_or_else(|| "default".into());

    // Default from and to to the maximum possible time range
    let from = from.or_else(|| {
        Some(DateTime::<Utc>::from_utc(
            NaiveDateTime::new(
                NaiveDate::from_ymd(1582, 10, 16),
                NaiveTime::from_hms(0, 0, 0),
            ),
            Utc,
        ))
    });

    let to = to.or_else(|| Some(Utc::now()));

    let mut sql_query = activity::table
        .left_join(usage::table.on(usage::activity_id.eq(activity::id)))
        .left_join(generation::table.on(generation::activity_id.eq(activity::id)))
        .left_join(association::table.on(association::activity_id.eq(activity::id)))
        .left_join(
            delegation::table.on(delegation::activity_id
                .nullable()
                .eq(activity::id.nullable())),
        )
        .left_join(
            entity::table.on(entity::id
                .eq(usage::entity_id)
                .or(entity::id.eq(generation::generated_entity_id))),
        )
        .left_join(
            agent::table.on(agent::id
                .eq(association::agent_id)
                .or(agent::id.eq(delegation::delegate_id))
                .or(agent::id.eq(delegation::responsible_id))),
        )
        .inner_join(nsdsl::namespace.on(activity::namespace_id.eq(nsdsl::id)))
        .filter(nsdsl::name.eq(&**ns))
        .filter(activity::started.ge(from.map(|x| x.naive_utc())))
        .filter(activity::ended.le(to.map(|x| x.naive_utc())))
        .select(Activity::as_select())
        .into_boxed();

    if !for_entity.is_empty() {
        sql_query = sql_query.filter(
            entity::name.eq_any(
                for_entity
                    .iter()
                    .map(|x| x.name_part().clone())
                    .collect::<Vec<_>>(),
            ),
        )
    };

    if !for_agent.is_empty() {
        sql_query = sql_query.filter(
            agent::name.eq_any(
                for_agent
                    .iter()
                    .map(|x| x.name_part().clone())
                    .collect::<Vec<_>>(),
            ),
        )
    };

    if !activity_types.is_empty() {
        sql_query = sql_query.filter(
            activity::domaintype.eq_any(
                activity_types
                    .iter()
                    .map(|x| x.name_part().clone())
                    .collect::<Vec<_>>(),
            ),
        );
    }

    if order.unwrap_or(TimelineOrder::NewestFirst) == TimelineOrder::NewestFirst {
        sql_query = sql_query.order_by(activity::started.desc());
    } else {
        sql_query = sql_query.order_by(activity::started.asc());
    };

    query(
        after,
        before,
        first,
        last,
        |after, before, first, last| async move {
            debug!(
                "Cursor query {}",
                debug_query::<Sqlite, _>(&sql_query).to_string()
            );
            let rx = sql_query.cursor(after, before, first, last);

            let start = rx.start;
            let limit = rx.limit;

            let rx = rx.load::<(Activity, i64)>(&mut connection)?;

            Ok::<_, GraphQlError>(project_to_nodes(rx, start, limit))
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn agents_by_type<'a>(
    ctx: &Context<'a>,
    typ: Option<DomaintypeId>,
    namespace: Option<ID>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> async_graphql::Result<Connection<i32, Agent, EmptyFields, EmptyFields>> {
    use crate::persistence::schema::{
        agent::{self},
        namespace::dsl as nsdsl,
    };

    let store = ctx.data_unchecked::<Store>();

    let mut connection = store.pool.get()?;
    let ns = namespace.unwrap_or_else(|| "default".into());

    let sql_query = agent::table
        .inner_join(nsdsl::namespace)
        .filter(
            nsdsl::name
                .eq(&**ns)
                .and(agent::domaintype.eq(typ.as_ref().map(|x| x.name_part().to_owned()))),
        )
        .select(Agent::as_select())
        .order_by(agent::name.asc());

    query(
        after,
        before,
        first,
        last,
        |after, before, first, last| async move {
            debug!(
                "Cursor query {}",
                debug_query::<Sqlite, _>(&sql_query).to_string()
            );
            let rx = sql_query.cursor(after, before, first, last);

            let start = rx.start;
            let limit = rx.limit;

            let rx = rx.load::<(Agent, i64)>(&mut connection)?;

            Ok::<_, GraphQlError>(project_to_nodes(rx, start, limit))
        },
    )
    .await
}

pub async fn agent_by_id<'a>(
    ctx: &Context<'a>,
    id: AgentId,
    namespace: Option<String>,
) -> async_graphql::Result<Option<Agent>> {
    use crate::persistence::schema::{
        agent::{self, dsl},
        namespace::dsl as nsdsl,
    };

    let store = ctx.data_unchecked::<Store>();

    let ns = namespace.unwrap_or_else(|| "default".into());
    let mut connection = store.pool.get()?;

    Ok(agent::table
        .inner_join(nsdsl::namespace)
        .filter(dsl::name.eq(id.name_part()).and(nsdsl::name.eq(&ns)))
        .select(Agent::as_select())
        .first::<Agent>(&mut connection)
        .optional()?)
}

pub async fn activity_by_id<'a>(
    ctx: &Context<'a>,
    id: ActivityId,
    namespace: Option<String>,
) -> async_graphql::Result<Option<Activity>> {
    use crate::persistence::schema::{
        activity::{self, dsl},
        namespace::dsl as nsdsl,
    };

    let store = ctx.data_unchecked::<Store>();

    let ns = namespace.unwrap_or_else(|| "default".into());
    let mut connection = store.pool.get()?;

    Ok(activity::table
        .inner_join(nsdsl::namespace)
        .filter(dsl::name.eq(id.name_part()).and(nsdsl::name.eq(&ns)))
        .select(Activity::as_select())
        .first::<Activity>(&mut connection)
        .optional()?)
}

pub async fn entity_by_id<'a>(
    ctx: &Context<'a>,
    id: EntityId,
    namespace: Option<String>,
) -> async_graphql::Result<Option<Entity>> {
    use crate::persistence::schema::{
        entity::{self, dsl},
        namespace::dsl as nsdsl,
    };

    let store = ctx.data_unchecked::<Store>();
    let ns = namespace.unwrap_or_else(|| "default".into());
    let mut connection = store.pool.get()?;

    Ok(entity::table
        .inner_join(nsdsl::namespace)
        .filter(dsl::name.eq(id.name_part()).and(nsdsl::name.eq(&ns)))
        .select(Entity::as_select())
        .first::<Entity>(&mut connection)
        .optional()?)
}
