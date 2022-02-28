use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use async_graphql::{
    extensions::Tracing,
    http::{playground_source, GraphQLPlaygroundConfig},
    Context, Error, ErrorExtensions, Object, OutputType, Schema, Subscription, Upload,
};
use async_graphql_warp::{graphql_subscription, GraphQLBadRequest};
use chrono::{DateTime, NaiveDateTime, Utc};
use common::commands::{
    ActivityCommand, AgentCommand, ApiCommand, ApiResponse, EntityCommand, KeyRegistration,
    PathOrFile,
};
use custom_error::custom_error;
use derivative::*;
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, Pool},
    Queryable, SqliteConnection,
};
use futures::Stream;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, instrument};
use uuid::Uuid;
use warp::{
    hyper::{Response, StatusCode},
    Filter, Rejection,
};

use crate::ApiDispatch;

#[derive(Default, Queryable)]
pub struct Agent {
    pub id: i32,
    pub name: String,
    pub namespace: String,
    pub domaintype: Option<String>,
    pub publickey: Option<String>,
    pub current: i32,
}

#[derive(Default, Queryable)]
pub struct Activity {
    pub id: i32,
    pub name: String,
    pub namespace: String,
    pub domaintype: Option<String>,
    pub started: Option<NaiveDateTime>,
    pub ended: Option<NaiveDateTime>,
}

#[derive(Default, Queryable)]
pub struct Entity {
    id: i32,
    name: String,
    namespace: String,
    domaintype: Option<String>,
    signature_time: Option<NaiveDateTime>,
    signature: Option<String>,
    locator: Option<String>,
}

#[derive(Default, Queryable)]
pub struct Submission {
    context: String,
    correlation_id: Uuid,
}

#[Object]
impl Submission {
    async fn context(&self) -> &str {
        &self.context
    }

    async fn correlation_id(&self) -> &Uuid {
        &self.correlation_id
    }
}

#[Object]
impl Agent {
    async fn namespace(&self) -> &str {
        &self.namespace
    }

    async fn name(&self) -> &str {
        &self.name
    }

    async fn public_key(&self) -> Option<&str> {
        self.publickey.as_deref()
    }

    #[graphql(name = "type")]
    async fn typ(&self) -> &str {
        if let Some(ref typ) = self.domaintype {
            typ
        } else {
            "agent"
        }
    }
}

#[Object]
impl Activity {
    async fn namespace(&self) -> &str {
        &self.namespace
    }

    async fn name(&self) -> &str {
        &self.name
    }

    async fn started(&self) -> Option<DateTime<Utc>> {
        self.started.map(|x| DateTime::from_utc(x, Utc))
    }

    async fn ended(&self) -> Option<DateTime<Utc>> {
        self.ended.map(|x| DateTime::from_utc(x, Utc))
    }

    #[graphql(name = "type")]
    async fn typ(&self) -> &str {
        if let Some(ref typ) = self.domaintype {
            typ
        } else {
            "activity"
        }
    }

    async fn was_associated_with<'a>(
        &self,
        ctx: &Context<'a>,
    ) -> async_graphql::Result<Vec<Agent>> {
        use crate::persistence::schema::wasassociatedwith::{self, dsl};

        let store = ctx.data_unchecked::<Store>();

        let mut connection = store.pool.get()?;

        let res = wasassociatedwith::table
            .filter(dsl::activity.eq(self.id))
            .inner_join(crate::persistence::schema::agent::table)
            .load::<((i32, i32), Agent)>(&mut connection)?;

        Ok(res.into_iter().map(|(_, x)| x).collect())
    }

    async fn used<'a>(&self, ctx: &Context<'a>) -> async_graphql::Result<Vec<Entity>> {
        use crate::persistence::schema::used::{self, dsl};

        let store = ctx.data_unchecked::<Store>();

        let mut connection = store.pool.get()?;

        let res = used::table
            .filter(dsl::activity.eq(self.id))
            .inner_join(crate::persistence::schema::entity::table)
            .load::<((i32, i32), Entity)>(&mut connection)?;

        Ok(res.into_iter().map(|(_, x)| x).collect())
    }
}

#[Object]
impl Entity {
    async fn namespace(&self) -> &str {
        &self.namespace
    }

    async fn name(&self) -> &str {
        &self.name
    }

    #[graphql(name = "type")]
    async fn typ(&self) -> &str {
        if let Some(ref typ) = self.domaintype {
            typ
        } else {
            "entity"
        }
    }

    async fn signature_time(&self) -> Option<DateTime<Utc>> {
        self.signature_time.map(|x| DateTime::from_utc(x, Utc))
    }

    async fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    async fn locator(&self) -> Option<&str> {
        self.locator.as_deref()
    }

    async fn was_attributed_to<'a>(
        &self,
        ctx: &Context<'a>,
    ) -> async_graphql::Result<Vec<Activity>> {
        use crate::persistence::schema::wasgeneratedby::{self, dsl};

        let store = ctx.data_unchecked::<Store>();

        let mut connection = store.pool.get()?;

        let res = wasgeneratedby::table
            .filter(dsl::entity.eq(self.id))
            .inner_join(crate::persistence::schema::activity::table)
            .load::<((i32, i32), Activity)>(&mut connection)?;

        Ok(res.into_iter().map(|(_, x)| x).collect())
    }

    async fn was_generated_by<'a>(
        &self,
        ctx: &Context<'a>,
    ) -> async_graphql::Result<Vec<Activity>> {
        use crate::persistence::schema::wasgeneratedby::{self, dsl};

        let store = ctx.data_unchecked::<Store>();

        let mut connection = store.pool.get()?;

        let res = wasgeneratedby::table
            .filter(dsl::entity.eq(self.id))
            .inner_join(crate::persistence::schema::activity::table)
            .load::<((i32, i32), Activity)>(&mut connection)?;

        Ok(res.into_iter().map(|(_, x)| x).collect())
    }
}

custom_error! {pub GraphQlError
    Db{source: diesel::result::Error}                           = "Database operation failed",
    DbConnection{source: diesel::ConnectionError}               = "Database connection failed",
    Api{source: crate::ApiError}                                = "API",
}

impl ErrorExtensions for GraphQlError {
    // lets define our base extensions
    fn extend(&self) -> Error {
        Error::new(format!("{}", self)).extend_with(|_err, _e| ())
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Store {
    #[derivative(Debug = "ignore")]
    pub pool: Pool<ConnectionManager<SqliteConnection>>,
}

impl Store {
    pub fn new(pool: Pool<ConnectionManager<SqliteConnection>>) -> Self {
        Store { pool }
    }
}

#[derive(Default)]
pub struct Query;

#[Object]
impl Query {
    async fn agent<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: String,
    ) -> async_graphql::Result<Option<Agent>> {
        use crate::persistence::schema::agent::{self, dsl};

        let store = ctx.data_unchecked::<Store>();

        let mut connection = store.pool.get()?;

        Ok(agent::table
            .filter(dsl::name.eq(name).and(dsl::namespace.eq(namespace)))
            .first::<Agent>(&mut connection)
            .optional()?)
    }

    async fn activities_by_time<'a>(
        &self,
        ctx: &Context<'a>,
        types: Vec<String>,
        from_inclusive: Option<DateTime<Utc>>,
        end_exclusive: Option<DateTime<Utc>>,
    ) -> async_graphql::Result<Vec<Activity>> {
        use crate::persistence::schema::activity;
        let store = ctx.data_unchecked::<Store>();

        let mut connection = store.pool.get()?;
        let mut query = activity::table.into_boxed();

        if let Some(start) = from_inclusive {
            query = query.filter(activity::started.gt(start.naive_utc()));
        }

        if let Some(end) = end_exclusive {
            query = query.filter(activity::started.lt(end.naive_utc()));
        }

        for t in types {
            query = query.or_filter(activity::domaintype.eq(t))
        }

        Ok(query.load::<Activity>(&mut connection)?)
    }
}

struct Mutation;

async fn transaction_context<'a>(
    res: ApiResponse,
    _ctx: &Context<'a>,
) -> async_graphql::Result<Submission> {
    match res {
        ApiResponse::Prov(id, _, correlation_id) => Ok(Submission {
            context: id.to_string(),
            correlation_id,
        }),
        _ => unreachable!(),
    }
}

#[Object]
impl Mutation {
    pub async fn create_agent<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: Option<String>,
        typ: Option<String>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Agent(AgentCommand::Create {
                name,
                namespace: namespace.clone(),
                domaintype: typ,
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn create_activity<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: Option<String>,
        typ: Option<String>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Activity(ActivityCommand::Create {
                name,
                namespace: namespace.clone(),
                domaintype: typ,
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn generate_key<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: Option<String>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Agent(AgentCommand::RegisterKey {
                name,
                namespace: namespace.clone(),
                registration: KeyRegistration::Generate,
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn start_activity<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: Option<String>,
        agent: String,
        time: Option<DateTime<Utc>>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Activity(ActivityCommand::Start {
                name,
                namespace: namespace.clone(),
                time,
                agent: Some(agent),
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn end_activity<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: Option<String>,
        agent: String,
        time: Option<DateTime<Utc>>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Activity(ActivityCommand::End {
                name: Some(name),
                namespace: namespace.clone(),
                time,
                agent: Some(agent),
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn activity_use<'a>(
        &self,
        ctx: &Context<'a>,
        activity: String,
        name: String,
        namespace: Option<String>,
        typ: Option<String>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Activity(ActivityCommand::Use {
                name,
                namespace: namespace.clone(),
                domaintype: typ,
                activity: Some(activity),
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn activity_generate<'a>(
        &self,
        ctx: &Context<'a>,
        activity: String,
        name: String,
        namespace: Option<String>,
        typ: Option<String>,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Activity(ActivityCommand::Generate {
                name,
                namespace: namespace.clone(),
                domaintype: typ,
                activity: Some(activity),
            }))
            .await?;

        transaction_context(res, ctx).await
    }

    pub async fn entity_attach<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
        namespace: Option<String>,
        attachment: Upload,
        on_behalf_of_agent: String,
        locator: String,
    ) -> async_graphql::Result<Submission> {
        let api = ctx.data_unchecked::<ApiDispatch>();

        let namespace = namespace.unwrap_or_else(|| "default".to_owned());

        let res = api
            .dispatch(ApiCommand::Entity(EntityCommand::Attach {
                name,
                namespace: namespace.clone(),
                agent: Some(on_behalf_of_agent),
                file: PathOrFile::File(Arc::new(Box::pin(
                    attachment.value(ctx)?.into_async_read(),
                ))),
                locator: Some(locator),
            }))
            .await?;

        transaction_context(res, ctx).await
    }
}

pub struct Subscription;

#[derive(Default, Queryable)]
pub struct CommitNotification {
    correlation_id: Uuid,
}

#[Object]
impl CommitNotification {
    pub async fn correlation_id(&self) -> &Uuid {
        &self.correlation_id
    }
}

#[Subscription]
impl Subscription {
    async fn commit_notifications<'a>(
        &self,
        ctx: &Context<'a>,
    ) -> impl Stream<Item = CommitNotification> {
        let api = ctx.data_unchecked::<ApiDispatch>().clone();
        let mut rx = api.notify_commit.subscribe();
        async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok((_prov, correlation_id)) =>
                    yield CommitNotification {correlation_id},
                    Err(RecvError::Lagged(_)) => {
                    }
                    Err(_) => break
                }
            }
        }
    }
}

#[instrument]
pub async fn serve_graphql(
    pool: Pool<ConnectionManager<SqliteConnection>>,
    api: ApiDispatch,
    address: SocketAddr,
    open: bool,
) {
    let schema = Schema::build(Query, Mutation, Subscription)
        .extension(Tracing)
        .data(Store::new(pool.clone()))
        .data(api)
        .finish();

    let graphql_post = async_graphql_warp::graphql(schema.clone()).and_then(
        |(schema, request): (
            Schema<Query, Mutation, Subscription>,
            async_graphql::Request,
        )| async move {
            Ok::<_, Infallible>(async_graphql_warp::GraphQLResponse::from(
                schema.execute(request).await,
            ))
        },
    );

    let graphql_playground = warp::path::end().and(warp::get()).map(|| {
        Response::builder()
            .header("content-type", "text/html")
            .body(playground_source(
                GraphQLPlaygroundConfig::new("/").subscription_endpoint("/"),
            ))
    });

    let open_address = address;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        debug!(?open_address, "Open browser at");
        open::that(&format!("http://{}/", open_address)).ok();
    });

    let routes = graphql_subscription(schema)
        .or(graphql_playground)
        .or(graphql_post)
        .recover(|err: Rejection| async move {
            if let Some(GraphQLBadRequest(err)) = err.find() {
                return Ok::<_, Infallible>(warp::reply::with_status(
                    err.to_string(),
                    StatusCode::BAD_REQUEST,
                ));
            }

            Ok(warp::reply::with_status(
                "INTERNAL_SERVER_ERROR".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        });

    warp::serve(routes).run(address).await;
}
