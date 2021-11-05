#[macro_use]
extern crate serde_derive;

mod cli;
mod config;

use api::{
    ActivityCommand, AgentCommand, Api, ApiCommand, ApiError, ApiResponse, EntityCommand,
    KeyRegistration, NamespaceCommand, QueryCommand,
};
use clap::{App, ArgMatches};
use clap_generate::{generate, Generator, Shell};
use cli::cli;
use colored_json::prelude::*;
use common::{ledger::LedgerWriter, signing::SignerError};
use config::*;
use custom_error::custom_error;
use std::{
    io,
    path::{Path, PathBuf},
};
use tracing::{error, instrument, Level};
use user_error::UFE;

#[cfg(not(feature = "inmem"))]
fn ledger(config: &Config) -> Result<Box<dyn LedgerWriter>, SignerError> {
    Ok(Box::new(proto::messaging::SawtoothValidator::new(
        &config.validator.address,
        &common::signing::DirectoryStoredKeys::new(&config.secrets.path)?.chronicle_signing()?,
    )))
}

#[cfg(feature = "inmem")]
fn ledger(_config: &Config) -> Result<Box<dyn LedgerWriter>, std::convert::Infallible> {
    use std::convert::Infallible;

    Ok(Box::new(common::ledger::InMemLedger::default()))
}

#[instrument]
fn api_exec(config: Config, options: &ArgMatches) -> Result<ApiResponse, ApiError> {
    let api = Api::new(
        &Path::join(&config.store.path, &PathBuf::from("db.sqlite")).to_string_lossy(),
        ledger(&config)?,
        &config.secrets.path,
        uuid::Uuid::new_v4,
    )?;

    vec![
        options.subcommand_matches("namespace").and_then(|m| {
            m.subcommand_matches("create").map(|m| {
                api.dispatch(ApiCommand::NameSpace(NamespaceCommand::Create {
                    name: m.value_of("namespace").unwrap().to_owned(),
                }))
            })
        }),
        options.subcommand_matches("agent").and_then(|m| {
            vec![
                m.subcommand_matches("create").map(|m| {
                    api.dispatch(ApiCommand::Agent(AgentCommand::Create {
                        name: m.value_of("agent_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                    }))
                }),
                m.subcommand_matches("register-key").map(|m| {
                    let registration = {
                        if m.is_present("generate") {
                            KeyRegistration::Generate
                        } else if m.is_present("privatekey") {
                            KeyRegistration::ImportSigning {
                                path: m.value_of_t::<PathBuf>("privatekey").unwrap(),
                            }
                        } else {
                            KeyRegistration::ImportVerifying {
                                path: m.value_of_t::<PathBuf>("privatekey").unwrap(),
                            }
                        }
                    };

                    api.dispatch(ApiCommand::Agent(AgentCommand::RegisterKey {
                        name: m.value_of("agent_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                        registration,
                    }))
                }),
                m.subcommand_matches("use").map(|m| {
                    api.dispatch(ApiCommand::Agent(AgentCommand::Use {
                        name: m.value_of("agent_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                    }))
                }),
            ]
            .into_iter()
            .flatten()
            .next()
        }),
        options.subcommand_matches("activity").and_then(|m| {
            vec![
                m.subcommand_matches("create").map(|m| {
                    api.dispatch(ApiCommand::Activity(ActivityCommand::Create {
                        name: m.value_of("activity_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                    }))
                }),
                m.subcommand_matches("start").map(|m| {
                    api.dispatch(ApiCommand::Activity(ActivityCommand::Start {
                        name: m.value_of("activity_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                        time: None,
                    }))
                }),
                m.subcommand_matches("end").map(|m| {
                    api.dispatch(ApiCommand::Activity(ActivityCommand::End {
                        name: m.value_of("activity_name").map(|x| x.to_owned()),
                        namespace: m.value_of("namespace").map(|x| x.to_owned()),
                        time: None,
                    }))
                }),
                m.subcommand_matches("use").map(|m| {
                    api.dispatch(ApiCommand::Activity(ActivityCommand::Use {
                        name: m.value_of("entity_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                        activity: m.value_of("activity_name").map(|x| x.to_owned()),
                    }))
                }),
                m.subcommand_matches("generate").map(|m| {
                    api.dispatch(ApiCommand::Activity(ActivityCommand::Generate {
                        name: m.value_of("entity_name").unwrap().to_owned(),
                        namespace: m.value_of("namespace").unwrap().to_owned(),
                        activity: m.value_of("activity_name").map(|x| x.to_owned()),
                    }))
                }),
            ]
            .into_iter()
            .flatten()
            .next()
        }),
        options.subcommand_matches("entity").and_then(|m| {
            vec![m.subcommand_matches("attach").map(|m| {
                api.dispatch(ApiCommand::Entity(EntityCommand::Attach {
                    name: m.value_of("entity_name").unwrap().to_owned(),
                    namespace: m.value_of("namespace").unwrap().to_owned(),
                    file: m.value_of_t::<PathBuf>("file").unwrap(),
                    locator: m.value_of("locator").map(|x| x.to_owned()),
                    agent: m.value_of("agent").map(|x| x.to_owned()),
                }))
            })]
            .into_iter()
            .flatten()
            .next()
        }),
        options.subcommand_matches("export").and_then(|m| {
            Some(api.dispatch(ApiCommand::Query(QueryCommand {
                namespace: m.value_of("namespace").unwrap().to_owned(),
            })))
        }),
    ]
    .into_iter()
    .flatten()
    .next()
    .unwrap_or(Ok(ApiResponse::Unit))
}

custom_error! {pub CliError
    Api{source: api::ApiError}                  = "Api error",
    Keys{source: SignerError}                   = "Key storage",
    FileSystem{source: std::io::Error}          = "Cannot locate configuration file",
    ConfigInvalid{source: toml::de::Error}      = "Invalid configuration file",
    InvalidPath                                 = "Invalid path",
}

impl UFE for CliError {}

fn main() {
    let matches = cli().get_matches();

    if let Ok(generator) = matches.value_of_t::<Shell>("completions") {
        let mut app = cli();
        eprintln!("Generating completion file for {}...", generator);
        print_completions(generator, &mut app);
        std::process::exit(0);
    }

    let _tracer = {
        if matches.is_present("debug") {
            tracing_subscriber::fmt()
                .pretty()
                .with_max_level(Level::TRACE)
                .init();
            Some(())
        } else {
            None
        }
    };

    handle_config_and_init(&matches)
        .and_then(|config| Ok(api_exec(config, &matches)?))
        .map(|response| {
            match response {
                ApiResponse::Prov(doc) => {
                    println!(
                        "{}",
                        doc.to_json()
                            .compact()
                            .unwrap()
                            .0
                            .pretty(4)
                            .to_colored_json_auto()
                            .unwrap()
                    );
                }
                ApiResponse::Unit => {}
            }
            std::process::exit(0);
        })
        .map_err(|e| {
            error!(?e, "Api error");
            e.into_ufe().print();
            std::process::exit(1);
        })
        .ok();
}

fn print_completions<G: Generator>(gen: G, app: &mut App) {
    generate(gen, app, app.get_name().to_string(), &mut io::stdout());
}
