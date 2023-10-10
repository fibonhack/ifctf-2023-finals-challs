#[macro_use]
extern crate lazy_static;

use poise::serenity_prelude as serenity;
use std::env;
#[macro_use]
mod commands;
// mod ctfd_client;
// mod ctfmanager;
// mod ctftime_api;
// mod db;
mod shared;

use shared::Context;
use shared::Data;
use shared::Error;

lazy_static! {
    static ref TOKEN: String = env::var("DISCORD_TOKEN").unwrap_or_else(|_| {
        "".to_string()
    },);
    static ref GUILD_ID: u64 = env::var("GUILD_ID")
        .unwrap_or_else(|_| "".to_string())
        .parse()
        .unwrap();
}

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    // This is our custom error handler
    // They are many errors that can occur, so we only handle the ones we want to customize
    // and forward the rest to the default handler
    match error {
        poise::FrameworkError::Setup { error, .. } => panic!("Failed to start bot: {:?}", error),
        poise::FrameworkError::Command { error, ctx } => {
            println!("Error in command `{}`: {:?}", ctx.command().name, error,);
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                println!("Error while handling error: {}", e)
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let options = poise::FrameworkOptions {
        commands: my_commands!(),
        prefix_options: poise::PrefixFrameworkOptions {
            prefix: Some("/".into()),
            ..Default::default()
        },
        on_error: |error| Box::pin(on_error(error)),
        pre_command: |ctx| {
            Box::pin(async move {
                println!("Executing command {}...", ctx.command().qualified_name);
            })
        },
        // event_handler: |_ctx, event, _framework, _data| {
        //     Box::pin(async move {
        //         println!("Got an event in event handler: {:?}", event.name());
        //         Ok(())
        //     })
        // },
        ..Default::default()
    };

    let framework = poise::Framework::builder()
        .options(options)
        .token(TOKEN.to_owned())
        .intents(
            serenity::GatewayIntents::non_privileged() | serenity::GatewayIntents::MESSAGE_CONTENT,
        )
        .setup(|_ctx, _ready, _framework| {
            Box::pin(async move {
                Ok(Data {})
            })
        });

    framework.run().await.unwrap();
}
