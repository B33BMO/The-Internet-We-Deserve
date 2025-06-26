mod shard;
mod crypto;
mod network;
mod storage;
mod messaging;
mod moderation;
mod utils;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "meshnet", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Shard, encrypt, and share a file
    Share {
        file: String,
        #[arg(long, default_value = "./shards")]
        out_dir: String,
    },
    /// Recover a file from shards
    Recover {
        #[arg(required = true)]
        shards: Vec<String>,
        #[arg(long, default_value = "./recovered.txt")]
        out_file: String,
    },
    /// Send an encrypted message to a peer
    Message {
        recipient: String,
        message: String,
    },
    /// Receive and decrypt a message from a peer
    Receive {
        sender: String,
        msg_file: String,
    },
    /// Generate a new keypair and save as prefix.pk / prefix.sk
    GenKeypair {
        prefix: String,
    },
    /// Run as a mesh node
    Node,
    /// Moderation commands (block/report a shard)
    Moderate {
        #[arg(long)]
        action: String,
        #[arg(long)]
        target: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    crypto::init();

    let cli = Cli::parse();

    match cli.command {
        // SHARD & ENCRYPT
        Commands::Share { file, out_dir } => {
            println!("Sharding and encrypting file: {}", file);
            let shards = shard::shard_file(&file, &out_dir)?;
            println!("Created shards: {:?}", shards);

            for shard_path in &shards {
                crypto::encrypt_shard_file(shard_path)?;
                println!("Encrypted shard: {}", shard_path);
            }
            println!("All shards encrypted. Ready to distribute.");
        }

        // RECOVER FILE
        Commands::Recover { shards, out_file } => {
            println!("Recovering file from shards...");
            let mut decrypted_shards = vec![];
            for shard in &shards {
                let decrypted = crypto::decrypt_shard_file(shard)?;
                decrypted_shards.push(decrypted);
            }
            // Save temp decrypted shards and recover file
            let temp_paths: Vec<_> = decrypted_shards
                .iter()
                .enumerate()
                .map(|(i, data)| {
                    let path = format!("./temp_shard{}.bin", i);
                    std::fs::write(&path, data).unwrap();
                    path
                })
                .collect();
            shard::recover_file(&temp_paths, &out_file)?;
            println!("File recovered to {}", out_file);
            for path in temp_paths {
                let _ = std::fs::remove_file(path);
            }
        }

        // SEND ENCRYPTED MESSAGE
        Commands::Message { recipient, message } => {
            println!("Encrypting and sending message to {}: {}", recipient, message);
            messaging::send_message(&recipient, &message).await?;
        }

        // RECEIVE AND DECRYPT MESSAGE
        Commands::Receive { sender, msg_file } => {
            println!("Receiving message from {}", sender);
            let msg = messaging::receive_message(&sender, &msg_file)?;
            println!("Decrypted message: {}", msg);
        }

        // GENERATE KEYPAIR
        Commands::GenKeypair { prefix } => {
            let (pk, sk) = crypto::gen_user_keypair();
            crypto::save_keypair(&pk, &sk, &prefix)?;
            println!(
                "Keypair generated and saved as {}.pk (public), {}.sk (secret)",
                prefix, prefix
            );
        }

        // RUN MESH NODE (stub)
        Commands::Node => {
            println!("Launching mesh node...");
            network::run_node().await?;
        }

        // MODERATION
        Commands::Moderate { action, target } => {
            println!("Moderation action: {} {:?}", action, target);
            match action.as_str() {
                "block" => {
                    if let Some(hash) = target {
                        moderation::block_shard(&hash)?;
                        println!("Shard {} blocked.", hash);
                    } else {
                        println!("No target specified for block.");
                    }
                }
                "report" => {
                    if let Some(hash) = target {
                        moderation::report_shard(&hash)?;
                        println!("Shard {} reported for abuse.", hash);
                    } else {
                        println!("No target specified for report.");
                    }
                }
                _ => println!("Unknown moderation action: {}", action),
            }
        }
    }

    Ok(())
}
