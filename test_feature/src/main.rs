use anyhow::Result;
use clap::Parser;
use ethers::prelude::*;
use std::sync::Arc;
use std::convert::TryFrom;
use futures::stream::{self, StreamExt};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target Wallet Address to scan (Source and Destination must match)
    #[arg(short, long, default_value = "0xD957F4ab9166c3332978f58754786235319c1520")]
    address: String,

    /// RPC URL for Sepolia
    #[arg(short, long, default_value = "https://ethereum-sepolia.publicnode.com")]
    rpc: String,

    /// Number of recent blocks to scan
    #[arg(short, long, default_value_t = 200)]
    blocks: u64,

    /// Concurrency limit for parallel scanning
    #[arg(short, long, default_value_t = 5)]
    concurrency: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let target_addr: Address = args.address.parse().expect("Invalid Ethereum Address");
    
    println!("Connecting to Sepolia RPC: {}", args.rpc);
    let provider = Provider::<Http>::try_from(args.rpc.as_str())?;
    let provider = Arc::new(provider);

    let current_block = match provider.get_block_number().await {
        Ok(n) => n.as_u64(),
        Err(e) => {
            eprintln!("Failed to get current block: {}", e);
            return Ok(());
        }
    };
    println!("Current Block: {}", current_block);
    
    let start_block = if current_block > args.blocks {
        current_block - args.blocks
    } else {
        0
    };

    println!("Scanning {} blocks ({} to {}) with concurrency: {}", 
             args.blocks, start_block, current_block, args.concurrency);
    println!("Target: {} -> {}", target_addr, target_addr);

    let blocks_range = start_block..=current_block;

    // Create a parallel stream
    stream::iter(blocks_range)
        .map(|block_num| {
            let provider = provider.clone();
            async move {
                let mut retries = 0;
                loop {
                    match provider.get_block_with_txs(block_num).await {
                        Ok(res) => return (block_num, Ok(res)),
                        Err(e) => {
                            if retries >= 5 {
                                return (block_num, Err(e));
                            }
                            retries += 1;
                            let delay = std::time::Duration::from_millis(500 * retries);
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        })
        .buffer_unordered(args.concurrency)
        .for_each(|(block_num, block_res)| async move {
            match block_res {
                Ok(Some(block)) => {
                    for tx in block.transactions {
                        if tx.from == target_addr {
                            if let Some(to_addr) = tx.to {
                                if to_addr == target_addr {
                                    let input_data = &tx.input;
                                    let memo = if input_data.len() > 0 {
                                        match std::str::from_utf8(input_data) {
                                            Ok(s) => s.to_string(),
                                            Err(_) => format!("(Hex) 0x{}", hex::encode(input_data)),
                                        }
                                    } else {
                                        "(No Memo)".to_string()
                                    };

                                    println!("\n[FOUND] Block: {}", block_num);
                                    println!("  Tx Hash: {:?}", tx.hash);
                                    println!("  Memo: {}", memo);
                                }
                            }
                        }
                    }
                }
                Ok(None) => {}, 
                Err(e) => eprintln!("\nError fetching block {} (Max retries): {}", block_num, e),
            }
        })
        .await;

    println!("\nScan Complete.");
    Ok(())
}
