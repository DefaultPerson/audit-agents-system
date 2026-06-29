//! Snapshot Extractor - Extract high-balance contracts from Erigon/Geth node
//!
//! This tool uses debug_accountRange RPC to iterate all accounts and filter
//! contracts with balance above threshold.
//!
//! Usage:
//!   snapshot-extractor --chain eth --rpc http://localhost:8545 --min-balance 100000 --output data/targets.db

use anyhow::Result;
use clap::Parser;
use ethers::providers::{Http, Middleware, Provider};
use rusqlite::Connection;
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "snapshot-extractor")]
#[command(about = "Extract high-balance contracts from EVM chain")]
struct Args {
    /// Chain identifier (eth, bsc)
    #[arg(long, default_value = "eth")]
    chain: String,

    /// RPC URL (must support debug_accountRange)
    #[arg(long)]
    rpc: String,

    /// Minimum balance in USD
    #[arg(long, default_value = "100000")]
    min_balance: u64,

    /// Output SQLite database path
    #[arg(long, default_value = "data/targets.db")]
    output: String,

    /// Snapshot block for debug_accountRange; defaults to latest
    #[arg(long)]
    block: Option<u64>,

    /// Price feed JSON path (address -> (price, decimals))
    #[arg(long)]
    prices: Option<String>,
}

#[derive(Debug, Clone)]
struct ContractInfo {
    address: String,
    balance_wei: String,
    balance_usd: f64,
    code_hash: String,
}

/// DeFiLlama coin IDs for native tokens
fn get_defillama_coin_id(chain: &str) -> &'static str {
    match chain {
        "eth" => "coingecko:ethereum",
        "bsc" => "coingecko:binancecoin",
        "arbitrum" => "coingecko:ethereum",
        "base" => "coingecko:ethereum",
        "polygon" => "coingecko:matic-network",
        "avalanche" => "coingecko:avalanche-2",
        "optimism" => "coingecko:ethereum",
        _ => "coingecko:ethereum",
    }
}

/// Fallback prices for when API is unavailable
fn get_fallback_price(chain: &str) -> f64 {
    match chain {
        "eth" => 3500.0,
        "bsc" => 600.0,
        "arbitrum" => 3500.0,
        "base" => 3500.0,
        "polygon" => 0.5,
        "avalanche" => 35.0,
        "optimism" => 3500.0,
        _ => 1.0,
    }
}

fn block_tag_from_snapshot(block: Option<u64>) -> String {
    block
        .map(|block| format!("0x{:x}", block))
        .unwrap_or_else(|| "latest".to_string())
}

/// Fetch native token price from DeFiLlama
async fn fetch_native_price(chain: &str) -> Result<f64> {
    let coin_id = get_defillama_coin_id(chain);
    let url = format!("https://coins.llama.fi/prices/current/{}", coin_id);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("DeFiLlama API returned {}", response.status());
    }

    let json: serde_json::Value = response.json().await?;

    // Parse response: {"coins": {"coingecko:ethereum": {"price": 3500.0, ...}}}
    let price = json["coins"][coin_id]["price"]
        .as_f64()
        .ok_or_else(|| anyhow::anyhow!("Price not found in response"))?;

    Ok(price)
}

/// Price service - maps token address to (price_usd, decimals)
struct PriceService {
    _prices: HashMap<String, (f64, u8)>,
    native_price: f64,
}

impl PriceService {
    fn from_json(path: &str, native_price: f64) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let prices: HashMap<String, (f64, u8)> = serde_json::from_str(&content)?;
        Ok(Self {
            _prices: prices,
            native_price,
        })
    }

    /// Create price service with live price from DeFiLlama
    async fn with_live_price(chain: &str) -> Self {
        let native_price = match fetch_native_price(chain).await {
            Ok(price) => {
                info!("Fetched {} price from DeFiLlama: ${:.2}", chain, price);
                price
            }
            Err(e) => {
                let fallback = get_fallback_price(chain);
                warn!(
                    "Failed to fetch price from DeFiLlama: {}. Using fallback: ${:.2}",
                    e, fallback
                );
                fallback
            }
        };

        Self {
            _prices: HashMap::new(),
            native_price,
        }
    }

    fn get_native_value_usd(&self, balance_wei: &str) -> f64 {
        // Parse balance as u128 (wei)
        let balance: u128 = balance_wei.parse().unwrap_or(0);
        // Convert to ETH (18 decimals)
        let balance_eth = balance as f64 / 1e18;
        balance_eth * self.native_price
    }
}

async fn extract_contracts(
    provider: &Provider<Http>,
    _chain: &str,
    min_balance_usd: f64,
    price_service: &PriceService,
    block_tag: &str,
) -> Result<Vec<ContractInfo>> {
    info!("Starting account iteration via debug_accountRange at {}...", block_tag);

    let mut contracts = Vec::new();
    let mut start_key = [0u8; 32];
    let batch_size = 256u64;
    let mut total_accounts = 0u64;

    loop {
        // Call debug_accountRange
        // Format: debug_accountRange(blockNumber, startKey, maxResults, noCode, noStorage)
        let result: serde_json::Value = provider
            .request(
                "debug_accountRange",
                (
                    block_tag,
                    format!("0x{}", hex::encode(&start_key)),
                    batch_size,
                    false, // noCode = false (we want code)
                    true,  // noStorage = true (skip storage for speed)
                ),
            )
            .await?;

        let accounts = result["accounts"].as_object();
        if accounts.is_none() || accounts.unwrap().is_empty() {
            break;
        }

        let accounts = accounts.unwrap();
        total_accounts += accounts.len() as u64;

        for (address, data) in accounts {
            // Check if it's a contract (has code)
            let code = data["code"].as_str().unwrap_or("0x");
            if code == "0x" || code.len() <= 2 {
                continue; // EOA, skip
            }

            // Get balance
            let balance_hex = data["balance"].as_str().unwrap_or("0x0");
            let balance_wei = u128::from_str_radix(&balance_hex[2..], 16).unwrap_or(0);
            let balance_usd = price_service.get_native_value_usd(&balance_wei.to_string());

            if balance_usd >= min_balance_usd {
                // Compute code hash
                let code_bytes = hex::decode(&code[2..]).unwrap_or_default();
                let code_hash = format!("0x{}", hex::encode(ethers::utils::keccak256(&code_bytes)));

                contracts.push(ContractInfo {
                    address: address.clone(),
                    balance_wei: balance_wei.to_string(),
                    balance_usd,
                    code_hash,
                });

                info!(
                    "Found contract: {} - ${:.2}",
                    address, balance_usd
                );
            }
        }

        // Get next key
        if let Some(next) = result["next"].as_str() {
            let next_bytes = hex::decode(&next[2..]).unwrap_or_default();
            if next_bytes.len() == 32 {
                start_key.copy_from_slice(&next_bytes);
            } else {
                break;
            }
        } else {
            break;
        }

        if total_accounts % 10000 == 0 {
            info!("Processed {} accounts, found {} contracts", total_accounts, contracts.len());
        }
    }

    info!(
        "Extraction complete: {} accounts processed, {} high-value contracts found",
        total_accounts,
        contracts.len()
    );

    Ok(contracts)
}

fn save_to_sqlite(contracts: &[ContractInfo], chain: &str, db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS contracts (
            address TEXT NOT NULL,
            chain TEXT NOT NULL,
            balance_usd REAL NOT NULL,
            balance_native TEXT NOT NULL,
            age INTEGER NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'new',
            code_hash TEXT,
            found_at TEXT NOT NULL,
            updated_at TEXT,
            PRIMARY KEY (address, chain)
        )",
        [],
    )?;

    let now = chrono::Utc::now().to_rfc3339();

    for contract in contracts {
        conn.execute(
            "INSERT INTO contracts (address, chain, balance_usd, balance_native, code_hash, found_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(address, chain) DO UPDATE SET
                balance_usd = excluded.balance_usd,
                balance_native = excluded.balance_native,
                code_hash = excluded.code_hash,
                updated_at = excluded.found_at",
            rusqlite::params![
                contract.address.to_lowercase(),
                chain,
                contract.balance_usd,
                contract.balance_wei,
                contract.code_hash,
                now
            ],
        )?;
    }

    info!("Saved {} contracts to {}", contracts.len(), db_path);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("Snapshot Extractor v0.1.0");
    info!("Chain: {}", args.chain);
    info!("RPC: {}", args.rpc);
    info!("Min balance: ${}", args.min_balance);
    let block_tag = block_tag_from_snapshot(args.block);
    info!("Snapshot block: {}", block_tag);

    // Initialize provider
    let provider = Provider::<Http>::try_from(&args.rpc)?;

    // Check connection
    let block = provider.get_block_number().await?;
    info!("Connected to chain, current block: {}", block);

    // Initialize price service (fetch live price from DeFiLlama)
    let price_service = if let Some(prices_path) = &args.prices {
        let native_price = get_fallback_price(&args.chain);
        info!("Loading prices from JSON file, using fallback native price: ${}", native_price);
        PriceService::from_json(prices_path, native_price)?
    } else {
        info!("Fetching live price from DeFiLlama...");
        PriceService::with_live_price(&args.chain).await
    };

    info!("Using native token price: ${:.2}", price_service.native_price);

    // Extract contracts
    let contracts = extract_contracts(
        &provider,
        &args.chain,
        args.min_balance as f64,
        &price_service,
        &block_tag,
    )
    .await?;

    // Save to SQLite
    save_to_sqlite(&contracts, &args.chain, &args.output)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_snapshot_block_and_prices_path() {
        let args = Args::try_parse_from([
            "snapshot-extractor",
            "--rpc",
            "http://localhost:8545",
            "--chain",
            "bsc",
            "--min-balance",
            "250000",
            "--output",
            "/tmp/targets.db",
            "--block",
            "4815162342",
            "--prices",
            "/tmp/prices.json",
        ])
        .expect("args should parse");

        assert_eq!(args.chain, "bsc");
        assert_eq!(args.rpc, "http://localhost:8545");
        assert_eq!(args.min_balance, 250000);
        assert_eq!(args.output, "/tmp/targets.db");
        assert_eq!(args.block, Some(4_815_162_342));
        assert_eq!(args.prices, Some("/tmp/prices.json".to_string()));
    }

    #[test]
    fn formats_snapshot_block_as_rpc_tag() {
        assert_eq!(block_tag_from_snapshot(None), "latest");
        assert_eq!(block_tag_from_snapshot(Some(48_151_623)), "0x2debc47");
    }

    #[test]
    fn maps_known_chain_prices_and_coin_ids() {
        assert_eq!(get_defillama_coin_id("bsc"), "coingecko:binancecoin");
        assert_eq!(get_defillama_coin_id("base"), "coingecko:ethereum");
        assert_eq!(get_defillama_coin_id("unknown"), "coingecko:ethereum");
        assert_eq!(get_fallback_price("polygon"), 0.5);
        assert_eq!(get_fallback_price("unknown"), 1.0);
    }

    #[test]
    fn computes_native_value_from_wei() {
        let price_service = PriceService {
            _prices: HashMap::new(),
            native_price: 600.0,
        };

        assert_eq!(
            price_service.get_native_value_usd("2000000000000000000"),
            1200.0
        );
        assert_eq!(price_service.get_native_value_usd("not-a-number"), 0.0);
    }

    #[test]
    fn save_to_sqlite_lowercases_address_and_upserts() {
        let db_path = std::env::temp_dir().join(format!(
            "snapshot-extractor-test-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let db_path_str = db_path.to_string_lossy().to_string();
        let contracts = vec![ContractInfo {
            address: "0xABCDEF0000000000000000000000000000000000".to_string(),
            balance_wei: "1000000000000000000".to_string(),
            balance_usd: 600.0,
            code_hash: "0xhash1".to_string(),
        }];

        save_to_sqlite(&contracts, "bsc", &db_path_str).expect("first save should work");
        let updated = vec![ContractInfo {
            address: "0xabcdef0000000000000000000000000000000000".to_string(),
            balance_wei: "2000000000000000000".to_string(),
            balance_usd: 1200.0,
            code_hash: "0xhash2".to_string(),
        }];
        save_to_sqlite(&updated, "bsc", &db_path_str).expect("upsert should work");

        let conn = Connection::open(&db_path).expect("db should open");
        let row: (String, f64, String, String, i64) = conn
            .query_row(
                "SELECT address, balance_usd, balance_native, code_hash,
                        (SELECT COUNT(*) FROM contracts)
                 FROM contracts WHERE chain = 'bsc'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("contract row should exist");

        assert_eq!(row.0, "0xabcdef0000000000000000000000000000000000");
        assert_eq!(row.1, 1200.0);
        assert_eq!(row.2, "2000000000000000000");
        assert_eq!(row.3, "0xhash2");
        assert_eq!(row.4, 1);

        drop(conn);
        std::fs::remove_file(db_path).expect("test db should be removed");
    }
}
