mod monitor;
mod policy;
mod protect;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    log::info!("=== JarTight Shield Initialized ===");

    if !policy::is_admin() {
        log::error!("Access Denied: Run JarTight as Administrator to lock down database handles.");
        return Ok(());
    }

    if let Err(e) = protect::apply_initial_restrictions() {
        log::error!("Failed to apply boot restrictions: {}", e);
    }

    log::info!("Proactive process guard is now running...");
    monitor::start_monitoring().await?;

    Ok(())
}