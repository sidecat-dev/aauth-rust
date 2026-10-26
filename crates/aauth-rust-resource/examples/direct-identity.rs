mod support;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for observation in support::run()? {
        println!(
            "{}: {} {}",
            observation.scenario, observation.status, observation.detail
        );
    }
    Ok(())
}
