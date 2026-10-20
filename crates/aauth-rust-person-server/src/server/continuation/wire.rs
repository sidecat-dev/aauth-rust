use super::*;
pub(super) fn encode(r: &Response<Vec<u8>>) -> Result<Value, Failure> {
    let mut headers = serde_json::Map::new();
    for name in ["content-type", "cache-control", "retry-after", "date"] {
        if let Some(v) = r.headers().get(name) {
            headers.insert(
                name.into(),
                json!(v.to_str().map_err(|_| Failure::internal())?),
            );
        }
    }
    Ok(
        json!({"status":r.status().as_u16(),"headers":headers,"body":std::str::from_utf8(r.body()).map_err(|_|Failure::internal())?}),
    )
}
pub(super) fn decode(v: &Value) -> Result<Response<Vec<u8>>, Failure> {
    let status = v["status"]
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .and_then(|v| StatusCode::from_u16(v).ok())
        .ok_or_else(Failure::internal)?;
    let mut r = Response::builder().status(status);
    for (k, v) in v["headers"].as_object().ok_or_else(Failure::internal)? {
        r = r.header(k, v.as_str().ok_or_else(Failure::internal)?);
    }
    r.body(
        v["body"]
            .as_str()
            .ok_or_else(Failure::internal)?
            .as_bytes()
            .to_vec(),
    )
    .map_err(|_| Failure::internal())
}
