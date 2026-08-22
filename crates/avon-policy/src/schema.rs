use schemars::schema_for;

use crate::spec::PolicySpec;

pub fn json_schema() -> serde_json::Value {
    let schema = schema_for!(PolicySpec);
    serde_json::to_value(schema).unwrap_or(serde_json::json!({}))
}
