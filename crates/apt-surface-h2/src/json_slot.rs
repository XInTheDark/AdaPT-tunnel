use serde_json::{Map, Value};

pub(crate) fn set_nested_string(
    root: &mut Value,
    path: &[&str],
    value: String,
) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("empty json slot path");
    }
    let mut current = root;
    for segment in &path[..path.len() - 1] {
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        let object = current
            .as_object_mut()
            .ok_or("json slot path does not resolve to an object")?;
        current = object
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    let object = current
        .as_object_mut()
        .ok_or("json slot path does not resolve to an object")?;
    object.insert(path[path.len() - 1].to_string(), Value::String(value));
    Ok(())
}

pub(crate) fn get_nested_string<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    if path.is_empty() {
        return None;
    }
    let mut current = root;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}
