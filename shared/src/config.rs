use std::env;
use std::str::FromStr;

pub fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

pub fn env_required(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} 环境变量未设置"))
}

pub fn env_parse<T: FromStr>(key: &str, default: T) -> T {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
