use std::collections::HashMap;
use std::fmt::Display;
use std::vec::Vec;

#[derive(Debug)]
pub struct JSONError {
    pub error: String,
}

impl JSONError {
    fn new(error: &str) -> Self {
        JSONError {
            error: String::from(error),
        }
    }
}

impl Display for JSONError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.error.as_str())?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum JSONValue {
    Object(HashMap<String, JSONValue>),
    String(String),
    Integer(i64),
    Float(f64),
    Null,
    Boolean(bool),
    List(Vec<JSONValue>),
}

type JSONResult<T> = Result<T, JSONError>;

fn trim_left(buffer: &mut Vec<u8>, position: &mut usize) {
    loop {
        match buffer.get(*position) {
            Some(x) => {
                if x.is_ascii_whitespace() {
                    *position += 1;
                } else {
                    return;
                }
            }
            _ => {
                return;
            }
        }
    }
}

pub fn parse_document(buffer: &mut Vec<u8>, position: &mut usize) -> JSONResult<JSONValue> {
    trim_left(buffer, position);

    match buffer.get(*position) {
        Some(b'{') => {
            *position += 1;
            return Ok(JSONValue::Object(parse_object(buffer, position)?));
        }
        Some(b'[') => {
            *position += 1;
            return Ok(JSONValue::List(parse_list(buffer, position)?));
        }
        _ => {
            return Err(JSONError::new(
                format!("Invalid syntax at position {}: expecting {{ or [", position).as_str(),
            ));
        }
    }
}

fn parse_object(
    buffer: &mut Vec<u8>,
    position: &mut usize,
) -> JSONResult<HashMap<String, JSONValue>> {
    let mut obj = HashMap::new();

    let mut found_separator = false;

    loop {
        trim_left(buffer, position);
        if !found_separator && buffer.get(*position) == Some(&b'}') {
            *position += 1;
            return Ok(obj);
        }

        let key = parse_string(buffer, position)?;

        trim_left(buffer, position);
        if buffer.get(*position) == Some(&b':') {
            *position += 1;
        } else {
            return Err(JSONError::new(
                format!("Invalid syntax at position {}: expecting :", position).as_str(),
            ));
        }

        let value = parse_value(buffer, position)?;

        obj.insert(key, value);

        trim_left(buffer, position);
        if buffer.get(*position) == Some(&b',') {
            *position += 1;
            found_separator = true;
        } else {
            found_separator = false;
        }
    }
}

fn parse_string(buffer: &mut Vec<u8>, position: &mut usize) -> JSONResult<String> {
    trim_left(buffer, position);

    if buffer.get(*position) == Some(&b'"') {
        *position += 1;
    } else {
        return Err(JSONError::new(
            format!("Invalid syntax at position {}: expecting \"", position).as_str(),
        ));
    }

    let mut str: Vec<u8> = Vec::new();

    loop {
        let c = buffer.get(*position);
        match c {
            Some(b'"') => {
                *position += 1;
                match String::from_utf8(str) {
                    Ok(x) => return Ok(x),
                    Err(_e) => {
                        return Err(JSONError::new(
                            format!("Invalid string ending at {}", position).as_str(),
                        ));
                    }
                }
            }
            Some(b'\\') =>{
                *position += 1;
                
                match buffer.get(*position) {
                    Some(b'u') => {
                        *position += 1;
                        let mut hex: Vec<u8> = Vec::new();
                        for _i in 0..4 {
                            match buffer.get(*position) {
                                Some(x) => {
                                    *position += 1;
                                    hex.push(*x);
                                }
                                None => {
                                    return Err(JSONError::new(
                                        format!("Invalid syntax at position {}: expecting escape sequence", position).as_str(),
                                    ));
                                }
                            }
                        }
                        let hex = match String::from_utf8(hex) {
                            Ok(x) => x,
                            Err(_e) => {
                                return Err(JSONError::new(
                                    format!("Invalid string ending at {}", position).as_str(),
                                ));
                            }
                        };

                        let hex = match u32::from_str_radix(hex.as_str(), 16) {
                            Ok(x) => x,
                            Err(_e) => {
                                return Err(JSONError::new(
                                    format!("Invalid string ending at {}", position).as_str(),
                                ));
                            }
                        };
                        match std::char::from_u32(hex) {
                            Some(x) => str.push(x as u8),
                            None => {
                                return Err(JSONError::new(
                                    format!("Invalid string ending at {}", position).as_str(),
                                ));
                            }
                        }
                    }
                    _ => {
                        str.push(b'\\');
                    }
                }
                
            }
            Some(x) => {
                *position += 1;
                str.push(*x);
            }
            None => {
                return Err(JSONError::new(
                    format!("Invalid syntax at position {}: expecting \"", position).as_str(),
                ));
            }
        }
    }
}

fn parse_value(buffer: &mut Vec<u8>, position: &mut usize) -> JSONResult<JSONValue> {
    trim_left(buffer, position);

    match buffer.get(*position) {
        Some(b'{') => {
            *position += 1;
            return Ok(JSONValue::Object(parse_object(buffer, position)?));
        }
        Some(b'[') => {
            *position += 1;
            return Ok(JSONValue::List(parse_list(buffer, position)?));
        }
        Some(b'"') => {
            return Ok(JSONValue::String(parse_string(buffer, position)?));
        }
        Some(_x) => {
            return Ok(parse_literal(buffer, position)?);
        }
        _ => {
            return Err(JSONError::new("Boh"));
        }
    }
}

fn parse_literal(buffer: &mut Vec<u8>, position: &mut usize) -> JSONResult<JSONValue> {
    let mut ans: Vec<u8> = Vec::new();

    loop {
        match buffer.get(*position) {
            Some(x) => {
                if x.is_ascii_whitespace() || *x == b',' || *x == b'}' || *x == b']' {
                    break;
                } else {
                    ans.push(*x);
                    *position += 1;
                }
            }
            _ => {
                return Err(JSONError::new("Unexpected end of file"));
            }
        }
    }

    let ans = match String::from_utf8(ans) {
        Ok(x) => x,
        Err(_x) => {
            return Err(JSONError::new(
                format!("Invalid string ending at {}", position).as_str(),
            ));
        }
    };

    if ans == "true" {
        return Ok(JSONValue::Boolean(true));
    } else if ans == "false" {
        return Ok(JSONValue::Boolean(false));
    } else if ans == "null" {
        return Ok(JSONValue::Null);
    } else if ans.contains(".") {
        let x = ans.parse::<f64>();
        if x.is_ok() {
            return Ok(JSONValue::Float(x.unwrap()));
        }
    } else {
        let x = ans.parse::<i64>();
        if x.is_ok() {
            return Ok(JSONValue::Integer(x.unwrap()));
        }
    }

    return Err(JSONError::new(format!("Invalid literal: {}", ans).as_str()));
}

fn parse_list(buffer: &mut Vec<u8>, position: &mut usize) -> JSONResult<Vec<JSONValue>> {
    let mut list = Vec::new();

    let mut found_separator = false;

    loop {
        trim_left(buffer, position);
        if !found_separator && buffer.get(*position) == Some(&b']') {
            *position += 1;
            return Ok(list);
        }

        let value = parse_value(buffer, position)?;

        list.push(value);

        trim_left(buffer, position);
        if buffer.get(*position) == Some(&b',') {
            *position += 1;
            found_separator = true;
        } else {
            found_separator = false;
        }
    }
}