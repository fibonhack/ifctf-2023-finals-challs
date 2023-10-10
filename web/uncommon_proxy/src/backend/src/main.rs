mod json;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
};

use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::env::var;
use uuid::Uuid;

type Db = Arc<Mutex<HashMap<String, String>>>;

#[derive(Deserialize)]
struct PostData {
    data: String,
}

fn admin(
    db: &web::Data<Db>,
    _obj: &HashMap<String, json::JSONValue>,
) -> Result<String, (u32, &'static str)> {
    match db.lock() {
        Ok(db) => {
            let result : Vec<String>= db.iter().map(|(key, _value)| key.clone()).collect();
            return Ok(result.join(","));
        }
        Err(_) => return Err((500, &(""))),
    }
}

fn add_note(
    db: &web::Data<Db>,
    obj: &HashMap<String, json::JSONValue>,
) -> Result<String, (u32, &'static str)> {
    match obj.get("content") {
        Some(x) => match x {
            json::JSONValue::String(x) => match db.lock() {
                Ok(mut db) => {
                    let key = Uuid::new_v4().to_string();
                    db.insert(key.clone(), x.clone());
                    return Ok(key);
                }
                Err(_) => return Err((500, &(""))),
            },
            _ => return Err((400, &("Invalid content"))),
        },
        _ => return Err((400, &("missing content"))),
    }
}

fn get_note(
    db: &web::Data<Db>,
    obj: &HashMap<String, json::JSONValue>,
) -> Result<String, (u32, &'static str)> {
    match obj.get("note_id") {
        Some(x) => match x {
            json::JSONValue::String(x) => match db.lock() {
                Ok(db) => match db.get(x) {
                    Some(x) => Ok(x.clone()),
                    None => Err((404, &("Note not found"))),
                },
                Err(_) => Err((500, &(""))),
            },
            _ => Err((400, &("Invalid note_id"))),
        },
        _ => Err((400, &("note_id not found"))),
    }
}

fn dispatcher(
    db: &web::Data<Db>,
    obj: &HashMap<String, json::JSONValue>,
) -> Result<String, (u32, &'static str)> {
    match obj.get("endpoint") {
        Some(x) => match x {
            json::JSONValue::String(x) => match x.as_str() {
                "admin" => admin(&db, &obj),
                "add_note" => add_note(&db, &obj),
                "get_note" => get_note(&db, &obj),
                _ => Err((404, &("endpoint not found"))),
            },
            _ => Err((400, &("Invalid endpoint"))),
        },
        _ => Err((400, &(""))),
    }
}

#[post("/")]
async fn index(db: web::Data<Db>, post_data: web::Form<PostData>) -> impl Responder {
    let mut position: usize = 0;
    let mut buffer = post_data.data.clone().into_bytes();

    match json::parse_document(&mut buffer, &mut position) {
        Ok(obj) => match obj {
            json::JSONValue::Object(obj) => match dispatcher(&db, &obj) {
                Ok(x) => HttpResponse::Ok().body(x),
                Err((code, msg)) => match code {
                    400 => HttpResponse::BadRequest().body(msg),
                    404 => HttpResponse::NotFound().body(msg),
                    _ => HttpResponse::InternalServerError().body(msg),
                },
            },
            _ => HttpResponse::NotFound().finish(),
        },
        _ => HttpResponse::NotFound().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Backend wake up");

    let db = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    db.lock()
        .unwrap()
        .insert(Uuid::new_v4().to_string(), var("FLAG").unwrap());

    let cleanup_thread_db = db.clone();
    thread::spawn(move || loop {
        match cleanup_thread_db.lock() {
            Ok(mut db) => {
                if db.len() > 100 {
                    db.clear();
                    db.insert(Uuid::new_v4().to_string(), var("FLAG").unwrap());
                    println!("DB cleaned");
                }
            }
            Err(_) => eprintln!("Error in db lock"),
        }

        thread::sleep(std::time::Duration::from_secs(30));
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(index)
    })
    .bind(("0.0.0.0", 8081))?
    .run()
    .await
}
