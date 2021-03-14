use js_sys::{Array, Reflect::get};
use std::{
    convert::{AsRef, TryInto},
    rc::Rc,
};
use wasm_bindgen_futures::JsFuture;
use web_sys::{RequestInit, Response};
use yew::prelude::*;

#[derive(Debug, PartialEq, Clone)]
pub enum Domain {
    Checking(String),
    Checked(String),
    Uncheckable(String, &'static str),
}

impl Domain {
    pub(crate) fn check(link: Rc<ComponentLink<crate::Model>>, host: String) -> Domain {
        let parts = host.split('.').collect::<Vec<&str>>();
        match parts.len() {
            1 | 2 => Domain::Checked(host),
            len => {
                let host2 = host.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match request_psl(host2.clone()).await {
                        Ok(domain) => {
                            link.send_message(crate::Msg::PslResponse {
                                host: host2.clone(),
                                result: Ok(domain),
                            })
                        }
                        Err(error) => {
                            link.send_message(crate::Msg::PslResponse {
                                host: host2.clone(),
                                result: Err(error),
                            })
                        }
                    };
                });
                Domain::Checking(format!(
                    "{}.{}",
                    parts.get(len - 2).unwrap(),
                    parts.get(len - 1).unwrap()
                ))
            }
        }
    }

    pub fn set_uncheckable(&mut self, error: &'static str) {
        *self = Domain::Uncheckable(self.as_ref().to_string(), error);
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        match self {
            Domain::Checked(domain) => domain.as_ref(),
            Domain::Checking(provisory_domain) => provisory_domain.as_ref(),
            Domain::Uncheckable(provisory_domain, _error) => provisory_domain.as_ref(),
        }
    }
}

pub async fn request_psl<'a>(host: String) -> Result<String, &'static str> {
    let mut request: RequestInit = RequestInit::new();
    request.method("GET");

    let window = web_sys::window().unwrap();
    let response = match JsFuture::from(window.fetch_with_str_and_init(
        &format!(
            "https://dns.google/resolve?name={}.query.publicsuffix.zone&type=PTR",
            host
        ),
        &request,
    ))
    .await
    {
        Ok(response) => Response::from(response),
        Err(_) => {
            return Err("Failed to send DNS request.");
        }
    };
    let status = response.status() as u16;
    if status != 200 {
        return Err("Status is not 200.");
    }
    let response = match response.json() {
        Ok(text) => match JsFuture::from(text).await {
            Ok(text) => text,
            Err(_) => {
                return Err("Invalid response (awaited).");
            }
        },
        Err(_) => {
            return Err("Invalid response.");
        }
    };

    let status = get(&response, &"Status".into()).map_err(|_| "No Status field.")?;
    if status != 0 {
        return Err("Status is not 0.");
    }

    let trusted = get(&response, &"AD".into()).map_err(|_| "No AD field.")?;
    if trusted != true {
        return Err("Response cannot be trusted.");
    }

    let answers = get(&response, &"Answer".into()).map_err(|_| "No Answer field.")?;
    let answers: Array = answers.try_into().map_err(|_| "Answer is not an array.")?;

    if answers.length() != 2 {
        return Err("Expected 2 parts in answer.");
    }

    let suffix = get(&answers.get(1), &"data".into()).map_err(|_| "No data in second answer.")?;
    let mut suffix = suffix
        .as_string()
        .ok_or("Data is not a string in second answer.")?;
    if !suffix.ends_with('.') || suffix.len() <= 1 {
        return Err("Invalid response data.");
    }
    suffix.remove(suffix.len() - 1);

    if !host.ends_with(&suffix) {
        return Err("Response data does not match request.");
    }
    let prefix = host[..host.len() - (suffix.len() + 1)]
        .split('.')
        .last()
        .unwrap_or("");

    Ok(host[host.len() - (prefix.len() + 1 + suffix.len())..].to_string())
}
