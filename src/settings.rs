use crate::{Model, Msg, message::Message};
use std::rc::Rc;
use yew::prelude::*;
use yew::services::storage::{Area, StorageService};

pub struct Settings {
    pub store_hash: bool,
    pub keylogger_protection: bool,
    link: Rc<ComponentLink<Model>>,
}

impl Settings {
    pub fn load(link: Rc<ComponentLink<Model>>) -> Settings {
        if let Ok(storage) = StorageService::new(Area::Local) {
            Settings {
                store_hash: storage
                    .restore::<Result<String, _>>("settings:store_hash")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                keylogger_protection: storage
                    .restore::<Result<String, _>>("settings:keylogger_protection")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                link,
            }
        } else {
            Settings {
                store_hash: true,
                keylogger_protection: false,
                link,
            }
        }
    }

    pub fn save(&self) -> bool {
        if let Ok(mut storage) = StorageService::new(Area::Local) {
            storage.store("settings:store_hash", Ok(self.store_hash.to_string()));
            storage.store(
                "settings:keylogger_protection",
                Ok(self.keylogger_protection.to_string()),
            );
            return true;
        }
        false
    }
}

impl Renderable for Settings {
    fn render(&self) -> Html {
        html! {
            <main>
                {"Settings:"}<br />
                <br/>
                <Message level="warning">
                    {"Settings can be modified by anyone with access to this computer."}
                </Message>
                <br/>
                <label class="checkbox">
                    <input type="checkbox" name="check" value="check" checked=self.store_hash id="settings-store-hash"/>
                    <span>{"Store a hash of my master password (very secure, recommended)"}</span>
                </label>
                <br/>
                <label class="checkbox">
                    <input type="checkbox" name="check" value="check" checked=self.keylogger_protection  id="settings-keylogger-protection"/>
                    <span>{"Keylogger protection"}</span>
                </label>
                <br/>
                <br/>
                <button class="big_button" onclick=self.link.callback(|_| Msg::Settings)>{ "Save" }</button><br />
            </main>
        }
    }
}
