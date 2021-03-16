#![recursion_limit = "1024"]
#![allow(clippy::large_enum_variant)]
use sha3::{Digest, Sha3_512};
use std::rc::Rc;
use wasm_bindgen::JsCast;
use web_sys::*;
use yew::prelude::*;
use yew::services::storage::{Area, StorageService};

#[macro_use]
mod util;
mod foldable_info;
mod generation;
mod message;
mod psl;
mod settings;
use foldable_info::*;
use generation::*;
use message::*;
use psl::*;
use settings::*;
use util::*;
mod keylogger_protection;
use keylogger_protection::*;

#[derive(PartialEq)]
pub enum MasterPasswordCheck {
    Checked,
    Missing,
    Unchecked,
}

impl Renderable for MasterPasswordCheck {
    fn render(&self) -> Html {
        match self {
            MasterPasswordCheck::Checked => html! {
                <Message level="success">{"Your master password is correct."}</Message>
            },
            MasterPasswordCheck::Unchecked => html! {
                <Message level="warning">{"Your master password is not checked (see settings)."}</Message>
            },
            MasterPasswordCheck::Missing => html! {
                <Message level="danger">{"Your master password seems wrong as it was never used on this computer before."}</Message>
            },
        }
    }
}

#[derive(PartialEq)]
pub enum Page {
    EnterMasterPassword,
    EnterUrl {
        master_password: String,
        master_password_check: MasterPasswordCheck,
    },
    DisplayPasswords {
        master_password: String,
        host: String,
        domain: Domain,
        show_more: bool,
        generated_passwords: [String; 6],
        accessible_password: usize,
    },
    Sorry(String),
}

pub struct Model {
    link: Rc<ComponentLink<Self>>,
    settings: Settings,
    settings_open: bool,
    keylogger_protector: KeyloggerProtector,
    page: Page,
}

pub enum Msg {
    Next,
    Back,
    PslResponse {
        host: String,
        result: Result<String, &'static str>,
    },
    InputMasterPassword(String),
    Settings,
    CopyPassword(usize),
    Noop,
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let link = Rc::new(link);
        let settings = Settings::load(Rc::clone(&link));
        let mut keylogger_protector = KeyloggerProtector::new();
        if settings.keylogger_protection {
            keylogger_protector.enable();
        }

        Self {
            link: Rc::clone(&link),
            page: Page::EnterMasterPassword,
            keylogger_protector,
            settings,
            settings_open: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Next => match &self.page {
                Page::EnterMasterPassword { .. } => {
                    let master_password = window()
                        .unwrap()
                        .document()
                        .unwrap()
                        .get_element_by_id("password_input")
                        .unwrap()
                        .dyn_into::<HtmlInputElement>()
                        .unwrap()
                        .value();

                    if master_password.is_empty() {
                        return false;
                    }

                    let mut hasher = Sha3_512::new();
                    hasher.update(format!("{}password", master_password));
                    let result = hasher.finalize();
                    let hashed_password: String = hex::encode(result[..].to_vec());

                    let storage = StorageService::new(Area::Local).expect("storage unavailable");
                    let last: Result<String, _> = storage.restore(&hashed_password);

                    let master_password_check = match (last.is_ok(), self.settings.store_hash) {
                        (true, _) => MasterPasswordCheck::Checked,
                        (false, true) => MasterPasswordCheck::Missing,
                        (false, false) => MasterPasswordCheck::Unchecked,
                    };

                    self.page = Page::EnterUrl {
                        master_password,
                        master_password_check,
                    };
                    true
                }
                Page::EnterUrl { master_password, .. } => {
                    let url = window()
                        .unwrap()
                        .document()
                        .unwrap()
                        .get_element_by_id("url_input")
                        .unwrap()
                        .dyn_into::<HtmlInputElement>()
                        .unwrap()
                        .value();

                    if url.is_empty() {
                        return false;
                    }

                    let host: String = if let Ok(url) = Url::new(&url) { url.host() } else { url };

                    let domain = Domain::check(Rc::clone(&self.link), host.clone());

                    if self.settings.store_hash {
                        let mut storage = StorageService::new(Area::Local).expect("storage unavailable");
                        let mut hasher = Sha3_512::new();
                        hasher.update(format!("{}password", master_password));
                        let result = hasher.finalize();
                        let hashed_password: String = hex::encode(result[..].to_vec());
                        storage.store(&hashed_password, Ok(String::new()));
                    }

                    let generated_passwords = [
                        generate_password(&master_password, domain.as_ref(), true, false, true),
                        generate_password(&master_password, domain.as_ref(), true, false, false),
                        generate_password(&master_password, domain.as_ref(), true, true, true),
                        generate_password(&master_password, domain.as_ref(), false, false, true),
                        generate_password(&master_password, domain.as_ref(), false, false, false),
                        generate_password(&master_password, domain.as_ref(), false, true, true),
                    ];

                    self.page = Page::DisplayPasswords {
                        master_password: master_password.clone(),
                        host,
                        domain,
                        generated_passwords,
                        accessible_password: 0,
                        show_more: false,
                    };
                    true
                }
                Page::DisplayPasswords {
                    master_password,
                    host,
                    generated_passwords,
                    accessible_password,
                    domain,
                    ..
                } => {
                    self.page = Page::DisplayPasswords {
                        master_password: master_password.clone(),
                        host: host.clone(),
                        domain: domain.clone(),
                        generated_passwords: generated_passwords.clone(),
                        accessible_password: *accessible_password,
                        show_more: true,
                    };
                    true
                }
                Page::Sorry(_) => false,
            },
            Msg::Settings => {
                if self.settings_open {
                    let window = window().unwrap();
                    let document = window.document().unwrap();
                    let store_hash = document
                        .get_element_by_id("settings-store-hash")
                        .unwrap()
                        .dyn_into::<HtmlInputElement>()
                        .unwrap()
                        .checked();
                    let keylogger_protection = document
                        .get_element_by_id("settings-keylogger-protection")
                        .unwrap()
                        .dyn_into::<HtmlInputElement>()
                        .unwrap()
                        .checked();

                    self.settings.store_hash = store_hash;
                    self.settings.keylogger_protection = keylogger_protection;
                    self.settings.save();

                    if self.settings.keylogger_protection && !self.keylogger_protector.is_enabled() {
                        self.keylogger_protector.enable();
                    } else if !self.settings.keylogger_protection && self.keylogger_protector.is_enabled() {
                        self.keylogger_protector.disable();
                    }
                }
                self.settings_open = !self.settings_open;
                true
            }
            Msg::CopyPassword(idx) => {
                if let Page::DisplayPasswords {
                    accessible_password,
                    generated_passwords,
                    ..
                } = &mut self.page
                {
                    if idx <= *accessible_password {
                        let document = window().unwrap().document().unwrap();
                        let element = document.create_element("textarea").unwrap();
                        element.set_attribute("readonly", "").unwrap();
                        element.set_attribute("style", "position: absolute; left: -9999px").unwrap();

                        let element: HtmlTextAreaElement = element.dyn_into().unwrap();
                        let document: HtmlDocument = document.dyn_into().unwrap();
                        let body = document.body().unwrap();
                        element.set_value(&generated_passwords[idx]);
                        body.append_child(&element).unwrap();
                        element.select();
                        document.exec_command("copy").unwrap();
                        body.remove_child(&element).unwrap();
                        if *accessible_password == idx {
                            *accessible_password += 1;
                        }
                    } else {
                        panic!("Error: this password can't be copied now");
                    }
                }
                true
            }
            Msg::Back => {
                match &self.page {
                    Page::EnterMasterPassword { .. } => (),
                    Page::EnterUrl { .. } => self.page = Page::EnterMasterPassword,
                    Page::DisplayPasswords { master_password, .. } => {
                        self.page = Page::EnterUrl {
                            master_password: master_password.clone(),
                            master_password_check: MasterPasswordCheck::Checked,
                        }
                    }
                    Page::Sorry(_) => self.page = Page::EnterMasterPassword,
                }
                true
            }
            Msg::InputMasterPassword(password) => self.keylogger_protector.handle_input(password),
            Msg::PslResponse { host, result } => {
                if let Page::DisplayPasswords {
                    domain,
                    host: expected_host,
                    generated_passwords,
                    master_password,
                    ..
                } = &mut self.page
                {
                    log!("got answer");
                    if host == *expected_host {
                        match result {
                            Ok(checked_domain) => *domain = Domain::Checked(checked_domain),
                            Err(e) => domain.set_uncheckable(e),
                        }

                        *generated_passwords = [
                            generate_password(&master_password, domain.as_ref(), true, false, true),
                            generate_password(&master_password, domain.as_ref(), true, false, false),
                            generate_password(&master_password, domain.as_ref(), true, true, true),
                            generate_password(&master_password, domain.as_ref(), false, false, true),
                            generate_password(&master_password, domain.as_ref(), false, false, false),
                            generate_password(&master_password, domain.as_ref(), false, true, true),
                        ];
                    } else {
                        log!("Host changed...");
                    }
                }
                true
            }
            Msg::Noop => false,
        }
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        if self.settings_open {
            return self.settings.render();
        }

        // TODO <a target="_blank" href="https://icones8.fr/icons/set/settings">Paramètres icon</a> icon by <a target="_blank" href="https://icones8.fr">Icons8</a>

        match &self.page {
            Page::EnterMasterPassword => {
                html! {
                    <main>
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Welcome!"}<br />
                        {self.keylogger_protector.render()}
                        <br />
                        <div class="input_container">
                            <input class="big-input" type="password" id="password_input" placeholder="Password" required=true oninput=self.link.callback(|data: InputData| Msg::InputMasterPassword(data.value)) onkeypress=self.link.callback(|event: KeyboardEvent| { if event.code() == "Enter" { Msg::Next } else { Msg::Noop }
                            })/>
                            <label class="label" for="password_input">{"Password"}</label>
                        </div><br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button><br />
                        <br />
                        <FoldableInfo title="How does it work?">
                            {"In opposition to any other password manager, this one will never store your passwords. Your passwords will be regenerated each time you need them. The generated passwords will never change, wherever and whenever you are. That means that you can get all your passwords on different devices without needing to synchronize or exchange any data. All your passwords will be generated from your master password to make them unique. They will also be different for every website. Thanks to a complex password generation, it is not possible to get your master password from a generated password. That means that if a website is compromised, and a generated password is stolen, the hacker will never be able to get your master password. Thanks to this design, this is the most secure password manager software in the world, as long as your master password remains strong and secret. "}
                        </FoldableInfo>
                        <br/>
                        <FoldableInfo title="How can I get a master password?">
                            {"Your master password will be the root of every generated password. It must be very strong because cracking your master password means cracking every generated password. It should be random."}
                            {{
                            let mut master_password = String::new();
                            while master_password.len() < 14 { // only bytes char so its ok
                                let number: u8 = get_random_between(32, 127);
                                if (123..=126).contains(&number) || (91..=96).contains(&number) || (58..=64).contains(&number) || (32..=47).contains(&number) {
                                    continue
                                }
                                master_password.push(number as char);
                            }
                            format!("Here is a master password generated just for you! {}", master_password)}}
                        </FoldableInfo>
                    </main>
                }
            }
            Page::EnterUrl {
                master_password_check, ..
            } => {
                html! {
                    <main>
                        {master_password_check.render()}
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Enter the URL of the website on which you want to get a password."}<br />
                        <br />
                        <div class="input_container">
                            <input class="big-input" type="text" id="url_input" value="" placeholder="URL" required=true onkeypress=self.link.callback(|event: KeyboardEvent| { if event.code() == "Enter" { Msg::Next } else { Msg::Noop }}) />
                            <label class="label" for="url_input">{"URL"}</label>
                        </div><br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button><br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Back)>{ "Back" }</button>
                    </main>
                }
            }
            Page::DisplayPasswords {
                domain,
                show_more: false,
                ..
            } => {
                html! {
                    <main>
                        {domain.render()}
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Press the button to copy your password for "}<a href=format!("https://{}", domain.as_ref())>{domain.as_ref()}</a>{"."}<br/>
                        <br/>
                        <button class="big_button" onclick=self.link.callback(|_| Msg::CopyPassword(0))>{"Copy password"}</button><br/>
                        <br/>
                        {"If this password is rejected, please try the \"Help\" button below."}<br/>
                        <br/>
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Next)>{ "Help" }</button><br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Back)>{ "Back" }</button>
                    </main>
                }
            }
            Page::DisplayPasswords {
                show_more: true,
                accessible_password,
                ..
            } => {
                let mut buttons = Vec::new();
                for idx in 0..6 {
                    buttons.push(if *accessible_password >= idx {
                        html! {
                            <div>
                                <button class="big_button" onclick=self.link.callback(move |_| Msg::CopyPassword(idx))>{format!("Password {}", idx)}</button><br/>
                                <br/>
                            </div>
                        }
                    } else {
                        html! {
                            <div><button class="big_button disabled_button">{"Try the password above"}</button><br/><br/></div>
                        }
                    });
                }
                html! {
                    <main>
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Try every password of this list in the correct order."}<br/>
                        <br/>
                        {
                            for buttons
                        }
                        {
                            if *accessible_password > 5 {
                                html! {
                                    <Message level="info">
                                        {"If none of these passwords above is working and you are trying to sign up, please find a password by yourself. You can send me an email (at mubelotix@gmail.com) to report the website, and I will see if I can do something. This website is weakly configured, and I can't do anything for that. If you are trying to sign in, either you didn't enter the correct password or the correct URL, or you created a password by yourself on this website."}
                                    </Message>
                                }
                            } else {
                                html!{}
                            }
                        }
                        <br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Back)>{ "Back" }</button>
                    </main>
                }
            }
            Page::Sorry(message) => {
                html! {
                    <main id="sorry">
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        <link rel="stylesheet"/>
                        <h2> {"Sorry, something is not working"} </h2>
                        <br/>
                        {message}<br/>
                        <br/>
                        {"You can contact "}<a href="mailto:mubelotix@gmail.com">{"me"}</a><br/>
                        <br/>
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Back)>{ "Restart" }</button>
                    </main>
                }
            }
        }
    }
}

fn main() {
    yew::initialize();
    App::<Model>::new().mount_to_body();
    yew::run_loop();
}
