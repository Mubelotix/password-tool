#![recursion_limit = "1024"]
use psl::request_psl;
use sha3::{Digest, Sha3_512};
use std::rc::Rc;
use string_tools::{get_all_after, get_all_before};
use wasm_bindgen::JsCast;
use web_sys::*;
use yew::prelude::*;
use yew::services::storage::{Area, StorageService};

#[macro_use]
mod util;
mod psl;
use psl::*;
use util::*;
mod keylogger_protection;
use keylogger_protection::*;

#[cfg(test)]
mod test {
    use super::extract_domain_name;
    use super::generate_password;

    #[test]
    fn test_password_did_not_changed() {
        assert_eq!(
            generate_password("testing", "example.com", true, false, true),
            "2d70dac574dbfa9aa025c3750657e70773d6b2a9b00f@*_BQF"
        );
    }

    #[test]
    fn url() {
        assert_eq!(
            &extract_domain_name("https://google.com").unwrap(),
            "google.com"
        );
        assert_eq!(&extract_domain_name("google.com").unwrap(), "google.com");
        assert_eq!(
            &extract_domain_name("https://google.com/test").unwrap(),
            "google.com"
        );
        assert_eq!(
            &extract_domain_name("http://mubelotix.dev/passwords").unwrap(),
            "mubelotix.dev"
        );
        assert_eq!(
            &extract_domain_name("https://test.mubelotix.dev/index.html").unwrap(),
            "mubelotix.dev"
        );
    }

    #[test]
    fn backward_compatibility_test() {
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, false, false),
            "00c7dfebc7943SOD"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, false, true),
            "00c7dfebc769*_BQ"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, true, false),
            "0199223235199105"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, true, true),
            "0199223235199105"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, false, false),
            "00c7dfebc769bc042ad64ed60d9447dcaeaf7e9cabef943SOD"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, false, true),
            "00c7dfebc769bc042ad64ed60d9447dcaeaf7e9cabef@*_BQF"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, true, false),
            "01992232351991051884422147821413148712201741751261"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, true, true),
            "01992232351991051884422147821413148712201741751261"
        );
    }
}

fn extract_domain_name(mut url: &str) -> Option<String> {
    url = if url.contains("://") {
        get_all_after(url, "://")
    } else {
        url
    };
    let mut url = String::from(get_all_before(url, "/"));
    let mut domain = String::new();

    while !url.is_empty() && !url.ends_with('.') {
        domain.insert(0, url.remove(url.len() - 1))
    }

    if !url.is_empty() && !domain.is_empty() {
        domain.insert(0, '.');
        url.remove(url.len() - 1);
    } else {
        return None;
    }

    while !url.is_empty() && !url.ends_with('.') {
        domain.insert(0, url.remove(url.len() - 1))
    }

    Some(domain)
}

fn generate_password(
    master_password: &str,
    domain: &str,
    big: bool,
    only_numbers: bool,
    special_chars: bool,
) -> String {
    let password_size = if big { 50 } else { 16 };

    let mut hasher = Sha3_512::new();

    let mut generated_password = master_password.to_string();
    generated_password.push_str("35Pqfs6FeEf545fD54");
    generated_password.push_str(domain);
    hasher.update(generated_password);
    let generated_password = hasher.finalize();

    let mut generated_password: String = if !only_numbers {
        if special_chars && !big {
            hex::encode(generated_password[..password_size / 2 - 2].to_vec())
        } else {
            hex::encode(generated_password[..password_size / 2 - 3].to_vec())
        }
    } else {
        let mut generated_password2 = String::new();
        for n in generated_password {
            generated_password2.push_str(&n.to_string());
        }
        let generated_password = generated_password2[..password_size].to_string();
        return generated_password;
    };

    if special_chars {
        if big {
            generated_password.push_str("@*_BQF");
        } else {
            generated_password.push_str("*_BQ");
        }
    } else {
        generated_password.push_str("943SOD");
    }

    generated_password
}

#[derive(PartialEq)]
pub enum Page {
    EnterMasterPassword {
        how_does_it_work: bool,
        how_to_get_mp: bool,
    },
    EnterUrl {
        master_password: String,
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

#[derive(PartialEq)]
pub enum Message {
    Success(String),
    Info(String),
    Warning(String),
    Danger(String),
}

impl Message {
    fn view(&self) -> Html {
        match self {
            Message::Success(message) => {
                html! {
                    <p class="success_message">
                        <b>{"Success: "}</b>
                        {message}
                    </p>
                }
            }
            Message::Info(message) => {
                html! {
                    <p class="info_message">
                        <b>{"Info: "}</b>
                        {message}
                    </p>
                }
            }
            Message::Warning(message) => {
                html! {
                    <p class="warning_message">
                        <b>{"Warning: "}</b>
                        {message}
                    </p>
                }
            }
            Message::Danger(message) => {
                html! {
                    <p class="danger_message">
                        <b>{"Danger: "}</b>
                        {message}
                    </p>
                }
            }
        }
    }
}

struct Settings {
    store_hash: bool,
    disallow_invalid_domains: bool,
    keylogger_protection: bool,
}

impl Settings {
    fn load() -> Option<Settings> {
        let storage = StorageService::new(Area::Local).ok()?;

        Some(Settings {
            store_hash: storage
                .restore::<Result<String, _>>("settings:store_hash")
                .ok()?
                .parse()
                .ok()?,
            disallow_invalid_domains: storage
                .restore::<Result<String, _>>("settings:disallow_invalid_domains")
                .ok()?
                .parse()
                .ok()?,
            keylogger_protection: storage
                .restore::<Result<String, _>>("settings:keylogger_protection")
                .ok()?
                .parse()
                .ok()?,
        })
    }

    fn save(&self) -> bool {
        if let Ok(mut storage) = StorageService::new(Area::Local) {
            storage.store("settings:store_hash", Ok(self.store_hash.to_string()));
            storage.store(
                "settings:disallow_invalid_domains",
                Ok(self.disallow_invalid_domains.to_string()),
            );
            storage.store(
                "settings:keylogger_protection",
                Ok(self.keylogger_protection.to_string()),
            );
            return true;
        }
        false
    }
}

struct Model {
    messages: Vec<Message>,
    link: Rc<ComponentLink<Self>>,
    settings: Settings,
    settings_open: bool,
    keylogger_protector: KeyloggerProtector,
    page: Page,
}

enum Msg {
    Next,
    Back,
    PslResponse {
        host: String,
        result: Result<String, &'static str>,
    },
    InputMasterPassword(String),
    Settings,
    CopyPassword(usize),
    ChangePanels(bool, bool),
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let messages = Vec::new();
        let settings = Settings::load().unwrap_or(Settings {
            store_hash: true,
            disallow_invalid_domains: true,
            keylogger_protection: false,
        });
        let mut keylogger_protector = KeyloggerProtector::new();
        if settings.keylogger_protection {
            keylogger_protector.enable();
        }

        Self {
            messages,
            link: Rc::new(link),
            page: Page::EnterMasterPassword {
                how_does_it_work: false,
                how_to_get_mp: false,
            },
            keylogger_protector,
            settings,
            settings_open: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Next => {
                self.messages = Vec::new();
                match &self.page {
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

                        let mut hasher = Sha3_512::new();
                        hasher.update(format!("{}password", master_password));
                        let result = hasher.finalize();
                        let hashed_password: String = hex::encode(result[..].to_vec());

                        let storage =
                            StorageService::new(Area::Local).expect("storage unavailable");
                        let last: Result<String, _> = storage.restore(&hashed_password);

                        if last.is_err() && self.settings.store_hash {
                            self.messages.push(Message::Danger(String::from("This master password has never been seen on this computer. Only continue if you are sure that the password is correct.")));
                        } else if !self.settings.store_hash {
                            self.messages.push(Message::Warning(String::from("This master password has not been verified. (disabled in your parameters)")));
                        } else if last.is_ok() {
                            self.messages.push(Message::Success(String::from(
                                "Your master password is correct.",
                            )));
                        }

                        self.page = Page::EnterUrl { master_password };
                        true
                    }
                    Page::EnterUrl { master_password } => {
                        let url = window()
                            .unwrap()
                            .document()
                            .unwrap()
                            .get_element_by_id("url_input")
                            .unwrap()
                            .dyn_into::<HtmlInputElement>()
                            .unwrap()
                            .value();

                        let host: String = if let Ok(url) = Url::new(&url) {
                            self.messages.push(Message::Success(format!(
                                "The password for the domain {} has been generated successfully.",
                                url.host()
                            )));
                            url.host()
                        } else {
                            url
                        };

                        let domain = Domain::check(Rc::clone(&self.link), host.clone());

                        if self.settings.store_hash {
                            let mut storage =
                                StorageService::new(Area::Local).expect("storage unavailable");
                            let mut hasher = Sha3_512::new();
                            hasher.update(format!("{}password", master_password));
                            let result = hasher.finalize();
                            let hashed_password: String = hex::encode(result[..].to_vec());
                            storage.store(&hashed_password, Ok(String::new()));
                        }

                        let generated_passwords = [
                            generate_password(&master_password, domain.as_ref(), true, false, true),
                            generate_password(
                                &master_password,
                                domain.as_ref(),
                                true,
                                false,
                                false,
                            ),
                            generate_password(&master_password, domain.as_ref(), true, true, true),
                            generate_password(
                                &master_password,
                                domain.as_ref(),
                                false,
                                false,
                                true,
                            ),
                            generate_password(
                                &master_password,
                                domain.as_ref(),
                                false,
                                false,
                                false,
                            ),
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
                }
            }
            Msg::Settings => {
                self.messages = Vec::new();
                if self.settings_open {
                    let window = window().unwrap();
                    let document = window.document().unwrap();
                    let store_hash = document
                        .get_element_by_id("settings-store-hash")
                        .unwrap()
                        .dyn_into::<HtmlInputElement>()
                        .unwrap()
                        .checked();
                    let disallow_invalid_domains = document
                        .get_element_by_id("settings-disallow-invalid-domains")
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

                    self.settings = Settings {
                        disallow_invalid_domains,
                        store_hash,
                        keylogger_protection,
                    };
                    self.settings.save();

                    if self.settings.keylogger_protection && !self.keylogger_protector.is_enabled()
                    {
                        self.keylogger_protector.enable();
                    } else if !self.settings.keylogger_protection
                        && self.keylogger_protector.is_enabled()
                    {
                        self.keylogger_protector.disable();
                    }
                } else {
                    self.messages.push(Message::Warning(String::from(
                        "The settings are shared with every users.",
                    )));
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
                        element
                            .set_attribute("style", "position: absolute; left: -9999px")
                            .unwrap();

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
                self.messages = Vec::new();
                match &self.page {
                    Page::EnterMasterPassword { .. } => (),
                    Page::EnterUrl { .. } => {
                        self.page = Page::EnterMasterPassword {
                            how_to_get_mp: false,
                            how_does_it_work: false,
                        }
                    }
                    Page::DisplayPasswords {
                        master_password, ..
                    } => {
                        self.page = Page::EnterUrl {
                            master_password: master_password.clone(),
                        }
                    }
                    Page::Sorry(_) => {
                        self.page = Page::EnterMasterPassword {
                            how_to_get_mp: false,
                            how_does_it_work: false,
                        }
                    }
                }
                true
            }
            Msg::InputMasterPassword(password) => self.keylogger_protector.handle_input(password),
            Msg::ChangePanels(how_does_it_work, how_to_get_mp) => {
                self.page = Page::EnterMasterPassword {
                    how_does_it_work,
                    how_to_get_mp,
                };
                true
            }
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
        }
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        let mut messages = self.messages.iter().collect::<Vec<&Message>>();
        messages.append(
            &mut self
                .keylogger_protector
                .get_messages(self.settings_open, &self.page),
        );
        let messages = messages.iter().map(|message| message.view());

        if self.settings_open {
            return html! {
                <main>
                    {"Settings:"}<br />
                    {for messages}
                    <br/>
                    <label class="checkbox">
                        <input type="checkbox" name="check" value="check" checked=self.settings.store_hash id="settings-store-hash"/>
                        <span>{"Store a hash of my master password (very secure, recommended)"}</span>
                    </label>
                    <br/>
                    <label class="checkbox">
                        <input type="checkbox" name="check" value="check" checked=self.settings.disallow_invalid_domains  id="settings-disallow-invalid-domains"/>
                        <span>{"Disallow invalid domains"}</span>
                    </label>
                    <br/>
                    <label class="checkbox">
                        <input type="checkbox" name="check" value="check" checked=self.settings.keylogger_protection  id="settings-keylogger-protection"/>
                        <span>{"Keylogger protection"}</span>
                    </label>
                    <br/>
                    <br/>
                    <button class="big_button" onclick=self.link.callback(|_| Msg::Settings)>{ "Save" }</button><br />
                </main>
            };
        }

        // TODO <a target="_blank" href="https://icones8.fr/icons/set/settings">Paramètres icon</a> icon by <a target="_blank" href="https://icones8.fr">Icons8</a>

        match &self.page {
            Page::EnterMasterPassword {
                how_does_it_work,
                how_to_get_mp,
            } => {
                let how_does_it_work: bool = *how_does_it_work;
                let how_to_get_mp: bool = *how_to_get_mp;
                html! {
                    <main>
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Welcome!"}<br />
                        {for messages}
                        <br />
                        <div class="input_container">
                            <input class="big-input" type="password" id="password_input" placeholder="Password" required=true oninput=self.link.callback(|data: InputData| Msg::InputMasterPassword(data.value))/>
                            <label class="label" for="password_input">{"Password"}</label>
                        </div>
                        <br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button><br />
                        <br />
                        {
                            if how_does_it_work {
                                html! {
                                    <>
                                    <br />
                                    <h3 class="faq_question" onclick=self.link.callback(move |_| Msg::ChangePanels(false, how_to_get_mp))>{"How does it work? [reduce]"}</h3>
                                    <p>
                                        {"In opposition to any other password manager, this one will never store your passwords. Your passwords will be regenerated each time you need them. The generated passwords will never change, wherever and whenever you are. That means that you can get all your passwords on different devices without needing to synchronize or exchange any data. All your passwords will be generated from your master password to make them unique. They will also be different for every website. Thanks to a complex password generation, it is not possible to get your master password from a generated password. That means that if a website is compromised, and a generated password is stolen, the hacker will never be able to get your master password. Thanks to this design, this is the most secure password manager software in the world, as long as your master password remains strong and secret. "}
                                    </p>
                                    </>
                                }
                            } else {
                                html! {
                                    <><br />
                                    <h3 class="faq_question" onclick=self.link.callback(move |_| Msg::ChangePanels(true, how_to_get_mp.clone()))>{"How does it work? [expand]"}</h3>
                                    </>
                                }
                            }
                        }
                        {
                            if how_to_get_mp {
                                let mut master_password = String::new();
                                while master_password.len() < 14 { // only bytes char so its ok
                                    let number: u8 = get_random_between(32, 127);
                                    if (123..=126).contains(&number) || (91..=96).contains(&number) || (58..=64).contains(&number) || (32..=47).contains(&number) {
                                        continue
                                    }
                                    master_password.push(number as char);
                                }

                                html! {
                                    <>
                                    <br />
                                    <h3 class="faq_question" onclick=self.link.callback(move |_| Msg::ChangePanels(how_does_it_work.clone(), false))>{"How can I get a master password? [reduce]"}</h3>
                                    <p>
                                        {"Your master password will be the root of every generated password. It must be very strong because cracking your master password means cracking every generated password. It should be random."}
                                    </p>
                                    {
                                        format!("Here is a master password generated just for you! {}", master_password)
                                    }
                                    </>
                                }
                            } else {
                                html! {
                                    <><br />
                                    <h3 class="faq_question" onclick=self.link.callback(move |_| Msg::ChangePanels(how_does_it_work.clone(), true))>{"How can I get a master password? [expand]"}</h3>
                                    </>
                                }
                            }
                        }
                    </main>
                }
            }
            Page::EnterUrl { .. } => {
                html! {
                    <main>
                        {for messages}
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Enter the URL of the website on which you want to get a password."}<br />
                        <br />
                        <div class="input_container">
                            <input class="big-input" type="text" id="url_input" value="" placeholder="URL" required=true />
                            <label class="label" for="url_input">{"URL"}</label>
                        </div>
                        <br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button><br />
                        <br />
                        <button class="big_button" onclick=self.link.callback(|_| Msg::Back)>{ "Back" }</button>
                    </main>
                }
            }
            Page::DisplayPasswords {
                domain, show_more: false, ..
            } => {
                html! {
                    <main>
                        {for messages}
                        {
                            match domain {
                                Domain::Checking(provisory_domain) => html! {{Message::Warning(format!("The domain {} may not be valid.", provisory_domain)).view()}},
                                Domain::Checked(domain) => html! {},
                                Domain::Uncheckable(provisory_domain, error) => html! {{Message::Warning(format!("The domain {} may not be valid as the program was unable to check it (check network) (error message: {}).", provisory_domain, error)).view()}},
                            }
                        }
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Press the button to copy your password for "}<a href=domain.as_ref()>{domain.as_ref()}</a>{"."}<br/>
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
                                <button class="big_button" onclick=self.link.callback(move |_| Msg::CopyPassword(idx))>{format!("Password {}", idx)}</button><br/><br/>
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
                        {for messages}
                        <img id="settings" src="parameters.png" onclick=self.link.callback(|_| Msg::Settings)/>
                        {"Try every password of this list in the correct order."}<br/>
                        <br/>
                        {
                            for buttons
                        }
                        {
                            if *accessible_password > 5 {
                                Message::Info(String::from("If none of these passwords above is working and you are trying to sign up, please find a password by yourself. You can send me an email (at mubelotix@gmail.com) to report the website, and I will see if I can do something. This website is weakly configured, and I can't do anything for that. If you are trying to sign in, either you didn't enter the correct password or the correct URL, or you created a password by yourself on this website.")).view()
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
