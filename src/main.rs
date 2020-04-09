#![recursion_limit="256"]
use stdweb::web::INonElementParentNode;
use yew::prelude::*;
use sha3::{Digest, Sha3_512};
use hex;
use stdweb::{js, web::document, web::html_element::InputElement, unstable::TryFrom};
use yew::services::storage::{StorageService, Area};
use yew::services::dialog::DialogService;
use string_tools::{get_all_after, get_all_before};


#[cfg(test)]
mod test {
    use super::generate_password;
    use super::extract_domain_name;

    #[test]
    fn test_password_did_not_changed() {
        assert_eq!(generate_password("testing", "example.com", true, false, true), "2d70dac574dbfa9aa025c3750657e70773d6b2a9b00f@*_BQF");
    }

    #[test]
    fn url() {
        assert_eq!(&extract_domain_name("https://google.com").unwrap(), "google.com");
        assert_eq!(&extract_domain_name("google.com").unwrap(), "google.com");
        assert_eq!(&extract_domain_name("https://google.com/test").unwrap(), "google.com");
        assert_eq!(&extract_domain_name("http://mubelotix.dev/passwords").unwrap(), "mubelotix.dev");
        assert_eq!(&extract_domain_name("https://test.mubelotix.dev/index.html").unwrap(), "mubelotix.dev");
    }

    #[test]
    fn backward_compatibility_test() {
        assert_eq!(&generate_password("test", "unknown.unknown", false, false, false), "00c7dfebc7943SOD");
        assert_eq!(&generate_password("test", "unknown.unknown", false, false, true), "00c7dfebc769*_BQ");
        assert_eq!(&generate_password("test", "unknown.unknown", false, true, false), "0199223235199105");
        assert_eq!(&generate_password("test", "unknown.unknown", false, true, true), "0199223235199105");
        assert_eq!(&generate_password("test", "unknown.unknown", true, false, false), "00c7dfebc769bc042ad64ed60d9447dcaeaf7e9cabef943SOD");
        assert_eq!(&generate_password("test", "unknown.unknown", true, false, true), "00c7dfebc769bc042ad64ed60d9447dcaeaf7e9cabef@*_BQF");
        assert_eq!(&generate_password("test", "unknown.unknown", true, true, false), "01992232351991051884422147821413148712201741751261");
        assert_eq!(&generate_password("test", "unknown.unknown", true, true, true), "01992232351991051884422147821413148712201741751261");
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
    
    while url.len() > 0 && !url.ends_with('.') {
        domain.insert(0, url.remove(url.len()-1))
    }

    if url.len() > 0 && domain.len() > 0 {
        domain.insert(0, '.');
        url.remove(url.len()-1);
    } else {
        return None
    }

    while url.len() > 0 && !url.ends_with('.') {
        domain.insert(0, url.remove(url.len()-1))
    }

    Some(domain)
}

fn generate_password(master_password: &str, domain: &str, big: bool, only_numbers: bool, special_chars: bool) -> String {
    let password_size = if big {
        50
    } else {
        16
    };
    
    let mut hasher = Sha3_512::new();
    
    let mut generated_password = master_password.to_string();
    generated_password.push_str("35Pqfs6FeEf545fD54");
    generated_password.push_str(domain);
    hasher.input(generated_password);
    let generated_password = hasher.result();

    let mut generated_password: String = if !only_numbers {
        if special_chars && !big {
            hex::encode(generated_password[..password_size/2-2].to_vec())
        } else {
            hex::encode(generated_password[..password_size/2-3].to_vec())
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

enum Page {
    EnterMainPassword,
    EnterUrl,
    DisplayGeneratedPassword,
    MorePasswords,
    Sorry(String)
}

struct Model {
    link: ComponentLink<Self>,
    main_password: String,
    url: String,
    domain: String,
    generated_passwords: [String; 6],
    accessible_password: usize,
    page: Page,
}

enum Msg {
    Next,
    SecondaryButton,
    CopyPassword(usize),
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            page: Page::EnterMainPassword,
            main_password: String::new(),
            url: String::new(),
            generated_passwords: [String::new(),String::new(),String::new(),String::new(),String::new(),String::new()],
            accessible_password: 0,
            domain: String::new(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Next => match self.page {
                Page::EnterMainPassword => {
                    // Provisory: because of bad wasm support on mobile
                    self.main_password = InputElement::try_from(document().get_element_by_id("password_input").unwrap()).unwrap().raw_value();
                    
                    let mut hasher = Sha3_512::new();
                    hasher.input(format!("{}password", self.main_password));
                    let result = hasher.result();
                    let hashed_password: String = hex::encode(result[..].to_vec());

                    let mut storage = StorageService::new(Area::Local).expect("storage unavailable");
                    let last: Result<String, _> = storage.restore(&hashed_password);
                    if last.is_ok() || DialogService::default().confirm("This password has never been seen on this computer before. Are you sure this password is valid?") {
                        self.page = Page::EnterUrl;
                        storage.store(&hashed_password, Ok(String::from("")));
                        true
                    } else {
                        false
                    }
                },
                Page::EnterUrl => {
                    // Provisory: because of bad wasm support on mobile
                    self.url = InputElement::try_from(document().get_element_by_id("url_input").unwrap()).unwrap().raw_value();

                    self.domain = extract_domain_name(&self.url).unwrap_or(String::from("unknown.unknown"));

                    self.generated_passwords[0] = generate_password(&self.main_password, &self.domain, true, false, true);
                    self.generated_passwords[1] = generate_password(&self.main_password, &self.domain, true, false, false);
                    self.generated_passwords[2] = generate_password(&self.main_password, &self.domain, true, true, true);
                    self.generated_passwords[3] = generate_password(&self.main_password, &self.domain, false, false, true);
                    self.generated_passwords[4] = generate_password(&self.main_password, &self.domain, false, false, false);
                    self.generated_passwords[5] = generate_password(&self.main_password, &self.domain, false, true, true);
                    
                    self.page = Page::DisplayGeneratedPassword;
                    self.accessible_password = 0;
                    true },
                Page::DisplayGeneratedPassword => {self.page = Page::MorePasswords; true},
                Page::Sorry(_) => false,
                Page::MorePasswords => {
                    {self.page = Page::Sorry("There is no page here!".to_string()); true}
                }
            },
            Msg::CopyPassword(idx) => {
                if idx <= self.accessible_password {
                    js! { @(no_return)
                        var el = document.createElement("textarea");
                        el.value = @{&self.generated_passwords[idx]};
                        el.setAttribute("readonly", "");
                        el.style = {position: "absolute", left: "-9999px"};
                        document.body.appendChild(el);
                        el.select();
                        document.execCommand("copy");
                        document.body.removeChild(el);
                    }
                    if self.accessible_password == idx {
                        self.accessible_password += 1;
                    }
                } else {
                    js! { @(no_return)
                        alert("Error: this password can't be copied now");
                    }
                }
                true
            },
            Msg::SecondaryButton => match self.page {
                Page::EnterMainPassword => {self.page = Page::Sorry(String::from("Unimplemented password generation")); true},
                Page::EnterUrl => {self.page = Page::EnterMainPassword; true},
                Page::DisplayGeneratedPassword => {self.page = Page::EnterUrl; true},
                Page::MorePasswords => {self.page = Page::DisplayGeneratedPassword; true},
                Page::Sorry(_) => {self.page = Page::EnterMainPassword; true},
            }
        }
    }

    fn view(&self) -> Html {
        match &self.page {
            Page::EnterMainPassword => {
                html! {
                    <main>
                        {"Welcome!"}<br />
                        <br />
                        <div class="input_container">
                            <input type="password" id="password_input" placeholder="Password" required=true />
                            <label for="password_input">{"Password"}</label>
                        </div>
                        <br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button><br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Generate a password" }</button>
                    </main>
                }
            },
            Page::EnterUrl => {
                html! {
                    <main>
                        {"Enter the URL of the website on which you want to get a password."}<br />
                        <br />
                        <div class="input_container">
                            <input type="text" id="url_input" value="" placeholder="URL" required=true />
                            <label for="url_input">{"URL"}</label>
                        </div>
                        <br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button><br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Back" }</button>
                    </main>
                }
            },
            Page::DisplayGeneratedPassword => {
                html! {
                    <main>
                        {
                            if self.domain == "unknown.unknown" {
                                String::from("WARNING: Failed to parse the URL. The domain has been replaced by the wildcard domain: \"unknown.unknown\". You should avoid using this password, go back and enter the domain name again.")
                            } else {
                                format!("Your password for the website {} has been generated successfully!", self.domain)
                            }
                            
                        }<br/>
                        <br/>
                        <button onclick=self.link.callback(|_| Msg::CopyPassword(0))>{"Copy password"}</button><br/>
                        <br/>
                        {"If your password is rejected, please try the \"Help\" button below."}<br/>
                        <br/>
                        <button onclick=self.link.callback(|_| Msg::Next)>{ "Help" }</button><br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Back" }</button>
                    </main>
                }
            },
            Page::MorePasswords => {
                let mut buttons = Vec::new();
                for idx in 0..6 {
                    buttons.push(if self.accessible_password >= idx {
                        html! {
                            <div><button onclick=self.link.callback(move |_| Msg::CopyPassword(idx))>{format!("Password {}", idx)}</button><br/><br/></div>
                        }
                    } else {
                        html! {
                            <div><button class="disabled_button">{"Try the password above"}</button><br/><br/></div>
                        }
                    });
                };
                html! {
                    <main>
                        {"Try every password of this list in the correct order."}<br/>
                        <br/>
                        {
                            for buttons
                        }
                        {
                            if self.accessible_password > 5 {
                                "If none of these passwords above is working and you are trying to sign up, please find a password by yourself. You can send me an email (at mubelotix@gmail.com) to report the website, and I will see if I can do something. This website is weakly configured, and I can't do anything for that. If you are trying to sign in, either you didn't enter the correct password or the correct URL, or you created a password by yourself on this website."
                            } else {
                                ""
                            }
                        }
                        <br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Back" }</button>
                    </main>
                }
            },
            Page::Sorry(message) => {
                html! {
                    <main id="sorry">
                        <link rel="stylesheet" type="text/css" href="css.css"/>
                        <h2> {"Sorry, something is not working"} </h2>
                        <br/>
                        {message}<br/>
                        <br/>
                        {"You can contact "}<a href="mailto:mubelotix@gmail.com">{"me"}</a><br/>
                        <br/>
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Restart" }</button>
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

