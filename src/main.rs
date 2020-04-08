#![recursion_limit="256"]
use stdweb::web::INonElementParentNode;
use yew::prelude::*;
use sha3::{Digest, Sha3_512};
use hex;
use stdweb::{js, web::document, web::html_element::InputElement, unstable::TryFrom};
use yew::services::storage::{StorageService, Area};
use yew::services::dialog::DialogService;

pub fn get_all_after<'a>(text: &'a str, end: &str) -> &'a str {
    if let Some(mut end_index) = text.find(end) {
        end_index += end.len();
        return &text[end_index..];
    } else {
        return "";
    }
}

pub fn get_all_before<'a>(text: &'a str, begin: &str) -> &'a str {
    let begin = text.find(begin).unwrap_or(text.len());
    &text[..begin]
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
        hex::encode(generated_password[..password_size/2-3].to_vec())
    } else {
        let mut generated_password2 = String::new();
        for n in generated_password {
            generated_password2.push_str(&n.to_string());
        }
        let generated_password = generated_password2[..password_size].to_string();
        return generated_password;
    };

    if special_chars {
        generated_password.push_str("@*_BQF");
    } else {
        generated_password.push_str("943SOD");
    }

    generated_password
}

enum Page {
    EnterMainPassword,
    EnterUrl,
    DisplayGeneratedPassword,
    Sorry(String)
}

struct Model {
    link: ComponentLink<Self>,
    main_password: String,
    url: String,
    domain: String,
    generated_password: String,
    page: Page,
}

enum Msg {
    Next,
    SecondaryButton,
    CopyPassword,
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
            generated_password: String::new(),
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

                    let mut storage = StorageService::new(Area::Local);
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

                    self.domain = extract_domain_name(&self.url).unwrap_or(String::from("unknow.unknow"));

                    self.generated_password = generate_password(&self.main_password, &self.domain, true, false, true);
                    
                    self.page = Page::DisplayGeneratedPassword;
                    true },
                Page::DisplayGeneratedPassword => {self.page = Page::Sorry("I didn't implemented this for now".to_string()); true},
                _ => false,
            },
            Msg::CopyPassword => {
                js! { @(no_return)
                    var el = document.createElement("textarea");
                    el.value = @{&self.generated_password};
                    el.setAttribute("readonly", "");
                    el.style = {position: "absolute", left: "-9999px"};
                    document.body.appendChild(el);
                    el.select();
                    document.execCommand("copy");
                    document.body.removeChild(el);
                }
                false
            },
            Msg::SecondaryButton => match self.page {
                Page::EnterMainPassword => {self.page = Page::Sorry(String::from("Unimplemented password generation")); true},
                Page::EnterUrl => {self.page = Page::EnterMainPassword; true},
                Page::DisplayGeneratedPassword => {self.page = Page::EnterUrl; true},
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
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Generate a password" }</button><br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button>
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
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Back" }</button><br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::Next)>{ "Next" }</button>
                    </main>
                }
            },
            Page::DisplayGeneratedPassword => {
                html! {
                    <main>
                        {format!("Your password for the website {} has been generated successfully!", self.domain)}<br/>
                        <br/>
                        <button onclick=self.link.callback(|_| Msg::CopyPassword)>{"Copy password"}</button><br/>
                        <br/>
                        {"In case where your password is rejected because of requirements, please try the button below."}<br/>
                        <br/>
                        <button onclick=self.link.callback(|_| Msg::SecondaryButton)>{ "Back" }</button><br />
                        <br />
                        <button onclick=self.link.callback(|_| Msg::Next)>{ "Help" }</button>
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
    fn gen_pass() {
        use std::fs;

        let words = fs::read_to_string("dic.txt").unwrap();
        let words: Vec<&str> = words.split('\n').filter(|word| word.len() > 3).collect();

        use rand::{thread_rng, Rng};

        let mut password = String::new();

        for i in 0..20 {
            let mut rng = thread_rng();
            let n: usize = rng.gen_range(0, words.len());
            let word = words[n];
            let mut chars = words[n].chars();
            password.push(chars.next().unwrap());
            password.push(chars.next().unwrap());
            password.push(chars.next().unwrap());

            println!("{}", word);
        }
        
        println!("{}", password);
    }
}