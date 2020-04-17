use crate::{Message, util::{get_random, PasswordSystemComponent}, Page};
use wasm_bindgen::JsCast;
use web_sys::{window, HtmlInputElement};

#[derive(PartialEq)]
pub enum KeyloggerProtector {
    Disabled,
    Enabled(bool, usize, String, Message)
}

impl KeyloggerProtector {
    pub fn new() -> KeyloggerProtector {
        KeyloggerProtector::Disabled
    }

    pub fn enable(&mut self) {
        let is_password = get_random(1) == 0;
        let remaining = get_random(2) as usize + 1;
        let message = if is_password {
            Message::Info(format!("Press {} keys entering your password. (keylogger protection)", remaining))
        } else {
            Message::Warning(format!("Press {} random keys similar to the keys you need to press to write your password. (keylogger protection)", remaining))
        };
        let value = match window().map(|w| w.document().map(|d| d.get_element_by_id("password_input").map(|e| e.dyn_into::<HtmlInputElement>().map(|e| e.value())))) {
            Some(Some(Some(Ok(value)))) => value,
            _ => String::new()
        };

        *self = KeyloggerProtector::Enabled(is_password, remaining, value, message);
    }

    pub fn disable(&mut self) {
        *self = KeyloggerProtector::Disabled;
    }

    pub fn is_enabled(&self) -> bool {
        self != &KeyloggerProtector::Disabled
    }

    pub fn handle_input(&mut self, password: String) {
        match self {
            KeyloggerProtector::Enabled(is_password, remaining, last_value, message) => {
                *remaining -= 1;

                if !*is_password {
                    let input = window().unwrap().document().unwrap().get_element_by_id("password_input").unwrap().dyn_into::<HtmlInputElement>().unwrap();
                    input.set_value(last_value);
                    input.click();
                } else {
                    *last_value = password;
                }

                if *remaining == 0 {
                    *is_password = !*is_password;

                    let crypto = window().unwrap().crypto().unwrap();
                    let mut random = [0; 1];
                    crypto.get_random_values_with_u8_array(&mut random).unwrap();

                    if *is_password {
                        *remaining = get_random(2) as usize + 1;
                    } else {
                        *remaining = get_random(9) as usize + 3;
                    }
                }

                *message = if *is_password {
                    Message::Info(format!("Press {} keys entering your password. (keylogger protection)", remaining))
                } else {
                    Message::Warning(format!("Press {} random keys similar to the keys you need to press to write your password. (keylogger protection)", remaining))
                };
            },
            KeyloggerProtector::Disabled => (),
        }
    }
}

impl PasswordSystemComponent for KeyloggerProtector {
    fn get_messages(&self, settings_open: bool, page: &Page) -> Vec<&Message> {
        if settings_open && page == &Page::EnterMainPassword {
            match self {
                KeyloggerProtector::Enabled(_,_,_, message) => vec![&message],
                KeyloggerProtector::Disabled => Vec::new()
            }
        } else {
            Vec::new()
        }
    }
}