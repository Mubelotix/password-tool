macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

pub fn get_random(max: u8) -> u8 {
    use web_sys::window;
    let crypto = window().unwrap().crypto().unwrap();
    let mut random = [0; 1];
    crypto.get_random_values_with_u8_array(&mut random).unwrap();
    random[0] % (max + 1)
}

use crate::{Page, Message};
pub trait PasswordSystemComponent {
    fn get_messages(&self, settings_open: bool, page: &Page) -> Vec<&Message>;
}