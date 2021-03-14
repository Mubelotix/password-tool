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

pub fn get_random_u8() -> u8 {
    use web_sys::window;
    let crypto = window().unwrap().crypto().unwrap();
    let mut random = [0; 1];
    crypto.get_random_values_with_u8_array(&mut random).unwrap();
    random[0]
}

pub fn get_random_u32() -> u32 {
    use web_sys::window;
    let crypto = window().unwrap().crypto().unwrap();
    let mut random = [0; 4];
    crypto.get_random_values_with_u8_array(&mut random).unwrap();
    u32::from_be_bytes(random)
}

pub fn get_random_u32_under(max: u32) -> u32 {
    use web_sys::window;
    let crypto = window().unwrap().crypto().unwrap();
    let mut random = [0; 4];
    crypto.get_random_values_with_u8_array(&mut random).unwrap();
    u32::from_be_bytes(random) % max
}

pub fn get_random_u32_between(min: u32, under: u32) -> u32 {
    use web_sys::window;
    let crypto = window().unwrap().crypto().unwrap();
    let mut random = [0; 4];
    crypto.get_random_values_with_u8_array(&mut random).unwrap();
    min + (u32::from_be_bytes(random) % (under - min))
}

pub fn get_random_between(min: u8, under: u8) -> u8 {
    use web_sys::window;
    let crypto = window().unwrap().crypto().unwrap();
    let mut random = [0; 1];
    crypto.get_random_values_with_u8_array(&mut random).unwrap();
    min + (random[0] % (under - min))
}
