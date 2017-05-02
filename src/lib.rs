
// please follow https://aturon.github.io/style/naming.html

#[macro_use(lazy_static)]
#[macro_use(__lazy_static_internal)]
#[macro_use(__lazy_static_create)]
extern crate lazy_static;

#[cfg(test)]
mod tests {

    use std::fs::File;
    use lib_xl4_bus::low_level::load_pem;

    #[test]
    fn test_load_pem() {

        let pem_file = File::open("test_data/cert.pem").unwrap();
        let obj = load_pem(pem_file).unwrap();
        println!("loaded {:?}", obj);

    }
}

pub mod lib_xl4_bus;
