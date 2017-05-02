
// please follow https://aturon.github.io/style/naming.html

#[macro_use(lazy_static)]
#[macro_use(__lazy_static_internal)]
#[macro_use(__lazy_static_create)]
extern crate lazy_static;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

pub mod lib_xl4_bus;
