#![no_std]
#![no_main]

mod read_macros;

mod btf;
mod maps;
mod helpers;

mod bio;
mod nvme;
mod vfs;

macro_rules! define_probe {
    (#[$attr:meta] $name:ident, $ctx:ty, $try_fn:ident) => {
        #[$attr]
        pub fn $name(ctx: $ctx) -> u32 {
            match $try_fn(ctx) {
                Ok(ret) | Err(ret) => ret,
            }
        }
    };
}
pub(crate) use define_probe;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
