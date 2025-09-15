#[macro_export]
macro_rules! read_field {
    ($ptr:expr, $struct_type:ty, $field:ident, $target_type: ty) => {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            ($ptr as u64 + core::mem::offset_of!($struct_type, $field) as u64)
                as *const $target_type,
        )
    };
}

#[macro_export]
macro_rules! read_ptr_field {
    ($ptr:expr, $struct_type:ty, $field:ident, $target_type:ty) => {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            ($ptr as u64 + core::mem::offset_of!($struct_type, $field) as u64)
                as *const *const $target_type,
        )
    };
}

#[macro_export]
macro_rules! ptr_field_is_null {
    ($ptr:expr, $struct_type:ty, $field:ident, $target_type:ty) => {
        match read_ptr_field!($ptr, $struct_type, $field, $target_type) {
            Ok(p) => p.is_null(),
            Err(_) => true,
        }
    };
}
