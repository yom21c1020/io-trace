use crate::btf::vmlinux::{bio, block_device, bvec_iter};
use crate::maps::TARGET_PID_MAP;
use crate::{ptr_field_is_null, read_field, read_ptr_field};

pub(crate) const ERR_CODE: u32 = 1;

pub(crate) fn check_tgid(tgid: u32) -> bool {
    unsafe {
        if let Some(target_tgid) = TARGET_PID_MAP.get(0) {
            // 0 = no filter (PID 미지정)
            if *target_tgid == 0 {
                return true;
            }
            return tgid == *target_tgid;
        }
        false
    }
}

pub(crate) fn bio_parse(bio_ptr: *const bio) -> Result<(u32, u64), u32> {
    unsafe {
        if ptr_field_is_null!(bio_ptr, bio, bi_bdev, block_device) {
            return Err(0);
        }

        let bd_dev: u32 = read_field!(
            read_ptr_field!(bio_ptr, bio, bi_bdev, block_device).map_err(|_| ERR_CODE)?,
            block_device,
            bd_dev,
            u32
        )
        .map_err(|_| ERR_CODE)?;

        let bi_sector: u64 = read_field!(bio_ptr, bio, bi_iter, bvec_iter)
            .map_err(|_| ERR_CODE)?
            .bi_sector;

        Ok((bd_dev, bi_sector))
    }
}

pub(crate) fn bio_get_start_sector(bio_ptr: *const bio) -> Result<u64, u32> {
    unsafe {
        if ptr_field_is_null!(bio_ptr, bio, bi_bdev, block_device) {
            return Err(0);
        }

        let bi_bdev_ptr: *const block_device =
            read_ptr_field!(bio_ptr, bio, bi_bdev, block_device).map_err(|_| ERR_CODE)?;
        let bd_start_sect: u64 =
            read_field!(bi_bdev_ptr, block_device, bd_start_sect, u64).map_err(|_| ERR_CODE)?;

        Ok(bd_start_sect)
    }
}
