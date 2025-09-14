#![no_std]
#![no_main]

mod read_macros;
mod vmlinux;

use core::mem::offset_of;

use aya_ebpf::helpers;
use aya_ebpf::macros::map;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

use vmlinux::{bio, block_device, bvec_iter};

#[map]
static BIO_REQUESTS: aya_ebpf::maps::HashMap<RequestKey, u64> =
    aya_ebpf::maps::HashMap::<RequestKey, u64>::with_max_entries(10240, 0);
static DEV_REQUESTS: aya_ebpf::maps::HashMap<RequestKey, u64> =
    aya_ebpf::maps::HashMap::<RequestKey, u64>::with_max_entries(10240, 0);

#[derive(Clone, Copy)]
#[repr(C)]
struct RequestKey {
    dev: u32,
    sector: u64,
}

fn dev_to_maj_min(dev: u32) -> (u32, u32) {
    let maj: u32 = dev >> 20;
    let min: u32 = dev & ((1 << 20) - 1);
    (maj, min)
}

fn bio_parse(bio_ptr: *const bio) -> Result<(u32, u64), u32> {
    unsafe {
        if ptr_field_is_null!(bio_ptr, bio, bi_bdev, block_device) {
            return Err(0);
        }

        let bd_dev: u32 = read_field!(
            read_ptr_field!(bio_ptr, bio, bi_bdev, block_device).map_err(|_| 1u32)?,
            block_device,
            bd_dev,
            u32
        ).map_err(|_| 1u32)?;
        let bi_sector: u64 = read_field!(bio_ptr, bio, bi_iter, bvec_iter).map_err(|_| 1u32)?.bi_sector;

        return Ok((bd_dev, bi_sector));
    }
}

fn bio_get_start_sector(bio_ptr: *const bio) -> Result<u64, u32> {
    unsafe {
        if ptr_field_is_null!(bio_ptr, bio, bi_bdev, block_device) {
            return Err(0);
        }

        let bi_bdev_ptr: *const block_device =
            read_ptr_field!(bio_ptr, bio, bi_bdev, block_device).map_err(|_| 1u32)?;
        let bd_start_sect: u64 =
            read_field!(bi_bdev_ptr, block_device, bd_start_sect, u64).map_err(|_| 1u32)?;

        return Ok(bd_start_sect);
    }
}

#[kprobe]
pub fn bio_submit_bio(ctx: ProbeContext) -> u32 {
    match try_bio_submit_bio(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bio_submit_bio(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let req_ptr: *const bio = ctx.arg(0).ok_or(1u32)?; // pointer
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        let bd_start_sect: u64 = bio_get_start_sector(req_ptr)?;

        let key: RequestKey = RequestKey {
            dev: bd_dev,
            sector: (bd_start_sect + bi_sector),
        };
        BIO_REQUESTS.insert(&key, &time, 0).map_err(|_| 1u32)?;
        info!(
            &ctx,
            "insert request: dev {} ({}, {}), sector {} ({}, {}), time {}",
            key.dev,
            maj,
            min,
            key.sector,
            bd_start_sect,
            bi_sector,
            time
        );
    }
    Ok(0)
}

#[kprobe]
pub fn bio_bio_endio(ctx: ProbeContext) -> u32 {
    match try_bio_bio_endio(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bio_bio_endio(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let req_ptr: *const bio = ctx.arg(0).ok_or(1u32)?;
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        let key: RequestKey = RequestKey {
            dev: bd_dev,
            sector: bi_sector,
        };

        if let Some(issued_time) = BIO_REQUESTS.get(&key) {
            let latency = time - *issued_time;
            info!(
                &ctx,
                "request completed: dev {} ({}, {}), sector {}, latency {}",
                key.dev,
                maj,
                min,
                key.sector,
                latency
            );
            BIO_REQUESTS.remove(&key).map_err(|_| 1u32)?;
        } else {
            info!(
                &ctx,
                "request completed but not found: dev {} ({}, {}), sector {}",
                key.dev,
                maj,
                min,
                key.sector
            );
        }
    }
    Ok(0)
}

// #[kprobe]
// pub fn dev_nvme_queue_rq(ctx: ProbeContext) -> u32 {
//     match try_dev_nvme_queue_rq(ctx) {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }
//
// pub fn try_dev_nvme_queue_rq(ctx: ProbeContext) -> Result<u32, u32> {
//     unsafe {
//         let _hctx_ptr: *const blk_mq_hw_ctx = ctx.arg(0).ok_or(1u32)?;
//         // Implementation incomplete - placeholder
//         Ok(0)
//     }
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
