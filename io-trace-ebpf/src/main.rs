#![no_std]
#![no_main]

mod nvme;
mod read_macros;
mod vmlinux;

use aya_ebpf::helpers::{self};
use aya_ebpf::macros::map;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::{debug, info};

// use nvme::{nvme_dev, nvme_queue};
use vmlinux::{address_space, bio, blk_mq_queue_data, block_device, bvec_iter, inode, request};

use crate::vmlinux::dev_t;

#[map]
static BIO_REQUESTS: aya_ebpf::maps::HashMap<RequestKey, u64> =
    aya_ebpf::maps::HashMap::<RequestKey, u64>::with_max_entries(10240, 0);

// #[map]
// static DEV_REQUESTS: aya_ebpf::maps::HashMap<RequestKey, u64> =
//     aya_ebpf::maps::HashMap::<RequestKey, u64>::with_max_entries(10240, 0);

#[map]
static DEV_REQUESTS: aya_ebpf::maps::HashMap<usize, u64> =
    aya_ebpf::maps::HashMap::<usize, u64>::with_max_entries(10240, 0);

#[derive(Clone, Copy)]
#[repr(C)]
struct RequestKey {
    dev: u32,
    sector: u64,
}

const ERR_CODE: u32 = 1;

const DEV_MAJ: u32 = 259;
const DEV_MIN: u32 = 5;

fn check_device(maj: u32, min: u32) -> bool {
    if maj == DEV_MAJ && min == DEV_MIN {
        return true;
    } else {
        return false;
    }
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
            read_ptr_field!(bio_ptr, bio, bi_bdev, block_device).map_err(|_| ERR_CODE)?,
            block_device,
            bd_dev,
            u32
        )
        .map_err(|_| ERR_CODE)?;

        let bi_sector: u64 = read_field!(bio_ptr, bio, bi_iter, bvec_iter)
            .map_err(|_| ERR_CODE)?
            .bi_sector;

        return Ok((bd_dev, bi_sector));
    }
}

fn bio_get_start_sector(bio_ptr: *const bio) -> Result<u64, u32> {
    unsafe {
        if ptr_field_is_null!(bio_ptr, bio, bi_bdev, block_device) {
            return Err(0);
        }

        let bi_bdev_ptr: *const block_device =
            read_ptr_field!(bio_ptr, bio, bi_bdev, block_device).map_err(|_| ERR_CODE)?;
        let bd_start_sect: u64 =
            read_field!(bi_bdev_ptr, block_device, bd_start_sect, u64).map_err(|_| ERR_CODE)?;

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
        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?; // pointer
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        let bd_start_sect: u64 = bio_get_start_sector(req_ptr)?;

        if !check_device(maj, min) {
            return Ok(0);
        };

        let key: RequestKey = RequestKey {
            dev: bd_dev,
            sector: (bd_start_sect + bi_sector),
        };
        BIO_REQUESTS.insert(&key, &time, 0).map_err(|_| ERR_CODE)?;
        info!(
            &ctx,
            "Block I/O : insert request: dev {} ({}, {}), sector {} ({}, {}), time {}",
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
        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?;
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        if !check_device(maj, min) {
            return Ok(0);
        };

        let key: RequestKey = RequestKey {
            dev: bd_dev,
            sector: bi_sector,
        };

        if let Some(issued_time) = BIO_REQUESTS.get(&key) {
            let latency = time - *issued_time;
            info!(
                &ctx,
                "Block I/O : request completed: dev {} ({}, {}), sector {}, latency {}",
                key.dev,
                maj,
                min,
                key.sector,
                latency
            );
            BIO_REQUESTS.remove(&key).map_err(|_| ERR_CODE)?;
        } else {
            info!(
                &ctx,
                "Block I/O : request completed but not found: dev {} ({}, {}), sector {}",
                key.dev,
                maj,
                min,
                key.sector
            );
        }
    }
    Ok(0)
}

#[kprobe]
pub fn dev_nvme_queue_rq(ctx: ProbeContext) -> u32 {
    match try_dev_nvme_queue_rq(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dev_nvme_queue_rq(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        // let hctx_ptr: *const blk_mq_hw_ctx = ctx.arg(0).ok_or(ERR_CODE)?;
        let bd_ptr: *const blk_mq_queue_data = ctx.arg(1).ok_or(ERR_CODE)?;
        if ptr_field_is_null!(bd_ptr, blk_mq_queue_data, rq, request) {
            return Err(0);
        }
        let req_ptr: *const request =
            read_ptr_field!(bd_ptr, blk_mq_queue_data, rq, request).map_err(|_| ERR_CODE)?;

        let bio_ptr: *const bio =
            read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;

        let (bd_dev, bi_sector) = bio_parse(bio_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        if !check_device(maj, min) {
            return Ok(0);
        };

        let key = req_ptr as usize;
        DEV_REQUESTS.insert(&key, &time, 0).map_err(|_| ERR_CODE)?;
        // info!(
        //     &ctx,
        //     "nvme queue request: request ptr {}, time {}", key, time
        // );

        info!(
            &ctx,
            "NVMe      : queue requested on dev ({}, {}), sector {}", maj, min, bi_sector
        );
        Ok(0)
    }
}

#[kprobe]
pub fn dev_nvme_complete_batch_req(ctx: ProbeContext) -> u32 {
    match try_dev_nvme_complete_batch_req(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dev_nvme_complete_batch_req(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;

        let key = req_ptr as usize;

        let bio_ptr: *const bio =
            read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;

        let (bd_dev, bi_sector) = bio_parse(bio_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        if !check_device(maj, min) {
            return Ok(0);
        };

        info!(
            &ctx,
            "NVMe      : Completed: dev ({}, {}), sector {}", maj, min, bi_sector
        );

        if let Some(issued_time) = DEV_REQUESTS.get(&key) {
            let latency = time - *issued_time;
            info!(
                &ctx,
                "NVMe      : request completed: request ptr {}, latency {}", key, latency
            );
            DEV_REQUESTS.remove(&key).map_err(|_| ERR_CODE)?;
        } else {
            info!(
                &ctx,
                "NVMe      : request completed but not found: request ptr {}", key
            );
        }
    }
    Ok(0)
}

#[kprobe]
pub fn fs_btree_writepages(ctx: ProbeContext) -> u32 {
    match try_fs_btree_writepages(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fs_btree_writepages(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let mapping_ptr: *const address_space = ctx.arg(0).ok_or(ERR_CODE)?;
        let inode_ptr: *const inode =
            read_ptr_field!(mapping_ptr, address_space, host, inode).map_err(|_| ERR_CODE)?;
        debug!(
            &ctx,
            "btree_writepages: mapping: {}, inode: {}", mapping_ptr as usize, inode_ptr as usize
        );
        Ok(0)
    }
}

#[kprobe]
pub fn fs_btrfs_writepages(ctx: ProbeContext) -> u32 {
    match try_fs_btrfs_writepages(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fs_btrfs_writepages(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let mapping_ptr: *const address_space = ctx.arg(0).ok_or(ERR_CODE)?;
        let inode_ptr: *const inode =
            read_ptr_field!(mapping_ptr, address_space, host, inode).map_err(|_| ERR_CODE)?;

        debug!(
            &ctx,
            "btrfs_writepages: mapping: {}, inode ptr: {}",
            mapping_ptr as usize,
            inode_ptr as usize
        );

        let i_rdev: dev_t = read_field!(inode_ptr, inode, i_rdev, dev_t).map_err(|_| ERR_CODE)?;
        let (maj, min) = dev_to_maj_min(i_rdev);

        debug!(&ctx, "btrfs_writepages: dev: {} ({}, {})", i_rdev, maj, min);
        Ok(0)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
