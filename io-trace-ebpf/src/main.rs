#![no_std]
#![no_main]

mod nvme;
mod read_macros;
mod vmlinux;

use aya_ebpf::helpers::{self};
use aya_ebpf::macros::map;
use aya_ebpf::EbpfContext;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::{debug, info};

// use nvme::{nvme_dev, nvme_queue};
use vmlinux::{address_space, bio, blk_mq_queue_data, block_device, bvec_iter, inode, request};

use crate::vmlinux::dev_t;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IoEvent {
    pub event_type: u32,
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,
    
    // 레이어별 식별자
    pub dev: u32,
    pub sector: u64,
    pub inode: u64,
    pub request_ptr: u64,
    
    // 추가 컨텍스트
    pub size: u32,  // I/O 크기
    pub flags: u32,  // READ/WRITE 등
}

// 이벤트 타입 상수
const EVENT_BTREE_WRITEPAGES:       u32 = 0;
const EVENT_BTRFS_WRITEPAGES:       u32 = 1;
const EVENT_BIO_SUBMIT:             u32 = 2;
const EVENT_BIO_COMPLETE:           u32 = 3;
const EVENT_NVME_QUEUE:             u32 = 4;
const EVENT_NVME_COMPLETE:          u32 = 5;
const EVENT_BLK_MQ_START_REQUEST:   u32 = 6;

#[map]
static EVENTS: aya_ebpf::maps::PerfEventArray<IoEvent> =
    aya_ebpf::maps::PerfEventArray::new(0);

#[derive(Clone, Copy)]
#[repr(C)]
struct RequestKey {
    tgid: u32,
    dev: u32,
    sector: u64,
}

const ERR_CODE: u32 = 1;

const DEV_MAJ: u32 = 259;
const DEV_MIN: u32 = 5;

const TARGET_TGID: u32 = 9738;

fn check_device(maj: u32, min: u32) -> bool {
    if maj == DEV_MAJ && min == DEV_MIN {
        return true;
    } else {
        return false;
    }
}

fn check_tgid(tgid: u32) -> bool {
    tgid == TARGET_TGID
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
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) { return Ok(0); }

        let pid: u32 = ctx.pid();
        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?; // pointer
//        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        let bd_start_sect: u64 = bio_get_start_sector(req_ptr)?;

//        if !check_device(maj, min) {
//            return Ok(0);
//        };
        
        let event = IoEvent {
            event_type: EVENT_BIO_SUBMIT,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            size: 0,
            flags: 0,
        };

        EVENTS.output(&ctx, &event, 0);
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
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) { return Ok(0); }

        let pid: u32 = ctx.pid();
        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?;
//        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

//        if !check_device(maj, min) {
//            return Ok(0);
//        };

        let event = IoEvent {
            event_type: EVENT_BIO_COMPLETE,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            size: 0,
            flags: 0,
        };

        EVENTS.output(&ctx, &event, 0);
    }
    Ok(0)
}

#[kprobe]
pub fn bio_blk_mq_start_request(ctx: ProbeContext) -> u32 {
    match try_bio_blk_mq_start_request(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_bio_blk_mq_start_request(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        let pid: u32 = ctx.pid();

        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;
        
        let event = IoEvent {
            event_type: EVENT_BLK_MQ_START_REQUEST,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: 0,
            sector: 0,
            request_ptr: req_ptr as u64,
            size: 0,
            flags: 0,
        };

        EVENTS.output(&ctx, &event, 0);
        Ok(0)
    }
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
        let tgid: u32 = ctx.tgid();
        // if !check_tgid(tgid) { return Ok(0); }

        let pid: u32 = ctx.pid();
        // let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

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

//        if !check_device(maj, min) {
//            return Ok(0);
//        };

        let event = IoEvent {
            event_type: EVENT_NVME_QUEUE,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            size: 0,
            flags: 0,
        };

        EVENTS.output(&ctx, &event, 0);
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
//        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) { return Ok(0); }

        let pid: u32 = ctx.pid();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;

        let key = req_ptr as usize;

        let bio_ptr: *const bio =
            read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;

        let (bd_dev, bi_sector) = bio_parse(bio_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

//        if !check_device(maj, min) {
//            return Ok(0);
//        };

        let event = IoEvent {
            event_type: EVENT_NVME_COMPLETE,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
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
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) { return Ok(0); }

        let pid: u32 = ctx.pid();
        let mapping_ptr: *const address_space = ctx.arg(0).ok_or(ERR_CODE)?;
        let inode_ptr: *const inode =
            read_ptr_field!(mapping_ptr, address_space, host, inode).map_err(|_| ERR_CODE)?;


        let event = IoEvent {
            event_type: EVENT_BTREE_WRITEPAGES,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: inode_ptr as u64,
            dev: 0,
            sector: 0,
            request_ptr: 0,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
        
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
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) { return Ok(0); }

        let pid: u32 = ctx.pid();

        let mapping_ptr: *const address_space = ctx.arg(0).ok_or(ERR_CODE)?;
        let inode_ptr: *const inode =
            read_ptr_field!(mapping_ptr, address_space, host, inode).map_err(|_| ERR_CODE)?;

        let event = IoEvent {
            event_type: EVENT_BTRFS_WRITEPAGES,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: inode_ptr as u64,
            dev: 0,
            sector: 0,
            request_ptr: 0,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);

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
