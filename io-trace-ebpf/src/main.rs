#![no_std]
#![no_main]

mod nvme;
mod read_macros;
mod vmlinux;

use aya_ebpf::EbpfContext;
use aya_ebpf::cty::size_t;
use aya_ebpf::helpers::{self};
use aya_ebpf::macros::map;
use aya_ebpf::{
    macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}
};
use aya_log_ebpf::{debug, info};

use nvme::{nvme_dev, nvme_queue};
use vmlinux::*;

use crate::nvme::{blk_mq_hw_ctx, request_queue};
use crate::vmlinux::dev_t;

use io_trace_common::*;

#[map]
static EVENTS: aya_ebpf::maps::PerfEventArray<IoEvent> = aya_ebpf::maps::PerfEventArray::new(0);

#[map]
static TARGET_PID_MAP: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(1, 0);

#[derive(Clone, Copy)]
#[repr(C)]
struct RequestKey {
    tgid: u32,
    dev: u32,
    sector: u64,
}

#[map]
static ENTRY_MAP: aya_ebpf::maps::PerCpuHashMap<u32, EntryData> = aya_ebpf::maps::PerCpuHashMap::with_max_entries(128, 0);

#[derive(Clone, Copy)]
struct EntryData {
    req_ptr: u64,
    ts_entry: u64,  // entry timestamp
}

#[map]
static BIO_MAP: aya_ebpf::maps::HashMap<u64, u64> = aya_ebpf::maps::HashMap::with_max_entries(1024, 0); // bio_ptr -> entry timestamp

const ERR_CODE: u32 = 1;

fn check_tgid(tgid: u32) -> bool {
    unsafe {
        if let Some(target_tgid) = TARGET_PID_MAP.get(0) {
            return tgid == *target_tgid;
        }
        // Map이 비어있으면 추적하지 않음
        false
    }
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

// Probing

#[kprobe]
pub fn vfs_vfs_write(ctx: ProbeContext) -> u32 {
    match try_vfs_vfs_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_vfs_vfs_write(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) {
            return Ok(0);
        }

        let pid: u32 = ctx.pid();

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let file: *const file = ctx.arg(0).ok_or(ERR_CODE)?;
        let count: size_t = ctx.arg(2).ok_or(ERR_CODE)?;
        let pos: *const loff_t = ctx.arg(3).ok_or(ERR_CODE)?;
        let pos_val: loff_t = aya_ebpf::helpers::bpf_probe_read_kernel(pos).map_err(|_| ERR_CODE)?;

        let f_mode: u32 = read_field!(file, file, f_mode, u32).map_err(|_| ERR_CODE)?;
        if (f_mode & 0x2) == 0 {
            return Ok(0);
        } // FMODE_WRITE     / -EBADF
        if (f_mode & 0x40000) == 0 {
            return Ok(0);
        } // FMODE_CAN_WRITE / -EINVAL

//offset / size
        

        let f_inode: *const inode =
            read_ptr_field!(file, file, f_inode, inode).map_err(|_| ERR_CODE)?;

        let i_sb: *const super_block =
            read_ptr_field!(f_inode, inode, i_sb, super_block).map_err(|_| ERR_CODE)?;
        let s_dev: u32 = read_field!(i_sb, super_block, s_dev, dev_t).map_err(|_| ERR_CODE)?;
        let i_ino: u64 = read_field!(f_inode, inode, i_ino, u64).map_err(|_| ERR_CODE)?;

        debug!(&ctx, "vfs_write hit, tgid {} / pid {} / count {} / pos {:x} / pos_val {} / inode {}", tgid, pid, count, pos as u64, pos_val, i_ino);

        let event = IoEvent {
            event_type: EventType::VfsWrite,
            timestamp,
            tgid,
            pid,
            dev: s_dev,
            sector: 0,
            inode: i_ino,
            request_ptr: 0,
            tag: 0,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
        Ok(0)
    }
}

#[kretprobe]
pub fn vfs_vfs_write_ret(ctx: RetProbeContext) -> u32 {
    match try_vfs_vfs_write_ret(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_vfs_vfs_write_ret(ctx: RetProbeContext) -> Result<u32, u32> {
    unsafe{
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) {
            return Ok(0);
        }

        let pid: u32 = ctx.pid();

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        debug!(&ctx, "vfs_write return, tgid {}, pid {}", tgid, pid);

        let event = IoEvent {
            event_type: EventType::VfsWriteRet,
            timestamp,
            tgid,
            pid,
            dev: 0,
            sector: 0,
            inode: 0,
            request_ptr: 0,
            tag: 0,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
        Ok(0)
    }
}

#[kprobe]
pub fn fs_generic_perform_write(ctx: ProbeContext) -> u32 {
    match try_fs_generic_perform_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_fs_generic_perform_write(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) {
            return Ok(0);
        }
        let pid: u32 = ctx.pid();

        let iocb: *const kiocb = ctx.arg(0).ok_or(ERR_CODE)?;
        let file: *const file =
            read_ptr_field!(iocb, kiocb, ki_filp, file).map_err(|_| ERR_CODE)?;

        // get pos (offset) from kiocb
        let pos: loff_t = read_field!(iocb, kiocb, ki_pos, loff_t).map_err(|_| ERR_CODE)?;

        // get inode
        let f_inode: *const inode = read_ptr_field!(file, file, f_inode, inode).map_err(|_| ERR_CODE)?;

        let i_sb: *const super_block =
            read_ptr_field!(f_inode, inode, i_sb, super_block).map_err(|_| ERR_CODE)?;
        let s_dev: u32 = read_field!(i_sb, super_block, s_dev, dev_t).map_err(|_| ERR_CODE)?;
        let i_ino: u64 = read_field!(f_inode, inode, i_ino, u64).map_err(|_| ERR_CODE)?;

        let count: i64 = 
            read_field!(file, file, f_count, atomic_long_t).map_err(|_| ERR_CODE)?
            .counter;

        let mapping: *const address_space =
            read_ptr_field!(file, file, f_mapping, address_space).map_err(|_| ERR_CODE)?;
        let a_ops: *const address_space_operations =
            read_ptr_field!(mapping, address_space, a_ops, address_space_operations)
                .map_err(|_| ERR_CODE)?;

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        debug!(&ctx, "generic_perform_write hit: tgid {} / pid {} / count {} / pos {} / inode {}", tgid, pid, count, pos, i_ino);

        let event = IoEvent {
            event_type: EventType::GenericPerformWrite,
            timestamp,
            tgid,
            pid,
            dev: s_dev,
            sector: 0,
            inode: i_ino,
            request_ptr: 0,
            tag: 0,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
        Ok(0)
    }
}

#[kprobe]
pub fn fs_iomap_file_buffered_write(ctx: ProbeContext) -> u32 {
    match try_fs_iomap_file_buffered_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_fs_iomap_file_buffered_write(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        if !check_tgid(tgid) {
            return Ok(0);
        }
        let pid: u32 = ctx.pid();
        debug!(&ctx, "iomap_file_buffered_write hit: tgid {} / pid {}", tgid, pid);

        Ok(0)
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
        //if !check_tgid(tgid) {
        //    return Ok(0);
        //}

        let pid: u32 = ctx.pid();
        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();


        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?; // pointer

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        let bd_start_sect: u64 = bio_get_start_sector(req_ptr)?;

        let bi_size: u32 = read_field!(req_ptr, bio, bi_iter, bvec_iter)
            .map_err(|_| ERR_CODE)?
            .bi_size;

        //        if !check_device(maj, min) {
        //            return Ok(0);
        //        };

        debug!(&ctx, "submit_bio hit, tgid {}, pid {}, bio_ptr {:x}, dev ({}, {}), sector {}, size {}", tgid, pid, req_ptr as u64, maj, min, bi_sector, bi_size);

        if !check_tgid(tgid) { BIO_MAP.insert(&(req_ptr as u64), &timestamp, 0).ok(); }

        let event = IoEvent {
            event_type: EventType::BioSubmit,
            timestamp,
            tgid,
            pid,
            inode: 0,
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            tag: 0,
            size: bi_size,
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
        if !check_tgid(tgid) {
            return Ok(0);
        }

        let pid: u32 = ctx.pid();

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?;

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        //        if !check_device(maj, min) {
        //            return Ok(0);
        //        };

        let event = IoEvent {
            event_type: EventType::BioComplete,
            timestamp,
            tgid,
            pid,
            inode: 0,
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            tag: 0,
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
        if !check_tgid(tgid) {
            return Ok(0);
        }

        let pid: u32 = ctx.pid();

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        let bio_ptr: *const bio =
            read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;
        let mut bd_dev: u32 = 0;
        let mut bi_sector: u64 = 0;

        let mut maj: u32 = 0;
        let mut min: u32 = 0;
        if bio_ptr != core::ptr::null() {
            (bd_dev, bi_sector) = bio_parse(bio_ptr)?;
            (maj, min) = dev_to_maj_min(bd_dev);
        } // try to read device number & sector

        let event = IoEvent {
            event_type: EventType::BlkMqStartRequest,
            timestamp,
            tgid,
            pid,
            inode: bio_ptr as u64, // save bio_ptr @ inode field
            dev: bd_dev,
            sector: bi_sector,
            request_ptr: req_ptr as u64,
            tag,
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
        let pid: u32 = ctx.pid();
        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let hctx_ptr: *const blk_mq_hw_ctx = ctx.arg(0).ok_or(ERR_CODE)?;
        let bd_ptr: *const blk_mq_queue_data = ctx.arg(1).ok_or(ERR_CODE)?;
        if ptr_field_is_null!(bd_ptr, blk_mq_queue_data, rq, request) {
            return Err(0);
        }
        let req_ptr: *const request =
            read_ptr_field!(bd_ptr, blk_mq_queue_data, rq, request).map_err(|_| ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        let nvmeq_ptr: *const nvme_queue =
            read_ptr_field!(hctx_ptr, blk_mq_hw_ctx, driver_data, nvme_queue)
                .map_err(|_| ERR_CODE)?;
        
        let mut bio_ptr_val: u64 = 0;
        let bio_ptr: *const bio =
            read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;
        if bio_ptr != core::ptr::null() {
            bio_ptr_val = bio_ptr as u64;
        }
        
        

        debug!(&ctx, "nvme_queue_rq //// pid {}, req_ptr {:x}, tag {}, bio_ptr {:x}", pid, req_ptr as u64, tag, bio_ptr_val);

        if let Some(&entry_ts) = BIO_MAP.get(&(bio_ptr_val)) {
            BIO_MAP.remove(&(bio_ptr as u64)).ok();
            debug!(&ctx, "nvme_queue_rq hit with pid {}, bio_ptr {:x}, elapsed {} ns", pid, bio_ptr as u64, timestamp - entry_ts);

            let data = EntryData {
                req_ptr: req_ptr as u64,
                ts_entry: timestamp,
            };
            ENTRY_MAP.insert(&pid, &data, 0).ok();

            let event = IoEvent {
                event_type: EventType::NvmeQueue,
                timestamp,
                tgid,
                pid,
                inode: bio_ptr_val,
                dev: 0,
                sector: 0,
                request_ptr: req_ptr as u64,
                tag,
                size: 0,
                flags: 0,
            };

            EVENTS.output(&ctx, &event, 0);
        }

        
        Ok(0)
    }
}

#[kretprobe]
pub fn dev_nvme_queue_rq_exit(ctx: RetProbeContext) -> u32 {
    match try_dev_nvme_queue_rq_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_dev_nvme_queue_rq_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    unsafe {
        let ret: u32 = ctx.ret().unwrap_or(1);
        if ret != 0 { return Err(0); }
        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let tgid = ctx.tgid();
        let pid = ctx.pid();

        if let Some(&data) = ENTRY_MAP.get(&pid) {
            debug!(&ctx, "nvme_queue_rq ret: pid {}, req_ptr {:x}, elapsed {} ns", pid, data.req_ptr, (timestamp - data.ts_entry));
            ENTRY_MAP.remove(&pid).ok();

            let event = IoEvent {
                event_type: EventType::NvmeQueueExit,
                timestamp,
                tgid,
                pid,
                inode: 0,
                dev: 0,
                sector: 0,
                request_ptr: data.req_ptr as u64,
                tag: 0,
                size: 0,
                flags: 0,
            };
        }

        
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
        let tgid: u32 = ctx.tgid();
        // if !check_tgid(tgid) {
        //     return Ok(0);
        // }

        let pid: u32 = ctx.pid();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        //let bio_ptr: *const bio =
        //    read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;
        //
        //let (bd_dev, bi_sector) = bio_parse(bio_ptr)?;
        //let (maj, min) = dev_to_maj_min(bd_dev);

        //        if !check_device(maj, min) {
        //            return Ok(0);
        //        };

        let event = IoEvent {
            event_type: EventType::NvmeCompleteBatch,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: 0,
            sector: 0,
            request_ptr: req_ptr as u64,
            tag,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }
    Ok(0)
}

#[kprobe]
pub fn dev_nvme_complete_rq(ctx: ProbeContext) -> u32 {
    match try_dev_nvme_complete_rq(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_dev_nvme_complete_rq(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        // let time: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let tgid: u32 = ctx.tgid();
        // if !check_tgid(tgid) {
        //     return Ok(0);
        // }

        let pid: u32 = ctx.pid();

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        //        if !check_device(maj, min) {
        //            return Ok(0);
        //        };

        let event = IoEvent {
            event_type: EventType::NvmeComplete,
            timestamp,
            tgid,
            pid,
            inode: 0,
            dev: 0,
            sector: 0,
            request_ptr: req_ptr as u64,
            tag,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
