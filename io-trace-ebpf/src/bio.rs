use aya_ebpf::EbpfContext;
use aya_ebpf::helpers;
use aya_ebpf::macros::kprobe;
use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::debug;

use io_trace_common::{EventType, IoEvent, dev_to_maj_min};

use crate::btf::vmlinux::{bio, bvec_iter, request};
use crate::define_probe;
use crate::helpers::{ERR_CODE, bio_get_start_sector, bio_parse, check_tgid};
use crate::maps::{BIO_MAP, EVENTS, IN_NVME_QUEUE_RQ};
use crate::{read_field, read_ptr_field};

define_probe!(#[kprobe] bio_submit_bio, ProbeContext, try_bio_submit_bio);
fn try_bio_submit_bio(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        //if !check_tgid(tgid) {
        //    return Ok(0);
        //}

        let pid: u32 = ctx.pid();
        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let req_ptr: *const bio = ctx.arg(0).ok_or(ERR_CODE)?;

        let (bd_dev, bi_sector) = bio_parse(req_ptr)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        let bd_start_sect: u64 = bio_get_start_sector(req_ptr)?;

        let bi_size: u32 = read_field!(req_ptr, bio, bi_iter, bvec_iter)
            .map_err(|_| ERR_CODE)?
            .bi_size;

        debug!(
            &ctx,
            "submit_bio hit, tgid {}, pid {}, bio_ptr {:x}, dev ({}, {}), sector {}, size {}",
            tgid, pid, req_ptr as u64, maj, min, bi_sector, bi_size
        );

        BIO_MAP.insert(&(req_ptr as u64), &timestamp, 0).ok();

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

define_probe!(#[kprobe] bio_bio_endio, ProbeContext, try_bio_bio_endio);
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

define_probe!(#[kprobe] bio_blk_mq_start_request, ProbeContext, try_bio_blk_mq_start_request);
fn try_bio_blk_mq_start_request(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let in_ctx = IN_NVME_QUEUE_RQ.get(0).copied().unwrap_or(0);
        if in_ctx == 0 {
            return Ok(0);
        }

        let tgid: u32 = ctx.tgid();
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

        debug!(&ctx, "blk_mq_start_request hit /////// bio_ptr: {:x}", bio_ptr as u64);
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
