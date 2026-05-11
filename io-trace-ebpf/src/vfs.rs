use aya_ebpf::EbpfContext;
use aya_ebpf::cty::size_t;
use aya_ebpf::helpers;
use aya_ebpf::macros::{kprobe, kretprobe, fexit};
use aya_ebpf::programs::{ProbeContext, RetProbeContext, FExitContext};
use aya_log_ebpf::debug;

use io_trace_common::{EventType, IoEvent};

use crate::btf::vmlinux::{
    address_space, address_space_operations, atomic_long_t, dev_t, ext4_fsblk_t, ext4_lblk_t, ext4_map_blocks, file, inode, kiocb, loff_t, super_block
};
use crate::define_probe;
use crate::helpers::{ERR_CODE, check_tgid};
use crate::maps::EVENTS;
use crate::{read_field, read_ptr_field};

define_probe!(#[kprobe] vfs_vfs_write, ProbeContext, try_vfs_vfs_write);
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
        let pos_val: loff_t =
            aya_ebpf::helpers::bpf_probe_read_kernel(pos).map_err(|_| ERR_CODE)?;

        let f_mode: u32 = read_field!(file, file, f_mode, u32).map_err(|_| ERR_CODE)?;
        if (f_mode & 0x2) == 0 {
            return Ok(0);
        } // FMODE_WRITE     / -EBADF
        if (f_mode & 0x40000) == 0 {
            return Ok(0);
        } // FMODE_CAN_WRITE / -EINVAL

        let f_inode: *const inode =
            read_ptr_field!(file, file, f_inode, inode).map_err(|_| ERR_CODE)?;

        let i_sb: *const super_block =
            read_ptr_field!(f_inode, inode, i_sb, super_block).map_err(|_| ERR_CODE)?;
        let s_dev: u32 = read_field!(i_sb, super_block, s_dev, dev_t).map_err(|_| ERR_CODE)?;
        let i_ino: u64 = read_field!(f_inode, inode, i_ino, u64).map_err(|_| ERR_CODE)?;

        debug!(
            &ctx,
            "vfs_write hit, tgid {} / pid {} / count {} / pos {:x} / pos_val {} / inode {}",
            tgid, pid, count, pos as u64, pos_val, i_ino
        );

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

define_probe!(#[kretprobe] vfs_vfs_write_ret, RetProbeContext, try_vfs_vfs_write_ret);
fn try_vfs_vfs_write_ret(ctx: RetProbeContext) -> Result<u32, u32> {
    unsafe {
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

define_probe!(#[kprobe] fs_generic_perform_write, ProbeContext, try_fs_generic_perform_write);
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

        let pos: loff_t = read_field!(iocb, kiocb, ki_pos, loff_t).map_err(|_| ERR_CODE)?;

        let f_inode: *const inode =
            read_ptr_field!(file, file, f_inode, inode).map_err(|_| ERR_CODE)?;

        let i_sb: *const super_block =
            read_ptr_field!(f_inode, inode, i_sb, super_block).map_err(|_| ERR_CODE)?;
        let s_dev: u32 = read_field!(i_sb, super_block, s_dev, dev_t).map_err(|_| ERR_CODE)?;
        let i_ino: u64 = read_field!(f_inode, inode, i_ino, u64).map_err(|_| ERR_CODE)?;

        let count: i64 = read_field!(file, file, f_count, atomic_long_t)
            .map_err(|_| ERR_CODE)?
            .counter;

        let mapping: *const address_space =
            read_ptr_field!(file, file, f_mapping, address_space).map_err(|_| ERR_CODE)?;
        let _a_ops: *const address_space_operations =
            read_ptr_field!(mapping, address_space, a_ops, address_space_operations)
                .map_err(|_| ERR_CODE)?;

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        debug!(
            &ctx,
            "generic_perform_write hit: tgid {} / pid {} / count {} / pos {} / inode {}",
            tgid, pid, count, pos, i_ino
        );

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

define_probe!(#[kprobe] fs_iomap_file_buffered_write, ProbeContext, try_fs_iomap_file_buffered_write);
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

define_probe!(#[kprobe] fs_do_writepages, ProbeContext, try_fs_do_writepages);
fn try_fs_do_writepages(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        let pid: u32 = ctx.pid();
        if !check_tgid(tgid) {
            return Ok(0);
        }
        
        let mapping: *const address_space = ctx.arg(0).ok_or(ERR_CODE)?;
        let host: *const inode = read_ptr_field!(mapping, address_space, host, inode).map_err(|_| ERR_CODE)?;

        debug!(&ctx, "do_writepages hit: tgid {} / pid {} / inode* {:x}", tgid, pid, host as u64);
        Ok(0)
    }
}

define_probe!(#[fexit] fs_ext4_map_blocks, FExitContext, try_fs_ext4_map_blocks);
fn try_fs_ext4_map_blocks(ctx: FExitContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        let pid: u32 = ctx.pid();
        if !check_tgid(tgid) {
            return Ok(0);
        }

        let inode: *const inode = ctx.arg(1);
        let map: *const ext4_map_blocks = ctx.arg(2);
        
        let m_pblk: ext4_fsblk_t = read_field!(map, ext4_map_blocks, m_pblk, ext4_fsblk_t).map_err(|_| ERR_CODE)?;
        let m_lblk: ext4_lblk_t = read_field!(map, ext4_map_blocks, m_lblk, ext4_lblk_t).map_err(|_| ERR_CODE)?;
        let m_len: u32 = read_field!(map, ext4_map_blocks, m_len, u32).map_err(|_| ERR_CODE)?;
        let m_flags: u32 = read_field!(map, ext4_map_blocks, m_flags, u32).map_err(|_| ERR_CODE)?;

        let i_blkbits = read_field!(inode, inode, i_blkbits, u8).map_err(|_| ERR_CODE)?;

        let inode_holder: u64 = inode as u64;
        let inode_addr: u64 = aya_ebpf::helpers::bpf_probe_read_kernel(&inode_holder as *const u64)
            .map_err(|_| ERR_CODE)?;

        let sector: u64 = m_pblk << (i_blkbits - 9);
        debug!(&ctx, "ext4_map_block ret: tgid {} / pid {} / inode* {:x} / m_pblk {}, m_lblk {}, m_len {}, m_flags {} / sector {}", tgid, pid, inode_addr, m_pblk, m_lblk, m_len, m_flags, sector);

        /*
            m_flags could be:
                /*
                 * Logical to physical block mapping, used by ext4_map_blocks()
                 *
                 * This structure is used to pass requests into ext4_map_blocks() as
                 * well as to store the information returned by ext4_map_blocks().  It
                 * takes less room on the stack than a struct buffer_head.
                 */
                #define EXT4_MAP_NEW		BIT(BH_New)
                #define EXT4_MAP_MAPPED		BIT(BH_Mapped)
                #define EXT4_MAP_UNWRITTEN	BIT(BH_Unwritten)
                #define EXT4_MAP_BOUNDARY	BIT(BH_Boundary)
                #define EXT4_MAP_DELAYED	BIT(BH_Delay)
                #define EXT4_MAP_FLAGS		(EXT4_MAP_NEW | EXT4_MAP_MAPPED |\
                				 EXT4_MAP_UNWRITTEN | EXT4_MAP_BOUNDARY |\
                				 EXT4_MAP_DELAYED)
        */
    }
    Ok(0)
}