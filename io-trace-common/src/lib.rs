#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoEvent {
    pub event_type: u32,
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,

    pub dev: u32,
    pub sector: u64,
    pub inode: u64,
    pub request_ptr: u64,
    pub tag: i32,

    pub size: u32,
    pub flags: u32,
}

// 이벤트 타입
pub const EVENT_BTREE_WRITEPAGES:         u32 = 0;
pub const EVENT_BTRFS_WRITEPAGES:         u32 = 1;
pub const EVENT_BIO_SUBMIT:               u32 = 2;
pub const EVENT_BIO_COMPLETE:             u32 = 3;
pub const EVENT_NVME_QUEUE:               u32 = 4;
pub const EVENT_NVME_COMPLETE_BATCH:      u32 = 5;
pub const EVENT_NVME_COMPLETE:            u32 = 6;
pub const EVENT_BLK_MQ_START_REQUEST:     u32 = 7;
pub const EVENT_VFS_WRITE:                u32 = 8;
pub const EVENT_VFS_WRITEV:               u32 = 9;
pub const EVENT_BTRFS_DO_WRITE_ITER:      u32 = 10;
pub const EVENT_BTRFS_BUFFERED_WRITE:     u32 = 11;
pub const EVENT_BTRFS_BUFFERED_WRITE_RET: u32 = 12;