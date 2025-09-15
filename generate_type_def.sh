#!/bin/bash

# bio, block_device, bvec_iter for submit_bio() and bio_endio()
# blk_mq_hw_ctx, nvme_queue, nvme_dev for nvme_queue_rq()

aya-tool generate \
	bio \
	block_device \
	bvec_iter \
	blk_mq_hw_ctx \
	> io-trace-ebpf/src/vmlinux.rs

aya-tool generate \
	--btf /sys/kernel/btf/nvme \
	nvme_queue \
	nvme_dev \
	> io-trace-ebpf/src/nvme.rs
