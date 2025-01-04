# IOMMUVM

IO Memory protection mechanisms prevent malicious and/or buggy IO devices. It achieves protection by using IOMMU to translate device addresses to physical addresses. However, recent research has found that providing strict memory protections with IOMMU naively may degrade application’s performance by up to 60% [1]. To provide the strongest safety property (commonly referred as strict mode), immediately after usage of each IO virtual address (IOVA), IOVA will be unmapped and corresponding IOTLB entries will be invalidated. Such operation leads to non trivial performance overhead and may degrade application performance significantly.

The performance impact is exacerbated in virtualized cases since nested IO page table walks are more expensive and frequent VM exits may also happen. Applications like Memcached and nginx may suffer from up to 97% throughput degradation while enforcing strict safety properties [2]. We wish to further explore the root cause of performance degradation in the virtualized and develop techniques to achieve close to native performance.

We plan to first profile application’s performance (Redis, Memacached, nginx) under strict, lazy and passthrough policies. We will need connected servers with CX6 NICs (e.g. r650 or 6525). We will analyze the performance breakdown, and develop OS-hypervisor techniques to make IOPT translation faster or reduce the number of IOTLB invalidations.


[1] Benny Rubin, Saksham Agarwal, Qizhe Cai, and Rachit Agarwal. 2024. Fast &amp; Safe IO Memory Protection. In Proceedings of the ACM SIGOPS 30th Symposium on Operating Systems Principles (SOSP '24). Association for Computing Machinery, New York, NY, USA, 95–109. https://doi.org/10.1145/3694715.3695943

[2] Kun Tian, Yu Zhang, Luwei Kang, Yan Zhao, and Yaozu Dong. 2020. CoIOMMU: a virtual IOMMU with cooperative DMA buffer tracking for efficient memory management in direct I/O. In Proceedings of the 2020 USENIX Conference on Usenix Annual Technical Conference (USENIX ATC'20). USENIX Association, USA, Article 32, 479–492.
