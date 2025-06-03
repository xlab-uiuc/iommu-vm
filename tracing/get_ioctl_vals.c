#include <stdio.h>
#include <linux/vfio.h> // Use the system's vfio.h
#include <sys/ioctl.h>  // For _IO, _IOW definitions

int main()
{
  printf("VFIO_IOMMU_MAP_DMA: 0x%lx\n", (unsigned long)VFIO_IOMMU_MAP_DMA);
  printf("VFIO_IOMMU_UNMAP_DMA: 0x%lx\n", (unsigned long)VFIO_IOMMU_UNMAP_DMA);
  return 0;
}