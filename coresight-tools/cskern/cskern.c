/*
 * Minimal /dev/csmem for direct userspace access to physical memory.
 *
 * Adapted from linux/drivers/char/mem.c
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/ptrace.h>
#include <linux/pfn.h>


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Devices to access physical and virtual memory");
MODULE_VERSION("0.1");


static int devmem_open(struct inode *inode, struct file *file)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}


static const struct vm_operations_struct devmem_mmap_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys
#endif
};

int __weak phys_mem_access_prot_allowed(struct file *file, unsigned long pfn, unsigned long size, pgprot_t *vma_prot)
{
	return 1;
}

static int devmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
	printk(KERN_INFO "cskern: mmap physical 0x%llx\n", (unsigned long long)offset);
	if ((offset >> PAGE_SHIFT) != vma->vm_pgoff) {
		printk(KERN_INFO "unaligned address\n");
		return -EINVAL;
        }
	if (offset + (phys_addr_t)size - 1 < offset) {
		printk(KERN_INFO "address wrapped zero\n");
		return -EINVAL;
	}
	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size, &vma->vm_page_prot)) {
		printk(KERN_INFO "prot not allowed\n");
		return -EINVAL;
	}
	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff, size, vma->vm_page_prot);
	vma->vm_ops = &devmem_mmap_ops;
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size, vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}


static int devkmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long pfn;
	printk(KERN_INFO "cskern: mmap virtual %p\n", (void const *)(vma->vm_pgoff << PAGE_SHIFT));
	pfn = __pa((u64)vma->vm_pgoff << PAGE_SHIFT) >> PAGE_SHIFT;
	return -EIO;
	if (!pfn_valid(pfn))
		return -EIO;
	vma->vm_pgoff = pfn;
	return devmem_mmap(file, vma);
}


enum {
	MINOR_MEM = 0,
	MINOR_KMEM = 1
};


static const struct file_operations devmem_ops = {
	.open   = devmem_open,
	.mmap   = devmem_mmap
};

static const struct file_operations devkmem_ops = {
	.open	= devmem_open,		/* same as mem */
	.mmap	= devkmem_mmap
};


static int csmem_class_open(struct inode *inode, struct file *filp)
{
 	int minor;
	if (minor == MINOR_MEM) {
		filp->f_op = &devmem_ops;
		return devmem_open(inode, filp);
	} else if (minor == MINOR_KMEM) {
		filp->f_op = &devkmem_ops;
		return devmem_open(inode, filp);
	} else {
		return -ENXIO;
	}
}


static const struct file_operations csmem_class_ops = {
	.open	= csmem_class_open
};


static struct class *csmem_class;
static dev_t csmem_dev;
static int csmem_major;

static struct cdev cs_memdev, cs_kmemdev;

#define SEQ "2"

static int create_devmem(void)
{
	/* Dynamically allocate a major device number with two minors */
	alloc_chrdev_region(&csmem_dev, 0, 2, "csmemregion" SEQ);
	csmem_major = MAJOR(csmem_dev);
	printk(KERN_INFO "Allocated csmem major class %u\n", csmem_major);

	/* Create the 'csmem' device class. This will create a file /sys/class/csmem. */
	csmem_class = class_create(THIS_MODULE, "csmemclass" SEQ);
	if (IS_ERR(csmem_class)) {
		printk(KERN_INFO "Failed to create device class\n");
		return PTR_ERR(csmem_class);
	}

	cdev_init(&cs_memdev, &devmem_ops);
	device_create(csmem_class, NULL, MKDEV(csmem_major, MINOR_MEM), NULL, "csmem");
	cdev_add(&cs_memdev, MKDEV(csmem_major, MINOR_MEM), 1);
        printk(KERN_INFO "Created /dev/csmem\n");
	cdev_init(&cs_kmemdev, &devmem_ops);
	device_create(csmem_class, NULL, MKDEV(csmem_major, MINOR_KMEM), NULL, "cskmem");
	cdev_add(&cs_kmemdev, MKDEV(csmem_major, MINOR_KMEM), 1);
        printk(KERN_INFO "Created /dev/cskmem\n");
	return 0;
}


static int __init cskern_init(void)
{
	int rc;
	printk(KERN_INFO "CoreSight memory-mapped access module\n");
#if defined(CONFIG_DEVMEM) && defined(CONFIG_DEVKMEM)
	printk(KERN_INFO "Advisory: CONFIG_DEVMEM and CONFIG_DEVKMEM are set, you shouldn't need this module\n");
#endif
	rc = create_devmem();
	/* Return 0 to indicate the module loaded */
	return rc;
}


static void __exit cskern_exit(void)
{
	printk(KERN_INFO "CoreSight kernel module unloading...\n");
	if (!IS_ERR(csmem_class)) {
		device_destroy(csmem_class, MKDEV(csmem_major, MINOR_MEM));
		device_destroy(csmem_class, MKDEV(csmem_major, MINOR_KMEM));
		csmem_class = NULL;
	}
}


module_init(cskern_init);
module_exit(cskern_exit);
