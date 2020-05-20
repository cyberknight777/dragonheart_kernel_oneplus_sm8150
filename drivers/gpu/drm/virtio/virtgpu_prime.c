/*
 * Copyright 2014 Canonical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Andreas Pokorny
 */

#include <drm/ttm/ttm_page_alloc.h>
#include "virtgpu_drv.h"

struct sg_table *virtgpu_gem_prime_get_sg_table(struct drm_gem_object *gobj)
{
	struct virtio_gpu_object *obj = gem_to_virtio_gpu_obj(gobj);
	unsigned long npages = obj->tbo.num_pages;

	return drm_prime_pages_to_sg(obj->tbo.ttm->pages, npages);
}

void *virtgpu_gem_prime_vmap(struct drm_gem_object *obj)
{
	struct virtio_gpu_object *bo = gem_to_virtio_gpu_obj(obj);
	int ret;

	ret = virtio_gpu_object_kmap(bo);
	if (ret)
		return NULL;
	return bo->vmap;
}

void virtgpu_gem_prime_vunmap(struct drm_gem_object *obj, void *vaddr)
{
	virtio_gpu_object_kunmap(gem_to_virtio_gpu_obj(obj));
}

int virtgpu_gem_prime_mmap(struct drm_gem_object *gobj,
			   struct vm_area_struct *vma)
{
	struct virtio_gpu_object *obj = gem_to_virtio_gpu_obj(gobj);
	int ret = 0;

	/*
	 * ttm_fbdev_mmap() returns -EACCESS unless vma->vm_pgoff is 0.
	 * vma->vm_pgoff is tentatively set to 0 and updated after
	 * ttm_fbdev_mmap().
	 */
	unsigned long pgoff = vma->vm_pgoff;

	vma->vm_pgoff = 0;
	ret = ttm_fbdev_mmap(vma, &obj->tbo);

	/*
	 * TTM does the real mapping via its page fault handler,
	 * ttm_bo_vm_fault(), which handles vma->vm_pgoff correctly.
	 */
	vma->vm_pgoff = pgoff + drm_vma_node_start(&obj->tbo.vma_node);

	return ret;
}
