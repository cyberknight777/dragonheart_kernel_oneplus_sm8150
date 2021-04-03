#ifndef __IM_H__
#define __IM_H__

#include <linux/sched.h>

/* since im_flag is 32bit, don't identify too much */
enum {
	IM_ID_SURFACEFLINGER = 0, // surfaceflinger
	IM_ID_KWORKER, // kworker
	IM_ID_LOGD, // logd
	IM_ID_LOGCAT, //logcat
	IM_ID_UX, //ux
	IM_ID_RENDER, //render
	IM_ID_MAIN, //app main
	IM_ID_ENQUEUE, //enqueue frame task
	IM_ID_GL, //open GL tasks
	IM_ID_VK, // vulkan tasks
	IM_ID_HWC, //hwcomposer
	IM_ID_HWBINDER, // hw binder
	IM_ID_BINDER, // binder
	IM_ID_HWUI, //hwui
	IM_ID_LAUNCHER, //launcher app
	IM_ID_MAX
};

#define IM_SURFACEFLINGER (1 << IM_ID_SURFACEFLINGER)
#define IM_KWORKER        (1 << IM_ID_KWORKER)
#define IM_LOGD           (1 << IM_ID_LOGD)
#define IM_LOGCAT         (1 << IM_ID_LOGCAT)
#define IM_UX             (1 << IM_ID_UX)
#define IM_RENDER         (1 << IM_ID_RENDER)
#define IM_GL             (1 << IM_ID_GL)
#define IM_VK             (1 << IM_ID_VK)
#define IM_HWC            (1 << IM_ID_HWC)
#define IM_HWBINDER       (1 << IM_ID_HWBINDER)
#define IM_BINDER         (1 << IM_ID_BINDER)

/* to be update */
enum {
	IM_IG_SF_PROBER = 0,
	IM_IG_SF_APP,
	IM_IG_SF_SF,
	IM_IG_SF_DISPSYNC,
	IM_IG_SF_SCREENSHOTTHRES,
	IM_IG_HWC_DPPS,
	IM_IG_HWC_LTM,
	IM_IG_MAX
};

extern void im_wmi(struct task_struct *task);
extern void im_wmi_current(void);
extern void im_set_flag(struct task_struct *task, int flag);
extern void im_set_flag_current(int flag);
extern void im_unset_flag(struct task_struct *task, int flag);
extern void im_unset_flag_current(int flag);
extern void im_reset_flag(struct task_struct *task);
extern void im_reset_flag_current(void);
extern void im_set_op_group(struct task_struct *task, int flag, bool insert);
extern int im_render_grouping_enable(void);
extern void im_list_add_task(struct task_struct *task);
extern void im_list_del_task(struct task_struct *task);

extern void im_to_str(int flag, char* desc, int size);
#else
static inline bool im_sf(struct task_struct *task) { return false; }
static inline bool im_kw(struct task_struct *task) { return false; }
static inline bool im_logd(struct task_struct *task) { return false; }
static inline bool im_logcat(struct task_struct *task) { return false; }
static inline bool im_rendering(struct task_struct *task) { return false; }
static inline bool im_ux(struct task_struct *task) { return false; }
static inline bool im_render(struct task_struct *task) { return false; }
static inline bool im_gl(struct task_struct *task) { return false; }
static inline bool im_vk(struct task_struct *task) { return false; }
static inline bool im_hwc(struct task_struct *task) { return false; }
static inline bool im_hwbinder(struct task_struct *task) { return false; }
static inline bool im_binder(struct task_struct *task) { return false; }
static inline bool im_binder_related(struct task_struct *task) { return false; }

static inline void im_wmi(struct task_struct *task) {}
static inline void im_wmi_current(void) {}
static inline void im_set_flag(struct task_struct *task, int flag) {}
static inline void im_set_flag_current(int flag) {}
static inline void im_unset_flag(struct task_struct *task, int flag) {}
static inline void im_unset_flag_current(int flag) {}
static inline void im_reset_flag(struct task_struct *task) {}
static inline void im_reset_flag_current(void) {}
static inline void im_set_op_group(struct task_struct *task,
			int flag, bool insert) {}
static inline int im_render_grouping_enable(void) { return 0; }
static inline void im_list_add_task(struct task_struct *task) {}
static inline void im_list_del_task(struct task_struct *task) {}
static inline void im_to_str(int flag, char* desc, int size) {}
#endif

#endif
