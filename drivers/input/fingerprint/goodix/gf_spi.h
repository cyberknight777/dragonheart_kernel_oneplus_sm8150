/*
 * driver definition for sensor driver
 *
 * Coypright (c) 2017 Goodix
 */
#ifndef __GF_SPI_H
#define __GF_SPI_H

#define CONFIG_MSM_RDM_NOTIFY
#undef CONFIG_FB
#if defined(CONFIG_MSM_RDM_NOTIFY)
#include <linux/msm_drm_notify.h>
#endif
#include <linux/gpio.h>
#include <linux/types.h>
#include <linux/notifier.h>
/**********************************************************/
enum FP_MODE{
	GF_IMAGE_MODE = 0,
	GF_KEY_MODE,
	GF_SLEEP_MODE,
	GF_FF_MODE,
	GF_DEBUG_MODE = 0x56
};

struct fp_underscreen_info {
    uint8_t touch_state;
    uint16_t x;
    uint16_t y;
};

#define SUPPORT_NAV_EVENT

#if defined(SUPPORT_NAV_EVENT)
#define GF_NAV_INPUT_UP			KEY_UP
#define GF_NAV_INPUT_DOWN		KEY_DOWN
#define GF_NAV_INPUT_LEFT		KEY_LEFT
#define GF_NAV_INPUT_RIGHT		KEY_RIGHT
#define GF_NAV_INPUT_CLICK		KEY_VOLUMEDOWN
#define GF_NAV_INPUT_DOUBLE_CLICK	KEY_VOLUMEUP
#define GF_NAV_INPUT_LONG_PRESS BTN_B
#define GF_NAV_INPUT_F2 KEY_F2
#define GF_NAV_INPUT_HEAVY		KEY_CHAT
#endif

#define GF_KEY_INPUT_HOME		KEY_HOME
#define GF_KEY_INPUT_MENU		KEY_MENU
#define GF_KEY_INPUT_BACK		KEY_BACK
#define GF_KEY_INPUT_POWER		KEY_POWER
#define GF_KEY_INPUT_CAMERA		KEY_CAMERA
#define GF_KEY_INPUT_LONG_PRESS		BTN_B

#if defined(SUPPORT_NAV_EVENT)
typedef enum gf_nav_event {
	GF_NAV_NONE = 0,
	GF_NAV_FINGER_UP,
	GF_NAV_FINGER_DOWN,
	GF_NAV_UP,
	GF_NAV_DOWN,
	GF_NAV_LEFT,
	GF_NAV_RIGHT,
	GF_NAV_CLICK,
	GF_NAV_HEAVY,
	GF_NAV_LONG_PRESS,
	GF_NAV_DOUBLE_CLICK,
	GF_NAV_F2,
} gf_nav_event_t;
#endif

typedef enum gf_key_event {
	GF_KEY_NONE = 0,
	GF_KEY_HOME,
	GF_KEY_POWER,
	GF_KEY_MENU,
	GF_KEY_BACK,
	GF_KEY_CAMERA,
	GF_KEY_LONGPRESS,
} gf_key_event_t;

struct gf_key {
	enum gf_key_event key;
	uint32_t value;   /* key down = 1, key up = 0 */
};

struct gf_key_map {
	unsigned int type;
	unsigned int code;
};

struct gf_ioc_chip_info {
	unsigned char vendor_id;
	unsigned char mode;
	unsigned char operation;
	unsigned char reserved[5];
};

#define GF_IOC_MAGIC    'g'     //define magic number
#define GF_IOC_INIT             _IOR(GF_IOC_MAGIC, 0, uint8_t)
#define GF_IOC_EXIT             _IO(GF_IOC_MAGIC, 1)
#define GF_IOC_RESET            _IO(GF_IOC_MAGIC, 2)
#define GF_IOC_ENABLE_IRQ       _IO(GF_IOC_MAGIC, 3)
#define GF_IOC_DISABLE_IRQ      _IO(GF_IOC_MAGIC, 4)
#define GF_IOC_ENABLE_POWER     _IO(GF_IOC_MAGIC, 7)
#define GF_IOC_DISABLE_POWER    _IO(GF_IOC_MAGIC, 8)
#define GF_IOC_INPUT_KEY_EVENT  _IOW(GF_IOC_MAGIC, 9, struct gf_key)
#define GF_IOC_ENTER_SLEEP_MODE _IO(GF_IOC_MAGIC, 10)
#define GF_IOC_GET_FW_INFO      _IOR(GF_IOC_MAGIC, 11, uint8_t)
#define GF_IOC_REMOVE           _IO(GF_IOC_MAGIC, 12)
#define GF_IOC_CHIP_INFO        _IOW(GF_IOC_MAGIC, 13, struct gf_ioc_chip_info)

#if defined(SUPPORT_NAV_EVENT)
#define GF_IOC_NAV_EVENT	_IOW(GF_IOC_MAGIC, 14, gf_nav_event_t)
#define  GF_IOC_MAXNR    15  /* THIS MACRO IS NOT USED NOW... */
#else
#define  GF_IOC_MAXNR    14  /* THIS MACRO IS NOT USED NOW... */
#endif

#define  USE_PLATFORM_BUS     1
#define GF_NETLINK_ENABLE 1
#define GF_NET_EVENT_IRQ 1
#define GF_NET_EVENT_FB_BLACK 2
#define GF_NET_EVENT_FB_UNBLACK 3
#define GF_NET_EVENT_TP_TOUCHDOWN 4
#define GF_NET_EVENT_TP_TOUCHUP 5
#define GF_NET_EVENT_UI_READY 6
#define GF_NET_EVENT_UI_DISAPPEAR 7
#define NETLINK_TEST 25
#define MAX_MSGSIZE 32

struct gf_dev {
	dev_t devt;
	struct list_head device_entry;
	struct platform_device *spi;
	struct clk *core_clk;
	struct clk *iface_clk;

	struct input_dev *input;
	/* buffer is NULL unless this device is open (users > 0) */
	unsigned users;
	signed irq_gpio;
	signed reset_gpio;
	signed pwr_gpio;
	int irq;
	int irq_enabled;
	int clk_enabled;

	struct regulator *vdd_3v2;
	int regulator_vdd_vmin;
	int regulator_vdd_vmax;
	int regulator_vdd_current;

	struct notifier_block msm_drm_notif;
	char device_available;
	char fb_black;
	struct pinctrl         *gf_pinctrl;
	struct pinctrl_state   *gpio_state_enable;
	struct pinctrl_state   *gpio_state_disable;
	signed enable_gpio;
	int screen_state;
};
static inline int gf_pinctrl_init(struct gf_dev* gf_dev);
static inline int gf_parse_dts(struct gf_dev* gf_dev);
static inline void gf_cleanup(struct gf_dev *gf_dev)
{
	pr_info("[info] %s\n",__func__);
	if (gpio_is_valid(gf_dev->irq_gpio))
	{
		gpio_free(gf_dev->irq_gpio);
		pr_info("remove irq_gpio success\n");
	}
	if (gpio_is_valid(gf_dev->reset_gpio))
	{
		gpio_free(gf_dev->reset_gpio);
		pr_info("remove reset_gpio success\n");
	}
}

static inline int gf_power_on(struct gf_dev *gf_dev)
{
	int rc = 0;

	pr_info("---- power on ok ----\n");

	return rc;
}
static inline int gf_power_off(struct gf_dev *gf_dev)
{
	int rc = 0;

    pr_info("---- power off ----\n");

	return rc;
}

static inline int gf_hw_reset(struct gf_dev *gf_dev, unsigned int delay_ms);
static inline int gf_irq_num(struct gf_dev *gf_dev);

static inline void sendnlmsg(char *msg);
static inline void sendnlmsg_tp(struct fp_underscreen_info *msg, int length);
static inline int netlink_init(void);
static inline void netlink_exit(void);
extern int gf_opticalfp_irq_handler(int event);
extern int opticalfp_irq_handler(struct fp_underscreen_info* tp_info);

#endif /*__GF_SPI_H*/
