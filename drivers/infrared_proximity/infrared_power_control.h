#include <linux/alarmtimer.h>

#define INFRARED_TAG                  "[oneplus_infrared] "
#define INFRARED_ERR(fmt, args...)    pr_err_once(INFRARED_TAG" %s : "fmt,__func__,##args)
#define INFRARED_LOG(fmt, args...)    pr_debug_ratelimited(INFRARED_TAG" %s : "fmt,__func__,##args)


typedef struct oneplus_infrared_state {
    int                     infrared_power_enable;
    int                     infrared_shutdown_state;
    int                     infrared_shutdown_state2;
    int		                infrared_irq;
    int                     irq_times;
    unsigned int	        infrared_gpio;
    struct device           *dev;
    struct regulator        *vdd;
    struct pinctrl          *pctrl;
    struct pinctrl_state    *shutdown_state;
    struct delayed_work	    infrared_irq_check_work;
} oneplus_infrared_state;
