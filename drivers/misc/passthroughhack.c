/*
 * Author: Chad Froebel <chadfroebel@gmail.com>
 *
 * Port to guacamole: engstk <eng.stk@sapo.pt>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/*
 * Possible values for "passthrough_hack" are :
 *
 *   0 - Disabled (default)
 *   1 - Enabled
*/

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/passthroughhack.h>
#include <linux/string.h>
#include <linux/module.h>

int passthrough_hack = 0;

static int __init get_passthrough_opt(char *ffc)
{
	if (strcmp(ffc, "0") == 0) {
		passthrough_hack = 0;
	} else if (strcmp(ffc, "1") == 0) {
		passthrough_hack = 1;
	} else {
		passthrough_hack = 0;
	}
	return 1;
}

__setup("ffc=", get_passthrough_opt);

static ssize_t passthrough_hack_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	size_t count = 0;
	count += sprintf(buf, "%d\n", passthrough_hack);
	return count;
}

static ssize_t passthrough_hack_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	sscanf(buf, "%d ", &passthrough_hack);
	if (passthrough_hack < 0 || passthrough_hack > 1)
		passthrough_hack = 0;

	return count;
}

static struct kobj_attribute passthrough_hack_attribute =
__ATTR(passthrough_hack, 0664, passthrough_hack_show, passthrough_hack_store);

static struct attribute *passthrough_hack_attrs[] = {
&passthrough_hack_attribute.attr,
NULL,
};

static struct attribute_group passthrough_hack_attr_group = {
.attrs = passthrough_hack_attrs,
};

/* Initialize passthrough hack sysfs folder */
static struct kobject *passthrough_hack_kobj;

int passthrough_hack_init(void)
{
	int passthrough_hack_retval;

	passthrough_hack_kobj = kobject_create_and_add("passthrough_hack", kernel_kobj);
	if (!passthrough_hack_kobj) {
			return -ENOMEM;
	}

	passthrough_hack_retval = sysfs_create_group(passthrough_hack_kobj, &passthrough_hack_attr_group);

	if (passthrough_hack_retval)
		kobject_put(passthrough_hack_kobj);

	if (passthrough_hack_retval)
		kobject_put(passthrough_hack_kobj);

	return (passthrough_hack_retval);
}

void passthrough_hack_exit(void)
{
	kobject_put(passthrough_hack_kobj);
}

module_init(passthrough_hack_init);
module_exit(passthrough_hack_exit);
