/* Mimic Chromium's Linux gamepad discovery: libudev enumerate input devices, pick joysticks, open evdev node. */
#include <libudev.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/input.h>
int main(void) {
  struct udev *u = udev_new(); if (!u) { puts("udev_new failed"); return 1; }
  struct udev_enumerate *e = udev_enumerate_new(u);
  udev_enumerate_add_match_subsystem(e, "input");
  udev_enumerate_scan_devices(e);
  int n = 0, joy = 0;
  struct udev_list_entry *it;
  udev_list_entry_foreach(it, udev_enumerate_get_list_entry(e)) {
    struct udev_device *d = udev_device_new_from_syspath(u, udev_list_entry_get_name(it));
    if (!d) { printf("  new_from_syspath failed for %s\n", udev_list_entry_get_name(it)); continue; }
    n++;
    const char *node = udev_device_get_devnode(d);
    const char *isjoy = udev_device_get_property_value(d, "ID_INPUT_JOYSTICK");
    if (node && isjoy && strncmp(node, "/dev/input/event", 16) == 0) {
      joy++;
      int fd = open(node, O_RDONLY | O_NONBLOCK);
      char name[128] = "?";
      if (fd >= 0) { if (ioctl(fd, EVIOCGNAME(sizeof name), name) < 0) snprintf(name, sizeof name, "ioctl: %s", strerror(errno)); close(fd); }
      printf("  joystick %s open=%s name=%s\n", node, fd >= 0 ? "ok" : strerror(errno), name);
    }
    udev_device_unref(d);
  }
  printf("input devices=%d joysticks=%d\n", n, joy);
  struct udev_monitor *m = udev_monitor_new_from_netlink(u, "udev");
  printf("udev monitor: %s\n", m ? (udev_monitor_enable_receiving(m) == 0 ? "ok" : strerror(errno)) : "create failed");
  return 0;
}
