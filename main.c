#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <signal.h>
#include <unistd.h>

#include <proc/readproc.h>

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <X11/Xpoll.h>

#include <X11/extensions/XInput.h>
#include <X11/extensions/XInput2.h>

#include "map.h"

static volatile sig_atomic_t stop = 0;
static Window renoise_window = None;
static hashmap * plugins;

typedef struct watch_data
{
    Display * disp;
    Window window;
} watch_data_t;

static int get_renoise_pid()
{
    PROCTAB * ptp;
    proc_t task;
    int pid = -1;

    ptp = openproc(PROC_FILLCOM | PROC_FILLSTAT);
    memset(&task, 0, sizeof (task));
	while(readproc(ptp, &task)) {
        char * pname;

        if(!task.cmdline)
            continue;

        pname = *task.cmdline;
        if(!pname)
            continue;

        pname = basename(pname);
        if(!strcmp(pname, "renoise")) {
            pid = task.XXXID;
            break;
        }
    }

    closeproc(ptp);

    return pid;
}

static void stop_watching(int signum)
{
    stop = 1;
}

static int handle_xerror(Display * disp, XErrorEvent * xe)
{
    if(xe->error_code == BadWindow) {
        fprintf(stderr, "Warning: BadWindow occured - normally this should be uncritical.\n");
    } else {
        fprintf(stderr, "X11 Error: %d\n", xe->error_code);
    }
    return 0;
}

static char * get_property (Display * disp , Window win, Atom xa_prop_type,
    char * prop_name, unsigned long * size)
{
    Atom xa_prop_name;
    Atom xa_ret_type;
    int ret_format;
    unsigned long ret_nitems;
    unsigned long ret_bytes_after;
    unsigned long tmp_size;
    unsigned char * ret_prop;
    char * ret;
    char * name;

    xa_prop_name = XInternAtom(disp, prop_name, False);

    if (XGetWindowProperty(disp, win, xa_prop_name, 0, 4096 / 4, False,
            xa_prop_type, &xa_ret_type, &ret_format,
            &ret_nitems, &ret_bytes_after, &ret_prop) != Success) {
        fprintf(stderr, "Cannot get %s property.\n", prop_name);
        return NULL;
    }

    if (xa_ret_type != xa_prop_type) {
        fprintf(stderr, "Invalid type of %s property.\n", prop_name);
        XFree(ret_prop);
        return NULL;
    }

    tmp_size = (ret_format / 8) * ret_nitems;
    if(ret_format == 32) tmp_size *= sizeof(long)/4;

    ret = malloc(tmp_size + 1);
    memcpy(ret, ret_prop, tmp_size);
    ret[tmp_size] = '\0';

    if (size) {
        *size = tmp_size;
    }

    XFree(ret_prop);
    return ret;
}

static Window *get_windows(Display * disp, unsigned long * size)
{
    Window * windows;

    if((windows = (Window *) get_property(disp, DefaultRootWindow(disp),
                    XA_WINDOW, "_NET_CLIENT_LIST", size)) == NULL) {
        if((windows = (Window *) get_property(disp, DefaultRootWindow(disp),
                        XA_CARDINAL, "_WIN_CLIENT_LIST", size)) == NULL) {
            fprintf(stderr, "Cannot get client list properties. (_NET_CLIENT_LIST or _WIN_CLIENT_LIST)\n");
            return NULL;
        }
    }

    return windows;
}

static int register_plugin(Display * disp, Window window, char * title)
{
    watch_data_t * data = malloc(sizeof(watch_data_t));
    Atom xa_delete;

    xa_delete = XInternAtom(disp, "WM_DELETE_WINDOW", True);

    XSetWMProtocols(disp, window, &xa_delete, 1);
    XSelectInput(disp, window, ExposureMask | KeyPressMask |
        KeyReleaseMask | StructureNotifyMask | FocusChangeMask);

    data->disp = disp;
    data->window = window;

    fprintf(stdout, "+ Sub-Window 0x%08x: %s\n", window, title);

    hashmap_set(plugins, (void *) &(data->window), sizeof(Window),
        (uintptr_t) data);

    return 0;
}

static int register_new_plugins(int pid, Display * disp)
{
    int i, j, ret;
    Window * windows;
    unsigned long nwindows;
    Window * opened;

    if ((windows = get_windows(disp, &nwindows)) == NULL) {
        return 1;
    }

    for (i = 0; i < nwindows / sizeof(Window); i++) {
        unsigned long * wpid;
        char * wtitle;
        watch_data_t * wdata;
        Window window = windows[i];

        wpid = (unsigned long *) get_property(disp, window, XA_CARDINAL,
            "_NET_WM_PID", NULL);
        if(!wpid || *wpid != pid)
            continue;

        wtitle = (char *) get_property(disp, window, XA_STRING,
            "WM_NAME", NULL);
        if(!wtitle)
            continue;

        if(strstr(wtitle, "Renoise (") == wtitle) {
            renoise_window = window;
            continue;
        }

        if(!hashmap_get(plugins, (void *) &windows[i], sizeof(Window),
                (uintptr_t *) &wdata)) {
            Window window = windows[i];
            Window root, parent, *children = NULL;
            unsigned int nchildren;

            if(!XQueryTree(disp, window, &root, &parent, &children, &nchildren)) {
                continue;
            }

            if(nchildren > 0) {
                register_plugin(disp, window, wtitle);
                XSetInputFocus(disp, window, RevertToParent, CurrentTime);

                if (children) {
                    for(j = 0; j < nchildren; j++) {
                        register_plugin(disp, children[j], wtitle);
                    }

                    XFree((char *)children);
                }
            }
        }

        free(wtitle);
        free(wpid);
    }

    free(windows);

    return 0;
}

Window get_window_parent(Display * disp, Window window)
{
    Window root, parent, *children = NULL;
    unsigned int nchildren;

    if(!XQueryTree(disp, window, &root, &parent, &children, &nchildren)) {
        return None;
    }

    if (children) {
        XFree((char *)children);
    }

    return parent;
}

static int watch_plugins(int pid)
{
    Display * disp;
    int xi_opcode;
    int event, error;

    XSetErrorHandler(handle_xerror);

    if(!(disp = XOpenDisplay(NULL))) {
        fprintf(stderr, "Cannot open X11 display.\n");
        return 1;
    }

    if (XQueryExtension(disp, "XInputExtension", &xi_opcode, &event, &error)) {
        int x11_fd;
        fd_set in_fds;
        Window active = None;
		XIEventMask m;

        fprintf(stdout, "XInput detected (opcode = 0x%02x)\n", xi_opcode);

        memset(&m, 0, sizeof(XIEventMask));

        m.deviceid = XIAllMasterDevices;
        m.mask_len = XIMaskLen(XI_LASTEVENT);
        m.mask = calloc(m.mask_len, sizeof(char));

        XISetMask(m.mask, XI_RawKeyPress);
        XISetMask(m.mask, XI_RawKeyRelease);
		XISelectEvents(disp, DefaultRootWindow(disp), &m, 1);
        XSync(disp, False);

        x11_fd = ConnectionNumber(disp);
        fprintf(stdout, "Listening for X11 events (fd = 0x%02x)\n", x11_fd);

        plugins = hashmap_create();

        signal(SIGINT, stop_watching);
        do {
            int ret;
            struct timeval tv;
            XEvent ev;

            FD_ZERO(&in_fds);
            FD_SET(x11_fd, &in_fds);

            tv.tv_usec = 500 * 1000;
            tv.tv_sec = 0;

            // Wait for X Event or a Timer
            ret = select(x11_fd + 1, &in_fds, NULL, NULL, &tv);
            if (ret > 0) {
                // printf("Event Received!\n");
            } else if (ret == 0) {
                ret = register_new_plugins(pid, disp);
                if(ret) {
                    fprintf(stderr, "Registering new plugins failed (%d).\n", ret);
                    break;
                }

                if(active == None) {
                    Window focused;
                    int revert_to;
                    watch_data_t * data;

                    XGetInputFocus(disp, &focused, &revert_to);
                    if(hashmap_get(plugins, (void *) &focused, sizeof(Window),
                        (uintptr_t *) &data)) {
                        active = focused;
                        XAutoRepeatOff(disp);
                        fprintf(stdout, "F Sub-Window 0x%08x\n", active);
                    }
                }
            } else {
                fprintf(stderr, "Wait for X11 events or timer failed (%d).\n", ret);
                break;
            }

            while(XPending(disp)) {
                watch_data_t * data;
                Window window;

                XNextEvent(disp, &ev);

                switch(ev.type) {
                case GenericEvent:
                    XGenericEventCookie *cookie = (XGenericEventCookie*)&ev.xcookie;

                    if (XGetEventData(disp, cookie) && cookie->type == GenericEvent && cookie->extension == xi_opcode && active != None) {
                        if (cookie->evtype == XI_RawKeyPress) {
                            XKeyEvent e;
                            XIRawEvent *re = (XIRawEvent *) cookie->data;

                            printf("P device=%d source=%d time=%ld detail=%d\n", re->deviceid, re->sourceid, re->time, re->detail);

                            e.display = disp;
                            e.window = renoise_window;
                            e.root = RootWindow(disp, DefaultScreen(disp));
                            e.subwindow = None;
                            e.time = CurrentTime;
                            e.x = e.y = 1;
                            e.x_root = e.y_root = 1;
                            e.same_screen = 1;
                            e.keycode = re->detail;

                            e.type = KeyPress;

                            XSendEvent(disp, renoise_window, 1, KeyPressMask, (XEvent *)&e);
                        } else if (cookie->evtype == XI_RawKeyRelease) {
                            XKeyEvent e;
                            XIRawEvent *re = (XIRawEvent *) cookie->data;

                            printf("R device=%d source=%d time=%ld detail=%d\n", re->deviceid, re->sourceid, re->time, re->detail);

                            e.display = disp;
                            e.window = renoise_window;
                            e.root = RootWindow(disp, DefaultScreen(disp));
                            e.subwindow = None;
                            e.time = CurrentTime;
                            e.x = e.y = 1;
                            e.x_root = e.y_root = 1;
                            e.same_screen = 1;
                            e.keycode = re->detail;

                            e.type = KeyRelease;

                            XSendEvent(disp, renoise_window, 1, KeyReleaseMask, (XEvent *)&e);
                        }
                    }
                    break;
                case FocusIn:
                    window = ev.xfocus.window;

                    if(hashmap_get(plugins, (void *) &window, sizeof(Window),
                        (uintptr_t *) &data)) {
                        active = ev.xfocus.window;
                        XAutoRepeatOff(disp);
                        fprintf(stdout, "F Sub-Window 0x%08x\n", active);
                    }
                    break;
                case FocusOut:
                    XAutoRepeatOn(disp);
                    active = None;
                    fprintf(stdout, "L\n");
                    break;
                case DestroyNotify:
                    window = ev.xdestroywindow.window;

                    if(hashmap_get(plugins, (void *) &window, sizeof(Window),
                        (uintptr_t *) &data)) {
                        hashmap_remove(plugins, (void *) &window, sizeof(Window));
                        free(data);

                        fprintf(stdout, "- Sub-Window 0x%08x\n", window);
                        if(active == window) {
                            fprintf(stdout, "L\n");
                            XAutoRepeatOn(disp);
                            active = None;
                        }
                    }
                    break;
                }
            }
        } while(!stop);

        hashmap_free(plugins);
    }

    XCloseDisplay(disp);

    return 0;
}

int main(int argc, char * argv[])
{
    int pid = get_renoise_pid();
    if(pid < 0) {
        fprintf(stderr, "Please run renoise!\n");
        return 1;
    }

    fprintf(stdout, "Found Renoise process: %d\n", pid);

    return watch_plugins(pid);
}