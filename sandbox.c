
            int ret;
            Atom xa_prop_name;
            Atom xa_ret_type;
            Atom xa_delete;
            int ret_format;
            unsigned long ret_nitems;
            unsigned long ret_bytes_after;
            unsigned long tmp_size;
            unsigned char * ret_prop;

            xa_prop_name = XInternAtom(disp, "_NET_WM_STATE", True);

            ret = XGetWindowProperty(disp, window, xa_prop_name, 0,
                sizeof(Atom), False, XA_ATOM, &xa_ret_type, &ret_format,
                &ret_nitems, &ret_bytes_after, &ret_prop);
            if(ret == Success && ret_prop) {
                for(j = 0; j < ret_nitems; j++) {
                    Atom prop = ((Atom *) ret_prop)[j];
                    char * value = XGetAtomName(disp, prop);
                    fprintf(stderr, "T %s\n", value);
                }
            }