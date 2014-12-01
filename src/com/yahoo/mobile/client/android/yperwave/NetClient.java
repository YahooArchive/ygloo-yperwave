package com.yahoo.mobile.client.android.yperwave;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import android.os.Environment;
import android.util.Log;

public class NetClient {
    private static final String LOG_TAG = "yperwave::netclient";

    private static final boolean DEBUG_INSTR = false;
    private static final boolean DEBUG_PERF = false;

    // Global setting for enabling or disabling JNI interface. Set
    // to -1 for automatic initialization, 0 for forcing off, 1 for
    // forcing on
    private static int sHasNative = -1;

    // Settable parameter to allow caller to turn native API off
    private static boolean sEnabled = true;

    // Debug helper to log full call stack
    private static void dumpStack(int minlevel) {
        final int skipstack = 3 + minlevel;
        StackTraceElement[] callStack = Thread.currentThread().getStackTrace();
        if (callStack.length >= skipstack) {
            Log.d(LOG_TAG, callStack[skipstack].getMethodName());
            for (int i = 0; i + skipstack < callStack.length; i++) {
                Log.d(LOG_TAG, " #" + i + " " + callStack[i + skipstack].toString());
            }
        }
    }

    // Helper for loading a shared library with non-default search path
    static private final String SYSTEM_LIBDIR = "system/vendor/lib";

    static public void loadLibrary(String libName) {
        try {
            java.lang.System.loadLibrary(libName);
            return;
        } catch (UnsatisfiedLinkError e) {
            // Failed to load, try to resolve from system
            String libTail = java.lang.System.mapLibraryName(libName);
            File libDir = new File(Environment.getRootDirectory(), SYSTEM_LIBDIR);
            File libFile = new File(libDir, libTail);
            if (libFile.isFile()) {
                try {
                    java.lang.System.load(libFile.getAbsolutePath());
                    return;
                } catch (UnsatisfiedLinkError e2) {
                }
            }
        }
    }

    static public boolean hasNative() {
	if (sHasNative <= 0) {
	    return false;
	}
	if (!sEnabled) {
	    return false;
	}

	return true;
    }
}
