package com.yahoo.mobile.client.android.yperwave;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import android.util.Log;
import android.util.TypedValue;

public class HttpPool {
    private static final String LOG_TAG = "yperwave::httppool";

    private static final boolean DEBUG_INSTR = false;
    private static final boolean DEBUG_PERF = false;

    private long mNativeHandle = 0;
 
    public static class Request {
	public String url;

	public Request() {
	    url = null;
	}
    }

    static {
        NetClient.loadLibrary("yperwave");
    }

    public HttpPool() {
    }
  
    public long getNativeHandle() {
    	return mNativeHandle;
    }

    /* Callbacks invoked from native code when a request is completed */
    protected
    int onSuccess(long requestid) {
    	// String url, Byte[] content
    	Log.d(LOG_TAG, "Request " + requestid + " completed");
    	return 0;
    }

    protected
    int onFailure(long requestid, int errorCode) {
    	Log.e(LOG_TAG, "Request " + requestid + " failed with code " + errorCode);
    	return 0;
    }
    
    public void release() {
    	if (mNativeHandle != 0) {
	    native_poolRelease();
	    mNativeHandle = 0;
    	}
    }

    private synchronized boolean init() {
    	if (mNativeHandle == 0) {
            long l = native_poolCreate();
            if (l == 0) {
                Log.d(LOG_TAG, "failed to initialize net client");
                return false;
            }
    	}
    	return true;
    }

    public long add(String url) {
    	init();

    	long request = native_poolAdd(url);
    	return request;
    }
    
    public long login(String appKey, String appSecret,
                      String login, String password) {
    	init();        
    	return native_login(appKey, appSecret, login, password);
    }

    public int setToken(String token) {
    	if (!init()) {
            return -1;
    	}

    	native_setToken(token);
    	return 0;
    }

    public String getToken() {
    	if (!init()) {
            return null;
    	}
 
    	return native_getToken();
    }
 
    public int step(int nsteps) {
        int nLeft = native_poolStep(nsteps);
   		
        return nLeft;
    }
    
    public int step() {
    	return step(1);
    }

    protected void finalize() throws Throwable {
        try {
            release();
        } finally {
            super.finalize();
        }
    }
	
    /* native methods */
    private native long native_poolCreate();
    private native int native_poolRelease();    
    private native long native_poolAdd(String url);
    private native int native_poolStep(int nsteps);

    private native long native_login(String appKey, String appSecret,
                                     String login, String password);

    private native int native_setToken(String token);
    private native String native_getToken();
}
