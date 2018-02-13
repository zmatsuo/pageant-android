package com.github.zmatsuo.pageantp_android;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class Binutil {

    public static void writeAllBytes(File file, final byte[] data) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        }
        try {
            fos.write(data);
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte[] readAllBytes(File file) {
        int size = (int) file.length();
        if (size == 0) {
            return null;
        }
        byte[] bytes = new byte[size];
        InputStream fis = null;
        try {
            fis = new FileInputStream(file);
            fis.read(bytes, 0, bytes.length);
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
            bytes = null;
        }
        return bytes;
    }

    public static byte[] readAllBytes(final String filename) {
        File file = new File(filename);
        return readAllBytes(file);
    }

    /**
     *  make byte[] from string
     *      static final String data_str = "001122ff";
     *      byte[] data = hexStringToByteArray(data_str);
     */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String dump(final byte[] data, int len) {
        if (len == 0 || len > data.length) {
            len = data.length;
        }
        int adr = 0;
        StringBuffer sb = new StringBuffer ();

        sb.append(String.format("len=%d(0x%x)\n", len, len));
        
        if (data == null || data.length == 0) {
            sb.append("00000000 " + System.getProperty("line.separator"));
            return sb.toString();
        }

        for ( byte b : data ){
            if (adr % 16 == 0){
                sb.append("\n");
                sb.append(String.format("%04x ", adr));
            }

            int i = 0xff & (int)b;
            sb.append(String.format("%02x", i));

            adr++;
            if (adr % 4 ==0) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    public static byte[] cat(final byte[] src1, final byte[] src2) {
        byte[] dest = new byte[src1.length + src2.length];
        int src1_len = src1.length;
        System.arraycopy(src1, 0, dest, 0, src1_len);
        System.arraycopy(src2, 0, dest, src1_len, src2.length);
        return dest;
    }

    public static byte[] slice(final byte[] src, int start, int len) {
        byte[] dest = new byte[len];
        int src_len = src.length - start;
        if (len > src_len) {
            len = src_len;
        }
        System.arraycopy(src, start, dest, 0, len);
        return dest;
    }
    
    public static int getInt(final byte[] src, int pos) {
        return 
            (((int)src[pos+0]) & 0xff) * 0x1000000 +
            (((int)src[pos+1]) & 0xff) * 0x10000 +
            (((int)src[pos+2]) & 0xff) * 0x100 +
            (((int)src[pos+3]) & 0xff) * 0x1;
    }

    public static void putInt(byte[] dest, int pos, int n) {
        dest[pos+0] = (byte)((n >> (8*3)) & 0xff);
        dest[pos+1] = (byte)((n >> (8*2)) & 0xff);
        dest[pos+2] = (byte)((n >> (8*1)) & 0xff);
        dest[pos+3] = (byte)((n >> (8*0)) & 0xff);
    }
    
    public static void putString(byte[] dest, int pos, String str) {
        System.arraycopy(str.getBytes(), 0, dest, pos, str.length());
    }
    
    public static void copyBin(byte[] dest, int pos, final byte[] bin) {
        System.arraycopy(bin, 0, dest, pos, bin.length);
    }
    
    public static byte[] getBinInt(int n) {
        byte[] dest = new byte[4];
        putInt(dest, 0, n);
        return dest;
    }

    public static byte[] getBinStr(final String str) {
        int len = str.length();
        byte[] dest = new byte[len + 4];
        putInt(dest, 0, len);
        putString(dest, 4, str);
        return dest;
    }

    public static byte[] getBinBin(final byte[] bin) {
        int len = bin.length;
        byte[] dest = new byte[len + 4];
        putInt(dest, 0, len);
        System.arraycopy(bin, 0, dest, 4, len);
        return dest;
    }

    static int putBin(byte[] dest, int pos, String str) {
        final int length = str.length();
        putInt(dest, pos, length);
        pos += 4;
        putString(dest, pos, str);
        pos += length;
        return pos;
    }
    
    static int putBin(byte[] dest, int pos, int n) {
        final int length = 4;
        putInt(dest, pos, length);
        pos += 4;
        putInt(dest, pos, n);
        pos += length;
        return pos;
    }
    
    static int putBin(byte[] dest, int pos, final byte[] bytes) {
        final int length = bytes.length;
        putInt(dest, pos, length);
        pos += 4;
        copyBin(dest, pos, bytes);
        pos += length;
        return pos;
    }
}

