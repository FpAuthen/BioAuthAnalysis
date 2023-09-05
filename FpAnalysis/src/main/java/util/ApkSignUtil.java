package util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ApkSignUtil {

    public static void main(String[] args) throws IOException, Exception {
        String path  = "/home/xiaolin/newFlowdroidNas/ymh_backup/test_app/com.themausoft.wpsapp_77_apps.evozi.com.apk";
        System.out.println(getSignature(path));
    }

    public static String getSignature(String path) {
        MessageDigest md5;
        byte[] bytes = new byte[0];
        try {
            md5 = MessageDigest.getInstance("MD5");
            bytes = getSignaturesFromApk(path);
            byte[] md5Bytes = md5.digest(bytes);
            StringBuffer hexValue = new StringBuffer();
            for (int i = 0; i < md5Bytes.length; i++) {
                int val = ((int) md5Bytes[i]) & 0xff;
                if (val < 16)
                    hexValue.append("0");
                hexValue.append(Integer.toHexString(val));
            }
            return hexValue.toString();
        } catch (Exception e) {
//            e.printStackTrace();
            return "";
        }
    }

    /**
     * 从APK中读取签名
     *
     * @param
     * @return
     * @throws IOException
     */
    private static byte[] getSignaturesFromApk(String strFile) throws IOException {
        File file = new File(strFile);
        JarFile jarFile = new JarFile(file);
        try {
            JarEntry je = jarFile.getJarEntry("AndroidManifest.xml");
            byte[] readBuffer = new byte[8192];
            Certificate[] certs = loadCertificates(jarFile, je, readBuffer);
            if (certs != null) {
                for (Certificate c : certs) {
                    return c.getEncoded();
                }
            }
        } catch (Exception ex) {
        }
        return null;
    }

    /**
     * 加载签名
     *
     * @param jarFile
     * @param je
     * @param readBuffer
     * @return
     */
    private static Certificate[] loadCertificates(JarFile jarFile, JarEntry je, byte[] readBuffer) {
        try {
            InputStream is = jarFile.getInputStream(je);
            while (is.read(readBuffer, 0, readBuffer.length) != -1) {
            }
            is.close();
            return je != null ? je.getCertificates() : null;
        } catch (IOException e) {
        }
        return null;
    }

}