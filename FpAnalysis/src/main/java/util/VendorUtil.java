package util;

import com.alibaba.fastjson.JSONObject;

public class VendorUtil {
    private static JSONObject pkgToVendor = FileUtil.getJsonObjectFromFile("/pkgToVendor_v3.json");

    public static String getVendor(String classname, String pkgName) {
        classname = classname.toLowerCase();
        String matchedPrefix = "";
        for (String prefix : pkgToVendor.keySet()) {
            if (classname.startsWith(prefix.toLowerCase())) {
                if (prefix.length() > matchedPrefix.length())
                    matchedPrefix = prefix;
            }
        }
        if (matchedPrefix.length() != 0)
            return pkgToVendor.getString(matchedPrefix);

        String[] parts = classname.split("\\.");
        if (parts.length > 2) {
            if (pkgToVendor.containsValue(parts[0])) {
                return parts[0];
            } else if (pkgToVendor.containsValue(parts[1])) {
                return parts[1];
            }
            return parts[0] + "." + parts[1] + "." + parts[2];
        } else if (classname.contains(pkgName)) {
            return pkgName;
        } else if (parts.length > 1) {
            return parts[0] + "." + parts[1];
        }
        return classname;
    }

    public static boolean isObused(String classname, String pkgName) {
        classname = classname.toLowerCase();
        String vendor = getVendor(classname, pkgName);
        if (pkgToVendor.containsValue(vendor))
            return false;
        String[] parts = classname.split("\\.");
        if (parts.length == 0 || (parts.length == 1 && !pkgToVendor.containsValue(parts[0])))
            return true;
        else if (pkgToVendor.containsValue(parts[0]) || (parts.length > 1 && pkgToVendor.containsValue(parts[1])))
            return false;
        else {
            return parts[0].length() <= 2 && parts[1].length() <= 2;
        }
    }
}
