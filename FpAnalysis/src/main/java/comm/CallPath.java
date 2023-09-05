package comm;

import soot.SootMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static util.VendorUtil.getVendor;
import static util.VendorUtil.isObused;

public  class CallPath {
    public SootMethod lastMethod;
    public ArrayList<SootMethod> path;

    public CallPath(SootMethod srcMethod) {
        lastMethod = srcMethod;
        path = new ArrayList<>();
        path.add(srcMethod);
    }

    public CallPath(CallPath rhs) {
        this.lastMethod = rhs.lastMethod;
        this.path = new ArrayList<>();
        this.path.addAll(rhs.path);
    }

    public void addCall(SootMethod sootMethod) {
        lastMethod = sootMethod;
        this.path.add(sootMethod);
    }

    public SootMethod getLast() {
        return lastMethod;
    }

    public boolean hasMethod(SootMethod sootMethod) {
        return path.contains(sootMethod);
    }

    public int size() {
        return path.size();
    }

    public boolean containPath(CallPath callPath) {
        if (this.path.size() >= callPath.path.size()) {
            boolean isContain = true;
            for (SootMethod method : callPath.path) {
                if (!this.path.contains(method)) {
                    isContain = false;
                    break;
                }
            }
            return isContain;
        }
        return false;
    }

    public List<String> toStringList() {
        List<String> pathInShort = new ArrayList<>();
        for (SootMethod sootMethod : path) {
            pathInShort.add(sootMethod.getSignature());
        }
        return pathInShort;
    }

    public String getVendorList(String pkgname) {
        List<String> pathInShort = new ArrayList<>();
        String preClass = "";
        for (SootMethod sootMethod : path) {
            String curClass = getVendor(sootMethod.getDeclaringClass().getPackageName(), pkgname);
            curClass = curClass.trim().equals("") ? sootMethod.getDeclaringClass().toString() : curClass;
            if (curClass.equals(preClass) && sootMethod != getLast())
                continue;
            preClass = curClass;
            pathInShort.add(curClass);
        }
        return String.join(";", pathInShort);
    }

    public String mainVendorChainHash(String pkgName) {
        List<String> filterList = Arrays.asList("util", "retrofit", "okhttp", "square", "kotlin", "reactivex", "android", "");
        StringBuilder sb = new StringBuilder();
        sb.append(path.get(0).getSignature());
        boolean flag = false;
        for (int i = 1; i < size(); i++) {
            SootMethod sootMethod = path.get(i);
            String vendor = getVendor(sootMethod.getDeclaringClass().getPackageName(), pkgName);
            if (filterList.contains(vendor) || isObused(sootMethod.getDeclaringClass().getPackageName(), pkgName))
                continue;
            sb.append(vendor);
            flag = true;
            break;
        }
        return flag ? sb.toString() : "";
    }

    @Override
    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("Call Path:\n");
        if (path.size() > 0) {
            for (int i = 0; i < path.size() - 1; i++) {
                SootMethod method = path.get(i);
                res.append("(Class=" + method.getDeclaringClass().getName() + "---Method=" + method.getName() + ")--->\n");
            }
            res.append("(Class=" + lastMethod.getDeclaringClass().getName() + "---Method=" + lastMethod.getName() + ")");
            res.append("\n");
        }
        return res.toString();
    }
}
