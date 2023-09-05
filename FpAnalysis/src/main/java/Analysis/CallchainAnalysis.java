package Analysis;

import comm.CallPath;
import comm.SootConfig;
import fcm.layout.ResourceUtil;
import org.xmlpull.v1.XmlPullParserException;
import scenery.Common;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot_analysis.CodeLocation;
import soot_analysis.Features;
import soot_analysis.SootContext;
import soot_analysis.Utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static base.Aapt.aaptResult;
import static soot_analysis.Utils.print;
import static soot_analysis.Utils.strExtract;
import static util.ApiUtil.isAndroidOrJavaClass;

//import org.xmlpull.v1.XmlPullParserException;


public class CallchainAnalysis {
    public String apkPath;
    public String resPath;
    public String pkg;
    private Set<SootMethod> visited = new HashSet<>();
    private Map<SootMethod, Boolean> cannotReached = new HashMap<>();
    private List<String> entryPoints = new ArrayList<>();
    private Set<String> launcherActivitiesPrefix = new HashSet<>();

    public CallchainAnalysis(String apkPath, String resPath) throws XmlPullParserException, IOException {
        this.apkPath = apkPath;
        this.pkg = getPkgname(apkPath);
        this.resPath = resPath;
    }

    public String getPkgname(String apkpath) throws XmlPullParserException, IOException {
//        return apkpath.substring(apkpath.lastIndexOf('/') + 1, apkpath.length() - 4);
        try {
            ProcessManifest processMan = new ProcessManifest(apkpath);
            entryPoints.addAll(processMan.getEntryPointClasses());

            Set<AXmlNode> launchableActivities = processMan.getLaunchableActivities();
            for (AXmlNode node : launchableActivities) {
                String className = getActivityName(node);
                launcherActivitiesPrefix.add(getPrefix(className));
            }
            return processMan.getPackageName();
        } catch (Exception e) {
            System.out.println(e.toString());
            return apkpath.substring(apkpath.lastIndexOf('/') + 1, apkpath.length() - 4);
        }
    }

    public static String getActivityName(AXmlNode node) {
        AXmlAttribute<?> attr = node.getAttribute("name");
        String className = (String) attr.getValue();
        return className;
    }

    public static String getPrefix(String cla) {
        int firstDot = cla.indexOf('.');
        if(firstDot == -1) return cla;
        int secondDot = cla.indexOf('.', firstDot + 1);
        if(secondDot == -1) return cla;
        int thirdDot = cla.indexOf('.', secondDot + 1);

        if (thirdDot != -1) {
            return cla.substring(0, thirdDot);
        } else {
            return cla;
        }
    }

    public static void main(String[] args) throws XmlPullParserException, IOException, ParseException {
        // arg: apkpath respath write_boolean
        String apkpath = args[0];
        String respath = args[1];
        CallchainAnalysis callchainAnalysis = new CallchainAnalysis(apkpath, respath);

        boolean write_map = Boolean.parseBoolean(args[2]);
        SootConfig.init(callchainAnalysis.apkPath);
        Common.init(write_map);
        ResourceUtil.init(callchainAnalysis.apkPath);
        callchainAnalysis.run();
    }

    public void run() throws IOException, ParseException {
        String ctime1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        print("START_WORKING on ", apkPath, "AT", ctime1);

        Features features = new Features();
        getMeta(features);

        print("=== analyzeCaller...");
        analyzeCaller(features);
        print("=== Analyses are done");

        print("================================= JSON START");
        String jsonstr = features.toJson();
        jsonstr = jsonstr.replace("\\n", "\n");     // 将字符串中的 \n 替换为换行符，在json结果文件中可以正常显示换行符
        print(jsonstr);
        String jsonpath = resPath;
        FileWriter fw = new FileWriter(jsonpath);
        PrintWriter out = new PrintWriter(fw);
        out.write(jsonstr);
        out.println();
        fw.close();
        out.close();
        print("================================= JSON END");

        String ctime2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());

        Date time1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(ctime1);
        Date time2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(ctime2);

        // Calculate the time difference in milliseconds
        long diffInMilliseconds = Math.abs(time2.getTime() - time1.getTime());

        print(pkg, "END", "AT", ctime2);
        System.out.println("Time difference: " + diffInMilliseconds / 1000.0 / 60.0 + " minutes");

    }

    public void getMeta(Features features){
        String aaptResult = aaptResult(apkPath);
        String pname = strExtract(aaptResult, "package: name='", "'");
        print(pname);
        String pversion = strExtract(aaptResult, "versionName='", "'");
        print(pversion);

        features.addMeta("pname", this.pkg);
        features.addMeta("version", pversion);
        features.addMeta("fname",this.apkPath);
    }

    private void analyzeCaller(Features features) {
        Collection<SootMethod> usages = new LinkedList<SootMethod>();
        for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
            usages.addAll(getTargetAPI(className, "authenticate"));
        }
        for(String className : Utils.expandToSupportClasses("android.hardware.biometrics.BiometricPrompt")){
            usages.addAll(getTargetAPI(className, "authenticate"));
        }
        for(String className : Utils.expandToSupportClasses("androidx.biometric.BiometricPrompt")){
            usages.addAll(getTargetAPI(className, "authenticate"));
        }
        if(usages.size() == 0){
            print("[analyzeCaller]: no authenticate found!");
        }

        //test
//        for(SootMethod api:usages) {
//            if(Common.CalleeToCallerMap.containsKey(api)){
//                print(Common.CalleeToCallerMap.get(api));
//            }
//            else {
//                print("Common.CalleeToCallerMap no authentication!!!");
//            }
//        }


        String res = null;
        for (SootMethod api : usages) {
            visited.clear();
            List<CallPath> callPaths = getCallChain(api);
            if(callPaths.isEmpty()) {
                features.add("Authenticate_caller_in_pkg", "", "", String.valueOf(false),"","");
                continue;
            }
            for(CallPath callPath: callPaths) {
                String path = callPath.toString();
                if(!path.isEmpty()) {
                    SootMethod last = callPath.getLast();
                    features.add("Authenticate_caller_in_pkg", last.getDeclaringClass().toString(),last.getSignature(), String.valueOf(true), "", path);
                }
                else {
                    features.add("Authenticate_caller_in_pkg", "", "", String.valueOf(false),"","");
                }
            }

//            if (res != null) {
//                String[] tres = res.split("@@@");		// callerClass@@@caller_chain
//                features.add("Authenticate_caller_in_pkg", tres[0], "", String.valueOf(true), "", tres[1]);
//                break;
//            } else {
//                features.add("Authenticate_caller_in_pkg", res, "", String.valueOf(false), "", "");
//            }
        }
    }

    private Set<SootMethod> getTargetAPI(String classname, String methodName) {
        Set<SootMethod> methods = new HashSet<>();
        if (!Scene.v().containsClass(classname))
            return methods;
        SootClass sootClass = Scene.v().getSootClass(classname);
        if (!sootClass.declaresMethodByName(methodName))
            return methods;
        for (SootMethod sootMethod : sootClass.getMethods()) {
            if (!sootMethod.getName().equals(methodName))
                continue;
            methods.add(sootMethod);
        }
        return methods;
    }

    private List<CallPath> getCallChain(SootMethod sootMethod) {
        List<CallPath> allPath = new ArrayList<>();
        CallPath path = new CallPath(sootMethod);
        cannotReached.clear();
        getCallChainRecursive(sootMethod, path, allPath);
        return allPath;
    }

    private boolean getCallChainRecursive(SootMethod sootMethod, CallPath path, List<CallPath> allPath) {
        print("\n[getCallChainRecursive]\n---->  ", sootMethod.toString());
        print("******-> PATH: ", path.toString());
//        print();
        if (isEntryPoint(sootMethod.getDeclaringClass())) {
            allPath.add(path);
            return true;
        }
//        if (visited.contains(sootMethod) && visitedHashset.contains(path.mainVendorChainHash())){
        if (!cannotReached.getOrDefault(sootMethod, true)) return false;
//        if (visited.contains(sootMethod) && path.mainVendorChainHash(this.pkg).equals("")) return false;
        if (visited.contains(sootMethod)) return false;

        visited.add(sootMethod);
        if (path.size() != 1 && (sootMethod.isJavaLibraryMethod() || isAndroidOrJavaClass(sootMethod.getDeclaringClass())))
            return false;

        if (!Common.CalleeToCallerMap.containsKey(sootMethod) || Common.CalleeToCallerMap.get(sootMethod).isEmpty())
            return false;

        int size = Common.CalleeToCallerMap.get(sootMethod).size();
        if (size > 50) return false;

        if (sootMethod.getDeclaringClass().toString().matches(".*(io\\.reactivex).*|.*(kotlin).*|.*(okhttps\\.Call).*|.*(com\\.google\\.android\\.gms\\.internal).*")) {
            if (size > 40 && path.size() != 1)
                return false;
        }

        boolean reached = false;
        for (SootMethod method : Common.CalleeToCallerMap.get(sootMethod)) {
            if (path.hasMethod(method))
                continue;

            print("===== caller: ", method.toString());
//            if (path.size() == 1) //&& !pattern.equals("") && !checkPattern(sootMethod, method, pattern))
//                continue;
            CallPath newPath = new CallPath(path);
            newPath.addCall(method);
            if (getCallChainRecursive(method, newPath, allPath))
                reached = true;
        }

        cannotReached.put(sootMethod, reached);
        return reached;
    }

    public boolean isEntryPoint(SootClass sootClass) {
        String pkgPrefix = "";
        int firstdot = pkg.indexOf('.');
        if(firstdot == -1)  pkgPrefix = pkg;
        else {
            int seconddot = pkg.indexOf('.', firstdot + 1);
            if(seconddot == -1) pkgPrefix = pkg;
            else pkgPrefix = pkg.substring(0, seconddot);
        }
//        String prefix = pkg.substring(0, pkg.lastIndexOf('.'));
        return entryPoints.contains(sootClass.toString()) || sootClass.toString().startsWith(pkgPrefix) || isLauncherPrefix(sootClass.toString());
//        return entryPoints.contains(sootClass.toString()) || sootClass.toString().startsWith(prefix);
//        return sootClass.toString().startsWith(self_package_prefix) || (!sootClass.getPackageName().isEmpty() && self_package_prefix.startsWith(sootClass.getPackageName()));
    }

    public boolean isLauncherPrefix(String sc) {
        for(String pre:launcherActivitiesPrefix) {
            if(sc.startsWith(pre))
                return true;
        }
        return false;
    }
}
