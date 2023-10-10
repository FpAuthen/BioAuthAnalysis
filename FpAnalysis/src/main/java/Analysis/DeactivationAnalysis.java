package Analysis;

import comm.SootConfig;
import fcm.layout.ResourceUtil;
import javafx.util.Pair;
import org.xmlpull.v1.XmlPullParserException;
import scenery.Common;
import soot.*;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot_analysis.*;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static base.Aapt.aaptResult;
import static soot_analysis.Utils.*;
import static soot_analysis.Utils.print;

public class DeactivationAnalysis {
    public String apkPath;
    public String resPath;
    public String pkg;
    private Set<SootMethod> visited = new HashSet<>();

    public DeactivationAnalysis(String apkpath, String respath) throws XmlPullParserException, IOException {
        this.apkPath = apkpath;
        this.resPath = respath;
        this.pkg = getPkgname(apkpath);
    }

    public String getPkgname(String apkpath) throws XmlPullParserException, IOException {
//        return apkpath.substring(apkpath.lastIndexOf('/') + 1, apkpath.length() - 4);
        try {
            ProcessManifest processMan = new ProcessManifest(apkpath);
            return processMan.getPackageName();
        } catch (Exception e) {
            System.out.println(e.toString());
            return apkpath.substring(apkpath.lastIndexOf('/') + 1, apkpath.length() - 4);
        }
    }

    public static void main(String[] args) throws XmlPullParserException, IOException, ParseException {
        // arg: apkpath respath write_boolean
        String apkpath = args[0];
        String respath = args[1];
        DeactivationAnalysis deactivationAnalysis = new DeactivationAnalysis(apkpath, respath);

        boolean write_map = Boolean.parseBoolean(args[2]);
        SootConfig.init(deactivationAnalysis.apkPath, "jimple");
        Common.init(write_map);
        ResourceUtil.init(deactivationAnalysis.apkPath);
        deactivationAnalysis.run();
    }

    public void run() throws IOException, ParseException {
        String ctime1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        print("START_WORKING on ", apkPath, "AT", ctime1);

        Features features = new Features();
        getMeta(features);
        SootContext sc = new SootContext(Scene.v());

        print("=== test onclickAuthenticate...");
//        analyzeDisableAuthentication(features);
        analyzeDisableAuthentication_semantics(features);


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

    public void getMeta(Features features) {
        String aaptResult = aaptResult(apkPath);//Android资源编译器（aapt）
        String pname = strExtract(aaptResult, "package: name='", "'");
        print(pname);
        String pversion = strExtract(aaptResult, "versionName='", "'");
        print(pversion);

        features.addMeta("pname", this.pkg);
        features.addMeta("version", pversion);
        features.addMeta("fname", this.apkPath);
    }

    public static Collection<SootMethod> getAuthenticateUsages() {
        // 这里只是获取到app中到fingerprint API方法，并非usage，但是用在disable检查中可以，因为该检查是回溯调用链
        Collection<SootMethod> usages = new LinkedList<SootMethod>();
        for (String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")) {
            usages.addAll(getTargetAPI(className, "authenticate"));
        }
        for (String className : Utils.expandToSupportClasses("android.hardware.biometrics.BiometricPrompt")) {
            usages.addAll(getTargetAPI(className, "authenticate"));
        }
        for (String className : Utils.expandToSupportClasses("androidx.biometric.BiometricPrompt")) {
            usages.addAll(getTargetAPI(className, "authenticate"));
        }
        if (usages.size() == 0) {
            print("[analyzeCaller]: no authenticate found!");
        }
        return usages;
    }

    // 检测关闭指纹认证时是否验证指纹
    private void analyzeDisableAuthentication(Features features) {
        Collection<SootMethod> usages = getAuthenticateUsages();

        String res = null;
        for (SootMethod usage : usages) {
//            res = dfs(usage, SC, pkg);
            res = switch_dfs_limitedDepth(usage, "onCheckedChanged", 100);

            if (res != null) {
                String[] tres = res.split("@@@");        // callerClass@@@caller_chain
                features.add("Authenticate_bg_dfs", tres[0], usage, String.valueOf(true), "", tres[1]);
                break;
            } else {
                features.add("Authenticate_bg_dfs", res, usage, String.valueOf(false), "", "");
            }
        }
    }

    // 判断调用链是否来自开关组件时，除了特定的onCheckedChanged回调，加入语义判断
    private void analyzeDisableAuthentication_semantics(Features features) {
        Collection<SootMethod> usages = getAuthenticateUsages();

        String res = null;
        for (SootMethod usage : usages) {
//            res = dfs(usage, SC, pkg);
            res = switch_dfs_limitedDepth_semantics(usage, "onCheckedChanged", 100);

//            if (res != null) {
            if (res.contains("@@@")) {
                String[] tres = res.split("@@@");        // callerClass@@@caller_chain
                features.add("Authenticate_bg_dfs", tres[0], usage, String.valueOf(true), "", "");
                break;
            } else {
//                features.add("Authenticate_bg_dfs", "", usage, String.valueOf(false), "", "");
                features.add("Authenticate_bg_dfs", "", usage, String.valueOf(false), "", res);
            }
        }
    }


    private static String switch_dfs_limitedDepth_semantics(SootMethod authenticateUsage, String kw, Integer limitDepth) {
        // 创建一个DFS队列
        Deque<Pair<SootMethod, Integer>> dfsStack = new ArrayDeque<>();
        dfsStack.push(new Pair<>(authenticateUsage, 0));
        StringBuilder caller_chain = new StringBuilder();

        Set<SootMethod> visitedMethods = new HashSet<>();
        while (!dfsStack.isEmpty()) {
            Pair<SootMethod, Integer> methodDepthPair = dfsStack.pop();
//            print("\n[pop]: ", String.valueOf(methodDepthPair));
            SootMethod method = methodDepthPair.getKey();
            int depth = methodDepthPair.getValue();

            // 超出预定的深度限制，即不继续探索更深
            if (visitedMethods.contains(method) || depth > limitDepth) {
                continue;
            }
            print(depth, String.valueOf(method));
            caller_chain.append(String.valueOf(methodDepthPair) + '\n');

            visitedMethods.add(method);

            // 百度sdk使用webview实现，开启时验证指纹，关闭时不验证
            // 特征sdk：关闭时不验证指纹
            List<String> sdkList = new LinkedList<>(Arrays.asList("com.baidu", "com.tencent", "com.taobao", "com.huawei", "com.meituan", "com.alipay.security"));
            for(String sdk: sdkList) {
                if(method.toString().toLowerCase().contains(sdk)) {
                    return "***SDK:" + method + "***" + caller_chain.toString();
                }
            }

            // 当调用链中找到 onClick 时，遍历onClick函数体，看是否存在checked相关操作，若有，则是开关组件等处理函数
            // 因为部分app使用checkBox等组件，但是使用onClick处理函数，在其中通过调用isChecked等判断开关状态
            if (method.toString().toLowerCase().contains("onclick")) {
                if (!method.hasActiveBody()) continue;
                for (Unit unit : method.getActiveBody().getUnits()) {
                    Stmt s = (Stmt) unit;
                    if (s.toString().toLowerCase().contains("checked")) {
                        caller_chain.append(String.valueOf(new Pair<>(method, depth + 1)) + '\n');
                        return method + ":::" + s.toString() + "@@@" + caller_chain;
                    }
                }
            }

            if (!Common.CalleeToCallerMap.containsKey(method) || Common.CalleeToCallerMap.get(method).isEmpty())
                continue;
            int size = Common.CalleeToCallerMap.get(method).size();
            if (size > 50) continue;

            for (SootMethod caller : Common.CalleeToCallerMap.get(method)) {
                // 如果caller和method相同，pass
                if (String.valueOf(caller).equals(String.valueOf(method))) {
                    continue;
                }
                String callerMethod = caller.getSignature();
                if (callerMethod.contains(kw) || callerMethod.toLowerCase().contains("switch")) {
                    // 判断caller的类名前缀是否为"APP"，如果是则停止搜索
                    caller_chain.append(String.valueOf(new Pair<>(callerMethod, depth + 1)) + '\n');
                    return callerMethod + "@@@" + caller_chain;
                } else {
                    dfsStack.push(new Pair<>(caller, depth + 1));
                }
            }
        }
//        return null;
        return caller_chain.toString();
    }


    private static String switch_dfs_limitedDepth(SootMethod authenticateUsage, String kw, Integer limitDepth) {
        // 创建一个DFS队列
        Deque<Pair<SootMethod, Integer>> dfsStack = new ArrayDeque<>();
        dfsStack.push(new Pair<>(authenticateUsage, 0));
        StringBuilder caller_chain = new StringBuilder();

        Set<SootMethod> visitedMethods = new HashSet<>();
        while (!dfsStack.isEmpty()) {
            Pair<SootMethod, Integer> methodDepthPair = dfsStack.pop();
//            print("\n[pop]: ", String.valueOf(methodDepthPair));
            SootMethod method = methodDepthPair.getKey();
            int depth = methodDepthPair.getValue();

            // 超出预定的深度限制，即不继续探索更深
            if (visitedMethods.contains(method) || depth > limitDepth) {
                continue;
            }
            print(depth, String.valueOf(method));
            caller_chain.append(String.valueOf(methodDepthPair) + '\n');

            visitedMethods.add(method);

            if (!Common.CalleeToCallerMap.containsKey(method) || Common.CalleeToCallerMap.get(method).isEmpty())
                continue;
            int size = Common.CalleeToCallerMap.get(method).size();
            if (size > 50) continue;

            for (SootMethod caller : Common.CalleeToCallerMap.get(method)) {
                // 如果caller和method相同，pass
                if (String.valueOf(caller).equals(String.valueOf(method))) {
                    continue;
                }
                String callerMethod = caller.getSignature();
                if (callerMethod.contains(kw)) {
                    // 判断caller的类名前缀是否为"APP"，如果是则停止搜索
                    caller_chain.append(String.valueOf(new Pair<>(callerMethod, depth + 1)) + '\n');
                    return callerMethod + "@@@" + caller_chain;
                } else {
                    dfsStack.push(new Pair<>(caller, depth + 1));
                }
            }
        }
        return null;
    }

    private static Set<SootMethod> getTargetAPI(String classname, String methodName) {
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

}