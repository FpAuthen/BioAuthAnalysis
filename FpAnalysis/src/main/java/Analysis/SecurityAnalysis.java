package Analysis;

import comm.SootConfig;
import fcm.layout.ResourceUtil;
import javafx.util.Pair;
import org.xmlpull.v1.XmlPullParserException;
import scenery.Common;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot_analysis.*;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static base.Aapt.aaptResult;
import static soot_analysis.SootAnalysis.*;
import static soot_analysis.Utils.*;

public class SecurityAnalysis {
    public String apkPath;
    public String resPath;
    public String pkg;
    private Set<SootMethod> visited = new HashSet<>();
    public SecurityAnalysis(String apkpath, String respath) throws XmlPullParserException, IOException {
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
        SecurityAnalysis securityAnalysis = new SecurityAnalysis(apkpath, respath);

        boolean write_map = Boolean.parseBoolean(args[2]);
        SootConfig.init(securityAnalysis.apkPath);
        Common.init(write_map);
        ResourceUtil.init(securityAnalysis.apkPath);
        securityAnalysis.run();
    }

    public void run() throws IOException, ParseException {
        String ctime1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        print("START_WORKING on ", apkPath, "AT", ctime1);

        Features features = new Features();
        getMeta(features);
        SootContext sc = new SootContext(Scene.v());

//        print("=== test onclickAuthenticate...");
//        analyzeDisableAuthentication(features);

        print("=== analyze deleting all the fps...");
        analyzeDelete(features, sc);
//        print("=== analyze weak configuration...");


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
                    return callerMethod + "@@@" + caller_chain.toString();
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


    // 检测删除所有指纹时是否直接bypass
    private void analyzeDelete(Features features, SootContext SC) {
        Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
        // 这里getAPIUsage找的caller还是匹配subsignature
        for (String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")) {
            usages.addAll(SC.getAPIUsage(className, "boolean hasEnrolledFingerprints", true, true));
        }
        //in this case it could be that they are using obfuscated wrapper library
        //I assume that they don't use both obfuscated wrapper library and direct call
        //to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
        //it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
        if (usages.size() == 0) {            // zx: unnecessary?
            usages.addAll(SC.getAPIUsage("android.hardware.fingerprint.FingerprintManager", "boolean hasEnrolledFingerprints", true, false));
        }

        // 加入androidx包调用的处理 androidx.biometric.BiometricManager.canAuthenticate
        for (String className : Utils.expandToSupportClasses("androidx.biometric.BiometricManager")) {
            usages.addAll(SC.getAPIUsage(className, "int canAuthenticate", true, true));
        }

        //filtering usages in framework which are not really used.
        Collection<CodeLocation> usages_filtered = new LinkedList<CodeLocation>();
        for (CodeLocation cl : usages) {
            if (!isSupportClass(cl.smethod.getDeclaringClass())) {
                usages_filtered.add(cl);
                continue;
            }
        }

        Collection<Tree<SlicerState>> strees = new LinkedList<>();

        for (CodeLocation cl : usages_filtered) {
            Unit uu = cl.sunit;
//			Local returnValue = (Local) ((Stmt) uu).getUseBoxes().get(0).getValue();
//			Value returnValue = ((Stmt) uu).getInvokeExpr().getUseBoxes().get(0).getValue();
//            Value returnValue = uu.getDefBoxes().get(0).getValue();//1、获取一个 Unit 对象的第一个定义操作数的值,为什么是第一个操作数字？从开始向下遍历
            List<ValueBox> defBoxes = uu.getDefBoxes();
            if(defBoxes.size()<1)//过滤掉死代码（调用有返回值的函数，却不对得到的返回值进行进一步的Unit）
                continue;
            Value returnValue=defBoxes.get(0).getValue();
            print("##################### return Value: ", String.valueOf(returnValue));

            //Slicer 可以根据程序的数据依赖关系和控制流信息，将与给定程序点相关的指令和变量提取出来，形成一个被称为切片（Slice）的代码片段。
            ForwardSlicer FS = new ForwardSlicer(SC, uu, String.valueOf(returnValue), cl.smethod);
            Tree<SlicerState> tree = FS.run_track(100);     // 找到hasEnroll检查api的返回值在if中的处理
            strees.add(tree);

            print("============== isWeakUnlock ==============");
            if (isWeakUnlock(tree)) {
                features.add("Unlock", uu.toString(), cl, "WEAK", String.valueOf(returnValue), String.valueOf(tree));
            } else {
                features.add("Unlock", uu.toString(), cl, "STRONG", String.valueOf(returnValue), String.valueOf(tree));
            }
            print();
        }
        print("&&&&&&&&&&&&&&&&&&&&&&&&&");
        print(String.valueOf(strees));
        print("&&&&&&&&&&&&&&&&&&&&&&&&&");
    }

    private static boolean isWeakUnlock(Tree<SlicerState> stree) {
        print("SIZE: ", stree.getAllNodes().size());

        for (SlicerState ss : stree.getAllNodes()) {
            print();
            print(String.valueOf(ss));
            print("REG: ", ss.reg);
            if (String.valueOf(ss.reg).equals("if")) {
                print("IF: ", String.valueOf(ss));
                Node<SlicerState> sn = stree.getNode(ss);
                // 判断if节点的子节点是否为两个不同的intent
                List<Node<SlicerState>> children = sn.children;
                print("Children:", String.valueOf(children));
                if (children.size() == 2) {
                    String intent1 = children.get(0).value.reg;
                    String intent2 = children.get(1).value.reg;
                    if (!intent1.equals(intent2) && (intent1.contains("MainActivity") || intent2.contains("MainActivity"))) {
                        print("WEAK!!!");
                        return true;
                    }
                    if (intent1.contains("MainActivity") && intent2.contains("MainActivity")) {
                        //可能两个都是进入主页面，存在一些其他判断
                        print("WEAK!!!");
                        return true;
                    }
                    if (intent1.contains("authenticate") ^ intent2.contains("authenticate")) {
                        print("WEAK!!!");
                        return true;
                    }
                }
            }
            if (String.valueOf(ss.reg).equals("WEAK")) {
                print("WEAK!!!");
                return true;
            }
        }
        print("STRONG!!!");
        return false;
    }





    private static Tree<CallgraphState> intersectTrees(Tree<CallgraphState> ft, Tree<CallgraphState> bt) {
        HashMap<SootMethod, Node<CallgraphState>> ftmap = new HashMap<>();
        for (Node<CallgraphState> n : ft.nodeMap.values()) {
            SootMethod mm = n.value.method;
            int level = n.level;
            if (!ftmap.containsKey(mm) || ftmap.get(mm).level > level) {
                ftmap.put(mm, n);
            }
        }
        HashMap<SootMethod, Node<CallgraphState>> btmap = new HashMap<>();
        for (Node<CallgraphState> n : bt.nodeMap.values()) {
            SootMethod mm = n.value.method;
            int level = n.level;
            if (!btmap.containsKey(mm) || btmap.get(mm).level > level) {
                btmap.put(mm, n);
            }
        }

        int candidateDepthF = Integer.MAX_VALUE;
        int candidateDepthB = Integer.MAX_VALUE;
        Node<CallgraphState> c1 = null;
        Node<CallgraphState> c2 = null;
        for (Map.Entry<SootMethod, Node<CallgraphState>> ee : ftmap.entrySet()) {
            SootMethod mm = ee.getKey();
            Node<CallgraphState> n1 = ee.getValue();
            Node<CallgraphState> n2 = btmap.get(mm);
            if (n2 != null) {
                int depthF = n1.level;
                int depthB = n2.level;
                if (depthB < candidateDepthB || (depthB == candidateDepthB && depthF < candidateDepthF)) {
                    candidateDepthF = depthF;
                    candidateDepthB = depthB;
                    c1 = n1;
                    c2 = n2;
                }
            }
        }

        Tree<CallgraphState> res = null;
        if (c1 != null && c2 != null) {
            res = new Tree<>();
            Node<CallgraphState> cnode = c1;
            List<Node<CallgraphState>> nlist = new LinkedList<>();
            while (cnode != null) {
                nlist.add(0, cnode);
                cnode = cnode.parent;
            }
            Node<CallgraphState> prev = new Node<CallgraphState>(nlist.get(0));
            prev.level = 0;
            nlist.remove(0);
            res.addHead(prev);
            for (Node<CallgraphState> n : nlist) {
                prev = res.addChild(prev, n.value);
            }
            cnode = c2;
            while (cnode != null) {
                prev = res.addChild(prev, cnode.value);
                cnode = cnode.parent;
            }
        }


        return res;
    }




}
