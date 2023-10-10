package Analysis;

import comm.SootConfig;
import fcm.layout.ResourceUtil;
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
import static soot_analysis.SootAnalysis.isSliceToConstant;
import static soot_analysis.Utils.*;
import static soot_analysis.Utils.join;

public class CryptoCheck {
    public String apkPath;
    public String resPath;
    public String pkg;
    private Set<SootMethod> visited = new HashSet<>();
    public CryptoCheck(String apkpath, String respath) throws XmlPullParserException, IOException {
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
        CryptoCheck cryptoCheck = new CryptoCheck(apkpath, respath);

        boolean write_map = Boolean.parseBoolean(args[2]);
        SootConfig.init(cryptoCheck.apkPath, "jimple");
        Common.init(write_map);
        ResourceUtil.init(cryptoCheck.apkPath);
        cryptoCheck.run();
    }

    public void run() throws IOException, ParseException {
        String ctime1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        print("START_WORKING on ", apkPath, "AT", ctime1);

        Features features = new Features();
        getMeta(features);
        SootContext sc = new SootContext(Scene.v());

        print("=== KeyGen analysis...");
        analyzeKeyGen(features, sc);

		print("=== OnAuthenticationSucceeded analysis...");
		analyzeOnAuthenticationSucceeded(features, sc);

        print("=== AuthenticationRequired analysis...");
        analyzeAuthenticationRequired(features, sc);

        print("=== Authenticate analysis...");
        analyzeAuthenticate(features, sc);

        print("=== Invalidated analysis...");
        analyzeInvalidated(features, sc);


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


    private static void analyzeKeyGen(Features features, SootContext SC) {
        Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "void <init>(java.lang.String,int)", false, false);

        for (CodeLocation cl : usages) {
            Value vv = getInvokeParameter(SC, cl.sunit, 1);
            String result;
            print("***[analyzeKeyGen]***", cl.toString());
            if (handleIntFlag(SC, cl, vv, 4, "and")) { //4 --> SIGN
                result = "Asymm";
            } else {
                result = "Symm";
            }
            features.add("Keybuilder", vv, cl, result, "", SC.getInvokeExpr(cl.sunit));
        }

        //these exotic ones does not have "setUserAuthenticationRequired", therefore cannot be used securely, as far as I understand
        SootClass scc = SC.cm.get("java.security.spec.AlgorithmParameterSpec");
        if (scc == null) {
            return;
        }
        List<SootClass> scl = SC.ch.getDirectImplementersOf(scc);
        List<String> exotic_classes = new LinkedList<String>();
        for (SootClass sc : scl) {
            if (sc.getShortName().equals("KeyGenParameterSpec")) {
                continue;
            }
            exotic_classes.add(sc.getName() + "$Builder");
        }
        Collection<CodeLocation> exotic_usages = SC.getAPIUsage(exotic_classes, "void <init>", true, false);

        for (CodeLocation cl : exotic_usages) {
            String result = "Exotic";
            features.add("Keybuilder", SC.getInvokeExpr(cl.sunit).getMethod().getDeclaringClass().getShortName(), cl, result, "", SC.getInvokeExpr(cl.sunit));
        }
    }

    private static void analyzeAuthenticate(Features features, SootContext SC) {
        Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
        for (String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")) {
            usages.addAll(SC.getAPIUsage(className, "void authenticate", true, true));
        }
        for (String className : Utils.expandToSupportClasses("android.hardware.biometrics.BiometricPrompt")) {
            usages.addAll(SC.getAPIUsage(className, "void authenticate", true, true));
        }
        for (String className : Utils.expandToSupportClasses("androidx.biometric.BiometricPrompt")) {
            usages.addAll(SC.getAPIUsage(className, "void authenticate", true, true));
        }


        //in this case it could be that they are using obfuscated wrapper library
        //I assume that they don't use both obfuscated wrapper library and direct call
        //to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
        //it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
        if (usages.size() == 0) {
            usages.addAll(SC.getAPIUsage("android.hardware.fingerprint.FingerprintManager", "void authenticate", true, false));
        }

        //filtering usages in framework which are not really used.
        Collection<CodeLocation> usages_filtered = new LinkedList<CodeLocation>();
        for (CodeLocation cl : usages) {
            if (!isSupportClass(cl.smethod.getDeclaringClass())) {
                usages_filtered.add(cl);
                continue;
            }
            // this is needed for instance in com.vzw.hss.myverizon
            Collection<CodeLocation> sml = SC.getCallers(cl.smethod);
            BackwardCallgraph bc = new BackwardCallgraph(SC, cl.smethod);
            Tree<CallgraphState> btree = bc.run(20);

            for (Node<CallgraphState> ncs : btree.nodeMap.values()) {
                CallgraphState cs = ncs.value;
                if (!isSupportClass(cs.method.getDeclaringClass())) {
                    usages_filtered.add(cl);
                    break;
                }
            }
        }

        for (CodeLocation cl : usages_filtered) {
            Value vv = getInvokeParameter(SC, cl.sunit, 0);
            String result;
            String slice = "";
            if (handleIntFlag(SC, cl, vv, 0, "equal")) {
                result = "Weak";
            } else {
                String reg = String.valueOf(vv);

                Slicer sl = new Slicer(SC, cl.sunit, reg, cl.smethod);
                sl.followMethodParams = true;
                sl.followReturns = true;
                sl.followFields = true;
                Tree<SlicerState> stree = sl.run(20);        //zx 追溯authenticate()的第一个参数crypto

                if (isNullSliceForAuthenticate(stree)) {
                    result = "Weak";
                } else {
                    result = "Strong";
                }

                slice = String.valueOf(stree);
            }


            features.add("Authenticate", vv, cl, result, slice, SC.getInvokeExpr(cl.sunit));
        }

    }

    private static void analyzeOnAuthenticationSucceeded(Features features, SootContext SC) {
        Collection<SootMethod> possibleTargets = new LinkedList<SootMethod>();
        SootClass sc = SC.cm.get("java.security.Signature");
        if (sc != null) {
            for (SootMethod mm : sc.getMethods()) {
                if (mm.getSubSignature().contains("sign(") || mm.getSubSignature().contains(" update(")) {
                    possibleTargets.add(mm);
                }
            }
        }
        sc = SC.cm.get("javax.crypto.Cipher");
        if (sc != null) {
            for (SootMethod mm : sc.getMethods()) {
                if (mm.getSubSignature().contains("doFinal(") || mm.getSubSignature().contains(" update(")) {
                    possibleTargets.add(mm);
                }
            }
        }

        Collection<Tree<CallgraphState>> possibleTargetsTrees = new LinkedList<Tree<CallgraphState>>();
        for (SootMethod mm : possibleTargets) {
            print("***[analyzeOnAuthenticationSucceeded]***", mm.toString());
            BackwardCallgraph bc = new BackwardCallgraph(SC, mm);
            bc.skipLibraries = true;
            Tree<CallgraphState> tree = bc.run(100);
            if (tree.nodeMap.size() > 1) {
                possibleTargetsTrees.add(tree);
            }
        }


        Collection<SootMethod> succeededUsages = new LinkedList<SootMethod>();
        for (String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback")) {
            SootMethod mm = SC.resolveMethod(className, "void onAuthenticationSucceeded", true);
            if (mm == null) {
                continue;
            }
            Collection<SootMethod> tusages = SC.getOverrides(mm);
            succeededUsages.addAll(tusages);
        }

        Collection<SootMethod> succeededUsages_filtered = new LinkedList<SootMethod>();
        for (SootMethod m : succeededUsages) {
            if (Utils.isSupportClass(m.getDeclaringClass())) {
                continue;
            }
            succeededUsages_filtered.add(m);
        }
        //in this case it could be that they are using obfuscated wrapper library
        //I assume that they don't use both obfuscated wrapper library and direct call
        //to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
        //it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
        if (succeededUsages_filtered.size() == 0) {
            succeededUsages_filtered = succeededUsages;
        }
        //I cannot really filter here to see if it is really used, since it is a callback the cg does not give me enough info.

        print("***[analyzeOnAuthenticationSucceeded]***", ":start forwardCallgraph");
        for (SootMethod m : succeededUsages_filtered) {

            ForwardCallgraph fc = new ForwardCallgraph(SC, m);
            Tree<CallgraphState> tree = fc.run(200);

            boolean found_something = false;

            for (Tree<CallgraphState> btree : possibleTargetsTrees) {
                Tree<CallgraphState> connectedTree = intersectTrees(tree, btree);
                if (connectedTree == null) {
                    continue;
                }

                for (Node<CallgraphState> n : connectedTree.nodeMap.values()) {
                    SootMethod m2 = n.value.method;
                    String cname = m2.getDeclaringClass().getName();
                    String mname = m2.getSubSignature();
                    if (cname.equals("java.security.Signature")) {
                        if (mname.contains("sign(") || mname.contains(" update(")) {
                            String result = "Asymm";        // zx
                            Tuple<Unit, InvokeExpr> u_i = SC.recoverEdge(n.value.method, n.parent.value.method);
                            if (u_i == null) {
                                continue;
                            }
                            Unit uu = u_i.x;
                            InvokeExpr ie = u_i.y;
                            String extra = "";
                            if (mname.contains("update(")) {
                                Value vv2 = ie.getArgs().get(0);
                                String reg = String.valueOf(vv2);
                                if (reg.startsWith("$")) {
                                    Slicer sl = new Slicer(SC, uu, reg, n.parent.value.method);
                                    Tree<SlicerState> stree = sl.run(20);
                                    extra = String.valueOf(stree);
                                } else {
                                    extra = String.valueOf(reg);
                                }
                            }
                            //*************** zx
                            if (mname.contains("sign(")) {
                                if (uu.getDefBoxes().size() == 0) {
                                    result = "Weak";
                                }
                            }
                            //*************** zx

//							features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Asymm", tree, extra);
//                            features.add("Succeeded", m2.getSignature(), join(",", new Object[]{m, uu, n.parent.value.method}), result, tree, extra);    //zx
                            features.add("Succeeded", m2.getSignature(), join(",", new Object[]{m, uu, n.parent.value.method}), result, "", extra);    //zx
                            found_something = true;
                        }
                    }
                    if (cname.equals("javax.crypto.Cipher")) {
                        if (mname.contains("doFinal(") || mname.contains(" update(")) { //update seems needed at least for ebay
                            Tuple<Unit, InvokeExpr> u_i = SC.recoverEdge(n.value.method, n.parent.value.method);
                            if (u_i == null) {
                                continue;
                            }
                            Unit uu = u_i.x;
                            InvokeExpr ie = u_i.y;

                            if (mname.contains("doFinal(")) {
                                boolean isEncryptingConstant = false;
                                if (ie.getArgs().size() == 1) {
                                    String reg = String.valueOf(ie.getArg(0));
                                    if (reg.startsWith("$")) {
                                        Slicer sl = new Slicer(SC, uu, reg, n.parent.value.method);
                                        sl.skipThisReg = false;
                                        sl.followMethodParams = true;
                                        Tree<SlicerState> stree = sl.run(20);
                                        isEncryptingConstant = isSliceToConstant(stree);
                                    }
                                }
                                // check if result is not used, or if what is encrypted is constant
                                if (isEncryptingConstant || uu.getDefBoxes().size() == 0) {
                                    features.add("Succeeded", m2.getSignature(), join(",", new Object[]{m, uu, n.parent.value.method}), "Weak", "", "");
                                } else {
                                    features.add("Succeeded", m2.getSignature(), join(",", new Object[]{m, uu, n.parent.value.method}), "Symm", "", "");
                                }
                            } else {
                                features.add("Succeeded", m2.getSignature(), join(",", new Object[]{m, uu, n.parent.value.method}), "Symm", "", "");
                            }

                            found_something = true;
                        }
                    }
                }
            }

            if (!found_something) {
                features.add("Succeeded", "", join(",", new Object[]{m, null, null}), "Unknown", "", "");
            }
            print("***[analyzeOnAuthenticationSucceeded]***", features.toString());
        }

    }

    private static void analyzeAuthenticationRequired(Features features, SootContext SC) {
        Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)", false, false);
        for (CodeLocation cl : usages) {
            Value vv = getInvokeParameter(SC, cl.sunit, 0);
            features.add("AuthenticationRequired", vv, cl, "", "KeyGenParameterSpec$Builder", SC.getInvokeExpr(cl.sunit));
        }
        usages = SC.getAPIUsage("android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationRequired(boolean)", false, false);
        for (CodeLocation cl : usages) {
            Value vv = getInvokeParameter(SC, cl.sunit, 0);
            features.add("AuthenticationRequired", vv, cl, "", "KeyProtection$Builder", SC.getInvokeExpr(cl.sunit));
        }
    }

    private static void analyzeInvalidated(Features features, SootContext SC){
        Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setInvalidatedByBiometricEnrollment(boolean)", false, false);
        for(CodeLocation cl : usages){
            Value vv = getInvokeParameter_resolve(SC,cl.sunit, 0, cl);
            features.add("InvalidatedByBiometricEnrollment", vv, cl, "", "KeyGenParameterSpec$Builder", SC.getInvokeExpr(cl.sunit));
        }
        usages = SC.getAPIUsage("android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setInvalidatedByBiometricEnrollment(boolean)", false, false);
        for(CodeLocation cl : usages){
            Value vv = getInvokeParameter_resolve(SC,cl.sunit, 0, cl);
            features.add("InvalidatedByBiometricEnrollment", vv, cl, "", "KeyProtection$Builder", SC.getInvokeExpr(cl.sunit));
        }
    }


}
