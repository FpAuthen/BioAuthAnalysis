package soot_analysis;

import javafx.util.Pair;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;

import java.io.*;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Map.Entry;

import static soot_analysis.Utils.*;


public class SootAnalysis {
	public static List<String> entryPoints = new ArrayList<>();
	public static CallGraph callGraph;

	public static void main(String[] args) throws IOException, ParseException, XmlPullParserException {
		if(args[0].equalsIgnoreCase("fp1")){
			fp1(args);
		}
//		String[] targs = {"","C:\\Users\\ZX\\AppData\\Local\\Android\\Sdk\\platforms",
//				"D:\\FUDAN\\Biometric\\weak_config\\apks\\weak.apk"};
//		fp1(targs);
		System.exit(99);
	}
	
	public static void fp1(String[] args) throws IOException, ParseException, XmlPullParserException {
		Map<String, String> config = new HashMap<String, String>();
		config.put("input_format", "apk");
		config.put("android_sdk", args[1]);
		config.put("ir_format", "shimple");
//		config.put("ir_format", "jimple");
		config.put("input_file", args[2]);

		// get Entry Points
		ProcessManifest processMan = new ProcessManifest(args[2]);
		entryPoints.addAll(processMan.getEntryPointClasses());
		print(entryPoints);
		
		String ctime1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
		print("START_WORKING on ", args[2], "AT", ctime1);
		
		String aaptResult = aaptResult(args[2]);
//		print("[*] aapt result", aaptResult);
		String md5 = computeMD5(args[2]);
		print(md5);
		String pname = strExtract(aaptResult, "package: name='", "'");
		print(pname);
		String pversion = strExtract(aaptResult, "versionName='", "'");
		print(pversion);

		
		SootAnalysis sa = new SootAnalysis();
		Scene ss = null;
		try {
			ss = sa.run(config);
//			ss = sa.run_flowdroid(config);
		} catch (Exception e) {
			print("Exception:", e.getMessage());
			print(join("\n",e.getStackTrace()));
			System.exit(33);
		}
		
		SootContext sc = new SootContext(ss);
		
		int nclasses = 0;
		int nmethods = 0;
		for(SootClass c : sc.cm.values()){
			if(c.isApplicationClass()){
				nclasses+=1;
				nmethods+=c.getMethodCount();
			}
		}
		
		Features features = new Features();
		features.addMeta("pname", pname);
		features.addMeta("version", pversion);
		features.addMeta("fname",new File(args[2]).getName());
		features.addMeta("md5", md5);
		features.addMeta("nclasses", String.valueOf(nclasses));


		print("=== KeyGen analysis...");
		analyzeKeyGen(features, sc);

//		print("=== OnAuthenticationSucceeded analysis...");
//		analyzeOnAuthenticationSucceeded(features, sc);

		print("=== AuthenticationRequired analysis...");
		analyzeAuthenticationRequired(features, sc);

		print("=== Authenticate analysis...");
		analyzeAuthenticate(features, sc);

		print("=== Invalidated analysis...");
		analyzeInvalidated(features, sc);

		print("=== keycreation analysis...");
		analyzeKeyCreation(features, sc);

//		print("=== test onclickAuthenticate...");
//		TestOnclickAuthenticate(features, sc);
        TestOnclickAuthenticate_dfs(features, sc);

		print("=== Unlock analysis...");
		analyzeUnlock(features, sc);

        print("=== analyzeCaller...");
        analyzeCaller(features, sc, pname);

		print("=== Analyses are done");
		
		print("================================= JSON START");
		String jsonstr = features.toJson();
		print(jsonstr);
		String jsonpath = args[3];
		FileWriter fw = new FileWriter(jsonpath);
		PrintWriter out = new PrintWriter(fw);
		out.write(jsonstr);
		out.println();
		fw.close();
		out.close();
		print("================================= JSON END");
		
		print("=== FEATURES:");
//		print(features);
		print("=== NCLASSES: " + String.valueOf(nclasses));
		print("=== NMETHODS: " + String.valueOf(nmethods));

		String ctime2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());

		Date time1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(ctime1);
		Date time2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(ctime2);

		// Calculate the time difference in milliseconds
		long diffInMilliseconds = Math.abs(time2.getTime() - time1.getTime());

		print(args[2], "END", "AT", ctime2);
		System.out.println("Time difference: " + diffInMilliseconds / 1000.0 / 60.0 + " minutes");

	}
	
	private static void analyzeKeyGen(Features features, SootContext SC) {
		Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "void <init>(java.lang.String,int)", false, false);

		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter(SC, cl.sunit, 1);
			String result;
			print("***[analyzeKeyGen]***", cl.toString());
			if(handleIntFlag(SC, cl, vv, 4, "and")){ //4 --> SIGN
				result = "Asymm";
			}else{
				result = "Symm";
			}
			features.add("Keybuilder", vv, cl, result, "", SC.getInvokeExpr(cl.sunit));
		}
		
		//these exotic ones does not have "setUserAuthenticationRequired", therefore cannot be used securely, as far as I understand
		SootClass scc = SC.cm.get("java.security.spec.AlgorithmParameterSpec");
		if(scc == null){
			return;
		}
		List<SootClass> scl = SC.ch.getDirectImplementersOf(scc);
		List<String> exotic_classes = new LinkedList<String>();
		for(SootClass sc : scl){
			if(sc.getShortName().equals("KeyGenParameterSpec")){
				continue;
			}
			exotic_classes.add(sc.getName()+"$Builder");
		}
		Collection<CodeLocation> exotic_usages = SC.getAPIUsage(exotic_classes, "void <init>", true, false);

		for(CodeLocation cl : exotic_usages){
			String result = "Exotic";
			features.add("Keybuilder", SC.getInvokeExpr(cl.sunit).getMethod().getDeclaringClass().getShortName(), cl, result, "", SC.getInvokeExpr(cl.sunit));
		}
	}
	
	private static void analyzeAuthenticate(Features features, SootContext SC) {
		Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
		for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
			usages.addAll(SC.getAPIUsage(className, "void authenticate", true, true));
		}
		//in this case it could be that they are using obfuscated wrapper library
		//I assume that they don't use both obfuscated wrapper library and direct call
		//to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
		//it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
		if(usages.size() == 0){			// zx: unnecessary?
			usages.addAll(SC.getAPIUsage("android.hardware.fingerprint.FingerprintManager", "void authenticate", true, false));
		}

		//filtering usages in framework which are not really used.
		Collection<CodeLocation> usages_filtered = new LinkedList<CodeLocation>();
		for(CodeLocation cl : usages){
			if(! isSupportClass(cl.smethod.getDeclaringClass())){
				usages_filtered.add(cl);
				continue;
			}
			// this is needed for instance in com.vzw.hss.myverizon
			Collection<CodeLocation> sml = SC.getCallers(cl.smethod);
			BackwardCallgraph bc = new BackwardCallgraph(SC, cl.smethod);
			Tree<CallgraphState> btree = bc.run(20);

			for(Node<CallgraphState> ncs : btree.nodeMap.values()){
				CallgraphState cs = ncs.value;
				if(! isSupportClass(cs.method.getDeclaringClass())){
					usages_filtered.add(cl);
					break;
				}
			}
		}

		for(CodeLocation cl : usages_filtered){
			Value vv = getInvokeParameter(SC,cl.sunit, 0);
			String result;
			String slice = "";
			if(handleIntFlag(SC, cl, vv, 0, "equal")){
				result = "Weak";
			}else{
				String reg = String.valueOf(vv);

				Slicer sl = new Slicer(SC, cl.sunit, reg, cl.smethod);
				sl.followMethodParams = true;
				sl.followReturns = true;
				sl.followFields = true;
				Tree<SlicerState>  stree = sl.run(20);		//zx 追溯authenticate()的第一个参数crypto

				if(isNullSliceForAuthenticate(stree)){
					result = "Weak";
				}else{
					result = "Strong";
				}

				slice = String.valueOf(stree);
			}


			features.add("Authenticate", vv, cl, result, slice, SC.getInvokeExpr(cl.sunit));
		}

	}


//	/****************** zx **************/
//	private static void analyzeCryptoCreation(Features features, SootContext SC) {
//		Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
//		for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
//			usages.addAll(SC.getAPIUsage(className, "void authenticate", true, true));
//		}
//		//in this case it could be that they are using obfuscated wrapper library
//		//I assume that they don't use both obfuscated wrapper library and direct call
//		//to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
//		//it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
//		if(usages.size() == 0){			// zx: unnecessary?
//			usages.addAll(SC.getAPIUsage("android.hardware.fingerprint.FingerprintManager", "void authenticate", true, false));
//		}
//
//		//filtering usages in framework which are not really used.
//		Collection<CodeLocation> usages_filtered = new LinkedList<CodeLocation>();
//		for(CodeLocation cl : usages){
//			if(! isSupportClass(cl.smethod.getDeclaringClass())){
//				usages_filtered.add(cl);
//				continue;
//			}
//			// this is needed for instance in com.vzw.hss.myverizon
//			Collection<CodeLocation> sml = SC.getCallers(cl.smethod);
//			BackwardCallgraph bc = new BackwardCallgraph(SC, cl.smethod);
//			Tree<CallgraphState> btree = bc.run(20);
//
//			for(Node<CallgraphState> ncs : btree.nodeMap.values()){
//				CallgraphState cs = ncs.value;
//				if(! isSupportClass(cs.method.getDeclaringClass())){
//					usages_filtered.add(cl);
//					break;
//				}
//			}
//		}
//
//		for(CodeLocation cl : usages_filtered){
//			Value vv = getInvokeParameter(SC,cl.sunit, 0);
//			String result;
//			String slice = "";
//			if(handleIntFlag(SC, cl, vv, 0, "equal")){
//				result = "Weak";
//			}else{
//				String reg = String.valueOf(vv);
//
//				Slicer sl = new Slicer(SC, cl.sunit, reg, cl.smethod);
//				sl.followMethodParams = true;
//				sl.followReturns = true;
//				sl.followFields = true;
//				Tree<SlicerState>  stree = sl.run(20);
//
//				for(SlicerState ss : stree.getLeaves()){
//					if(stringInList(String.valueOf(ss.reg), Arrays.asList(new String[] {"field", "nullreg"}))){
//						continue;
//					}
//					if(String.valueOf(ss.reg).startsWith("@this")){
//						continue;
//					}
//					if(String.valueOf(ss.reg).equals("return")){
//						if(String.valueOf(ss.unit).contains("android.hardware.fingerprint.FingerprintManager$CryptoObject: void <init>")){
//							Value crypto = getInvokeParameter(SC, ss.unit, 0);
//
//
//							continue;
//						}
//					}
//				}
//
//
//
//
//				if(isNullSliceForAuthenticate(stree)){
//					result = "Weak";
//				}else{
//					result = "Strong";
//				}
//
//				slice = String.valueOf(stree);
//			}
//
//
//			features.add("Authenticate", vv, cl, result, slice, SC.getInvokeExpr(cl.sunit));
//		}
//
//	}
//	/****************** zx **************/

	/****************** zx *************/
	private static void TestOnclickAuthenticate(Features features, SootContext SC) {
		// 为onclick建前向cg看是否能识别到authenticate调用  爆炸 5000节点上限也找不到authenticate调用
/*		Collection<SootMethod> possibleTargets = new LinkedList<SootMethod>();
		SootClass sc = SC.cm.get("v8.o");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("onClick(")){
					possibleTargets.add(mm);
				}
			}
		}
		Collection<Tree<CallgraphState>> possibleTargetsTrees = new LinkedList<Tree<CallgraphState>>();
		boolean found_something = false;
		for(SootMethod mm : possibleTargets){
			ForwardCallgraph fc = new ForwardCallgraph(SC, mm);
			Tree<CallgraphState> tree = fc.run();
			if(tree.nodeMap.size()>1){
				possibleTargetsTrees.add(tree);
			}

		}
		print("############");
		print(String.valueOf(possibleTargetsTrees));
		print("############");
 */

		// 从authenticate建立后向cg看是否有onclick
		Collection<SootMethod> possibleTargets = new LinkedList<SootMethod>();
		SootClass sc = SC.cm.get("android.hardware.fingerprint.FingerprintManager");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("authenticate(")){
					possibleTargets.add(mm);
				}
			}
		}
		Collection<Tree<CallgraphState>> possibleTargetsTrees = new LinkedList<Tree<CallgraphState>>();
		for(SootMethod mm : possibleTargets){
			BackwardCallgraph bc = new BackwardCallgraph(SC, mm);
			bc.skipLibraries = true;
//			Tree<CallgraphState> tree = bc.run(200);
			Tree<CallgraphState> tree = bc.run(1000);
			if(tree.nodeMap.size()>1){
				possibleTargetsTrees.add(tree);
			}
		}
//		print("############");
//		print(String.valueOf(possibleTargetsTrees));
//		print("############");

		features.add("Authenticate_bg", "", "", String.valueOf(possibleTargetsTrees), "", "");
	}

    private static void TestOnclickAuthenticate_dfs(Features features, SootContext SC) {
        Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
        for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
            usages.addAll(SC.getAPIUsage(className, "void authenticate", true, false));
        }
        if(usages.size() == 0){
            print("[analyzeCaller]: no authenticate found!");
        }
        String res = null;
        for(CodeLocation usage : usages) {
//            res = dfs(usage, SC, pkg);
            res = switch_dfs_limitedDepth(usage, SC, "onCheckedChanged", 100);

            if (res != null) {
                String[] tres = res.split("@@@");		// callerClass@@@caller_chain
                features.add("Authenticate_bg_dfs", tres[0], "", String.valueOf(true), "", tres[1]);
                break;
            } else {
                features.add("Authenticate_bg_dfs", res, "", String.valueOf(false), "", "");
            }
        }
    }

    private static String switch_dfs_limitedDepth(CodeLocation authenticateUsage, SootContext SC, String kw, Integer limitDepth) {
        // 创建一个DFS队列
        SootMethod authenticateMethod = authenticateUsage.smethod;
        Deque<Pair<SootMethod, Integer>> dfsStack = new ArrayDeque<>();
        dfsStack.push(new Pair<>(authenticateMethod, 0));
//		String lastMethod = "";
        StringBuilder caller_chain = new StringBuilder();

        Set<SootMethod> visitedMethods = new HashSet<>();
        while (!dfsStack.isEmpty()) {
            Pair<SootMethod, Integer> methodDepthPair = dfsStack.pop();
            SootMethod method = methodDepthPair.getKey();
            int depth = methodDepthPair.getValue();

            // 超出预定的深度限制，即不继续探索更深
            if (visitedMethods.contains(method) || depth > limitDepth) {
                continue;
            }
            print(depth, String.valueOf(method));
            caller_chain.append(String.valueOf(methodDepthPair));

            visitedMethods.add(method);

            for (CodeLocation caller_cl : SC.getCallers(method)) {
                SootMethod caller = caller_cl.smethod;

                // 如果caller和method相同，pass
                if(String.valueOf(caller).equals(String.valueOf(method))) {
                    continue;
                }
                String callerMethod = caller.getSignature();
                if (callerMethod.contains(kw)) {
                    // 判断caller的类名前缀是否为"APP"，如果是则停止搜索
                    return callerMethod + "@@@" + caller_chain.toString();
                } else {
                    dfsStack.push(new Pair<>(caller, depth + 1));
                }
            }
        }
        return null;
    }


        /****************** zx iskeyentry, create *************/
	private static void analyzeKeyCreation(Features features, SootContext SC) {

		// 判断在生成密钥前是否调用isKeyEntry，即每次都判断密钥是否存在，不存在就新建密钥
		Collection<SootMethod> possibleTargets = new LinkedList<SootMethod>();
		SootClass sc = SC.cm.get("javax.crypto.KeyGenerator");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("init(")){
					possibleTargets.add(mm);
				}
			}
		}
		Collection<Tree<CallgraphState>> possibleTargetsTrees = new LinkedList<Tree<CallgraphState>>();
		for(SootMethod mm : possibleTargets){
			BackwardCallgraph bc = new BackwardCallgraph(SC, mm);
			bc.skipLibraries = true;
			Tree<CallgraphState> tree = bc.run(10);
			if(tree.nodeMap.size()>1){
				possibleTargetsTrees.add(tree);
			}
		}

//		print("\n****************************init************\n", String.valueOf(possibleTargetsTrees));
//		print("\n****************************\n");

		boolean find_flag = false;
		Tree<CallgraphState> target_tree = null;

		// 遍历init的后向cg，找其中涉及的method中是否有isKeyEntry调用
		for(Tree<CallgraphState> btree : possibleTargetsTrees){
			HashMap<SootMethod, Node<CallgraphState>> ftmap = new HashMap<>();
			for(Node<CallgraphState> n : btree.nodeMap.values()){
				SootMethod mm = n.value.method;
				int level = n.level;
				if(! ftmap.containsKey(mm) || ftmap.get(mm).level > level){
					ftmap.put(mm, n);
				}
			}

			for(Entry<SootMethod, Node<CallgraphState>>  ee : ftmap.entrySet()){
				SootMethod mm = ee.getKey();
				if(!mm.hasActiveBody()){
					continue;
				}

//				print("########################\n", String.valueOf(mm), "\n");
				Node<CallgraphState> n1 = ee.getValue();
				for(Unit uu : mm.getActiveBody().getUnits()){
//					print("*** unit: ", String.valueOf(uu), "\n");
//					if(uu instanceof InvokeStmt){
					if(uu instanceof InvokeStmt || uu instanceof AssignStmt && ((AssignStmt) uu).containsInvokeExpr()) {
//						InvokeExpr invokeExpr = ((InvokeStmt) uu).getInvokeExpr();
						// 将语句转换为 InvokeExpr
						InvokeExpr invokeExpr;
						if (uu instanceof InvokeStmt) {
							invokeExpr = ((InvokeStmt) uu).getInvokeExpr();
						} else {
							invokeExpr = ((AssignStmt) uu).getInvokeExpr();
						}
//						print("** class, method: ", invokeExpr.getMethod().getDeclaringClass().getName(), invokeExpr.getMethod().getName());
						if (invokeExpr.getMethod().getDeclaringClass().getName().equals("java.security.KeyStore")
								&& invokeExpr.getMethod().getName().equals("isKeyEntry")) {
							System.out.println("Found call to java.security.KeyStore.isKeyEntry");
							find_flag = true;
							target_tree = btree;
							break;
						}
					}
				}
			}
		}
		features.add("isKeyEntry_beforeCreation", "", "", String.valueOf(find_flag), target_tree, "");	//zx


		//判断authenticate前是否调用init新建密钥（算了先不搞了，跟上面的不一样，authenticate要看的不是它的后向cg而是它参数crypto的

	}


	private static void analyzeUnlock(Features features, SootContext SC) {
		Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
		for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
			usages.addAll(SC.getAPIUsage(className, "boolean hasEnrolledFingerprints", true, true));
		}
		//in this case it could be that they are using obfuscated wrapper library
		//I assume that they don't use both obfuscated wrapper library and direct call
		//to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
		//it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
		if(usages.size() == 0){			// zx: unnecessary?
			usages.addAll(SC.getAPIUsage("android.hardware.fingerprint.FingerprintManager", "boolean hasEnrolledFingerprints", true, false));
		}

		// 加入androidx包调用的处理 androidx.biometric.BiometricManager.canAuthenticate
		for(String className : Utils.expandToSupportClasses("androidx.biometric.BiometricManager")){
			usages.addAll(SC.getAPIUsage(className, "int canAuthenticate", true, true));
		}

		//filtering usages in framework which are not really used.
		Collection<CodeLocation> usages_filtered = new LinkedList<CodeLocation>();
		for(CodeLocation cl : usages){
			if(! isSupportClass(cl.smethod.getDeclaringClass())){
				usages_filtered.add(cl);
				continue;
			}
		}

		Collection<Tree<SlicerState>> strees = new LinkedList<>();

		for(CodeLocation cl : usages_filtered){
			Unit uu = cl.sunit;
//			Local returnValue = (Local) ((Stmt) uu).getUseBoxes().get(0).getValue();
//			Value returnValue = ((Stmt) uu).getInvokeExpr().getUseBoxes().get(0).getValue();
			Value returnValue = uu.getDefBoxes().get(0).getValue();
			print("##################### return Value: ", String.valueOf(returnValue));

			ForwardSlicer FS = new ForwardSlicer(SC, uu, String.valueOf(returnValue), cl.smethod);
            Tree<SlicerState> tree = FS.run_track(100);
            strees.add(tree);

			print("============== isWeakUnlock ==============");
			if(isWeakUnlock(tree)) {
				features.add("Unlock", uu.toString(), cl, "WEAK", String.valueOf(returnValue), String.valueOf(tree));
			}
			else {
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

		for(SlicerState ss : stree.getAllNodes()){
			print();
			print(String.valueOf(ss));
			print("REG: ", ss.reg);
			if(String.valueOf(ss.reg).equals("if")) {
				print("IF: ", String.valueOf(ss));
				Node<SlicerState> sn = stree.getNode(ss);
				// 判断if节点的子节点是否为两个不同的intent
				List<Node<SlicerState>> children = sn.children;
				print("Children:", String.valueOf(children));
				if(children.size() == 2) {
					String intent1 = children.get(0).value.reg;
					String intent2 = children.get(1).value.reg;
					if(!intent1.equals(intent2) && (intent1.contains("MainActivity") || intent2.contains("MainActivity"))) {
						print("WEAK!!!");
						return true;
					}
					if(intent1.contains("MainActivity") && intent2.contains("MainActivity")) {
						//可能两个都是进入主页面，存在一些其他判断
						print("WEAK!!!");
						return true;
					}
					if(intent1.contains("authenticate") ^ intent2.contains("authenticate")) {
						print("WEAK!!!");
						return true;
					}
				}
			}
			if(String.valueOf(ss.reg).equals("WEAK")) {
				print("WEAK!!!");
				return true;
			}
		}
		print("STRONG!!!");
		return false;
	}


	// dfs找authenticate的caller，不断回溯，如果caller类名中包含APP包名，则认为是APP中调用了，否则未调用
	private static void analyzeCaller(Features features, SootContext SC, String pkg) {
        Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
        for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
            usages.addAll(SC.getAPIUsage(className, "void authenticate", true, false));
        }
        if(usages.size() == 0){
            print("[analyzeCaller]: no authenticate found!");
        }
        String res = null;
        for(CodeLocation usage : usages) {
//            res = dfs(usage, SC, pkg);
			res = dfs_limitedDepth(usage, SC, pkg, 100);
//			res = dfs_limitedDepth(usage, SC, pkg, 500);

			if (res != null) {
				String[] tres = res.split("@@@");		// callerClass@@@caller_chain
				features.add("Authenticate_caller_in_pkg", tres[0], "", String.valueOf(true), "", tres[1]);
				break;
			} else {
				features.add("Authenticate_caller_in_pkg", res, "", String.valueOf(false), "", "");
			}
		}
    }

    private static String dfs(CodeLocation authenticateUsage, SootContext SC, String pkg) {
        // 创建一个DFS队列
        SootMethod authenticateMethod = authenticateUsage.smethod;
        Deque<SootMethod> dfsStack = new ArrayDeque<>();
        dfsStack.push(authenticateMethod);

        Set<SootMethod> visitedMethods = new HashSet<>();
        while (!dfsStack.isEmpty()) {
            SootMethod method = dfsStack.pop();
            if (visitedMethods.contains(method)) {
                continue;
            }
            visitedMethods.add(method);

            for (CodeLocation caller_cl : SC.getCallers(method)) {
                SootMethod caller = caller_cl.smethod;
                String callerClassName = caller.getDeclaringClass().getName();
                if (callerClassName.startsWith(pkg)) {
                    // 判断caller的类名前缀是否为"APP"，如果是则停止搜索
                    return callerClassName;
                } else {
                    dfsStack.push(caller);
                }
            }
        }
        return null;
    }

    private static String dfs_limitedDepth(CodeLocation authenticateUsage, SootContext SC, String pkg, Integer limitDepth) {
		// 创建一个DFS队列
		SootMethod authenticateMethod = authenticateUsage.smethod;
		Deque<Pair<SootMethod, Integer>> dfsStack = new ArrayDeque<>();
		dfsStack.push(new Pair<>(authenticateMethod, 0));
//		String lastMethod = "";
		StringBuilder caller_chain = new StringBuilder();

		Set<SootMethod> visitedMethods = new HashSet<>();
		while (!dfsStack.isEmpty()) {
			Pair<SootMethod, Integer> methodDepthPair = dfsStack.pop();
			SootMethod method = methodDepthPair.getKey();
			int depth = methodDepthPair.getValue();

			// 超出预定的深度限制，即不继续探索更深
			if (visitedMethods.contains(method) || depth > limitDepth) {
				continue;
			}
			print(depth, String.valueOf(method));
			caller_chain.append(String.valueOf(methodDepthPair));

			visitedMethods.add(method);

			Collection<CodeLocation> caller_cls = SC.getCallers(method);
//			Collection<CodeLocation> caller_cls = SC.getCallers_precise(method);
//			Collection<SootMethod> caller_cls = findCaller(method);

			if (caller_cls.size() > 50) {
				continue;
			}

			HashSet<String> uni_callers = new LinkedHashSet<>();
			for (CodeLocation caller_cl : caller_cls) {
//			for (SootMethod caller : caller_cls) {
				SootMethod caller = caller_cl.smethod;
				if(uni_callers.contains(String.valueOf(caller))) {
					continue;
				}
				uni_callers.add(String.valueOf(caller));

				// 如果caller和method相同，pass
				if(String.valueOf(caller).equals(String.valueOf(method))) {
					continue;
				}

				print(depth + 1, String.valueOf(caller));

				String callerClassName = caller.getDeclaringClass().getName();
//				if (callerClassName.startsWith(pkg)) {
				if(isEntryPoint(callerClassName, pkg)) {
					// 判断caller的类名前缀是否为"APP"，如果是则停止搜索
					caller_chain.append(String.valueOf(new Pair<>(caller, depth + 1)));
					return callerClassName + "@@@" + caller_chain.toString();
				} else if (!visitedMethods.contains(caller)) {
					dfsStack.push(new Pair<>(caller, depth + 1));
				}
			}
		}
		return null;
	}

	public static boolean isEntryPoint(String classname, String pkg) {
		return entryPoints.contains(classname) && classname.startsWith(pkg);
	}

	public static Collection<SootMethod> findCaller(SootMethod sootMethod) {
		HashSet<SootMethod> res = new HashSet<>();
		Iterator<Edge> edges = callGraph.edgesInto(sootMethod);
		while(edges.hasNext()) {
			Edge edge = edges.next();
			SootMethod caller = edge.getSrc().method();
			res.add(caller);
		}
		return res;
	}

	/******************************************************/

	private static void analyzeOnAuthenticationSucceeded(Features features, SootContext SC) {
		Collection<SootMethod> possibleTargets = new LinkedList<SootMethod>();
		SootClass sc = SC.cm.get("java.security.Signature");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("sign(")|| mm.getSubSignature().contains(" update(")){
					possibleTargets.add(mm);
				}
			}
		}
		sc = SC.cm.get("javax.crypto.Cipher");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("doFinal(")|| mm.getSubSignature().contains(" update(")){
					possibleTargets.add(mm);
				}
			}
		}
		
		Collection<Tree<CallgraphState>> possibleTargetsTrees = new LinkedList<Tree<CallgraphState>>();
		for(SootMethod mm : possibleTargets){
			BackwardCallgraph bc = new BackwardCallgraph(SC, mm);
			bc.skipLibraries = true;
			Tree<CallgraphState> tree = bc.run(200);
			if(tree.nodeMap.size()>1){
				possibleTargetsTrees.add(tree);
			}
		}
		
		
		Collection<SootMethod> succeededUsages = new LinkedList<SootMethod>();
		for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback")){
			SootMethod mm = SC.resolveMethod(className, "void onAuthenticationSucceeded", true);
			if(mm==null){
				continue;
			}
			Collection<SootMethod> tusages = SC.getOverrides(mm);
			succeededUsages.addAll(tusages);
		}

		Collection<SootMethod> succeededUsages_filtered = new LinkedList<SootMethod>();
		for(SootMethod m : succeededUsages){
			if(Utils.isSupportClass(m.getDeclaringClass())){
				continue;
			} 
			succeededUsages_filtered.add(m);
		}
		//in this case it could be that they are using obfuscated wrapper library
		//I assume that they don't use both obfuscated wrapper library and direct call
		//to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
		//it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
		if(succeededUsages_filtered.size() == 0){
			succeededUsages_filtered = succeededUsages;
		}
		//I cannot really filter here to see if it is really used, since it is a callback the cg does not give me enough info.
				
		for(SootMethod m : succeededUsages_filtered){
			
			ForwardCallgraph fc = new ForwardCallgraph(SC, m);
			Tree<CallgraphState> tree = fc.run();
			
			boolean found_something = false;
			
			for(Tree<CallgraphState> btree : possibleTargetsTrees){
				Tree<CallgraphState> connectedTree = intersectTrees(tree, btree);
				if(connectedTree==null){
					continue;
				}

				for(Node<CallgraphState> n : connectedTree.nodeMap.values()){
					SootMethod m2 = n.value.method;
					String cname = m2.getDeclaringClass().getName();
					String mname = m2.getSubSignature();
					if(cname.equals("java.security.Signature")){
						if(mname.contains("sign(")|| mname.contains(" update(")){
							String result = "Asymm";		// zx
							Tuple<Unit, InvokeExpr> u_i = SC.recoverEdge(n.value.method, n.parent.value.method);
							if(u_i == null){
								continue;
							}
							Unit uu = u_i.x;
							InvokeExpr ie = u_i.y;
							String extra = "";
							if(mname.contains("update(")){
								Value vv2 = ie.getArgs().get(0);
								String reg = String.valueOf(vv2);
								if(reg.startsWith("$")){
									Slicer sl = new Slicer(SC, uu, reg, n.parent.value.method);
									Tree<SlicerState>  stree = sl.run(20);
									extra = String.valueOf(stree);
								}else{
									extra = String.valueOf(reg);
								}
							}
							//*************** zx
							if(mname.contains("sign(")) {
								if(uu.getDefBoxes().size() == 0){
									result = "Weak";
								}
							}
							//*************** zx

//							features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Asymm", tree, extra);
							features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), result, tree, extra);	//zx
							found_something = true;
						}
					}
					if(cname.equals("javax.crypto.Cipher")){ 
						if(mname.contains("doFinal(") || mname.contains(" update(")){ //update seems needed at least for ebay
							Tuple<Unit, InvokeExpr> u_i = SC.recoverEdge(n.value.method, n.parent.value.method);
							if(u_i == null){
								continue;
							}
							Unit uu = u_i.x;
							InvokeExpr ie = u_i.y;
						
							if(mname.contains("doFinal(")){
								boolean isEncryptingConstant = false;
								if(ie.getArgs().size()==1){
									String reg = String.valueOf(ie.getArg(0));
									if(reg.startsWith("$")){
										Slicer sl = new Slicer(SC, uu, reg, n.parent.value.method);
										sl.skipThisReg = false;
										sl.followMethodParams = true;
										Tree<SlicerState> stree = sl.run(20);
										isEncryptingConstant = isSliceToConstant(stree);
									}
								}
								// check if result is not used, or if what is encrypted is constant
								if (isEncryptingConstant || uu.getDefBoxes().size() == 0){
									features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Weak", tree, "");
								}else{
									features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Symm", tree, "");
								}
							}else{
								features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Symm", tree, "");
							}

							found_something = true;
						}
					}
				}
			}

			if(! found_something){
				features.add("Succeeded", "", join(",",new Object[] {m, null, null}), "Unknown", tree, "");
			}
		}
		
	}

	public static Tree<CallgraphState> intersectTrees(Tree<CallgraphState> ft, Tree<CallgraphState> bt){
		HashMap<SootMethod, Node<CallgraphState>> ftmap = new HashMap<>();
		for(Node<CallgraphState> n : ft.nodeMap.values()){
			SootMethod mm = n.value.method;
			int level = n.level;
			if(! ftmap.containsKey(mm) || ftmap.get(mm).level > level){
				ftmap.put(mm, n);
			}
		}
		HashMap<SootMethod, Node<CallgraphState>> btmap = new HashMap<>();
		for(Node<CallgraphState> n : bt.nodeMap.values()){
			SootMethod mm = n.value.method;
			int level = n.level;
			if(! btmap.containsKey(mm) || btmap.get(mm).level > level){
				btmap.put(mm, n);
			}
		}
		
		int candidateDepthF = Integer.MAX_VALUE;
		int candidateDepthB = Integer.MAX_VALUE;
		Node<CallgraphState> c1 = null;
		Node<CallgraphState> c2 = null;
		for(Entry<SootMethod, Node<CallgraphState>>  ee : ftmap.entrySet()){
			SootMethod mm = ee.getKey();
			Node<CallgraphState> n1 = ee.getValue();
			Node<CallgraphState> n2 = btmap.get(mm);
			if(n2!=null){
				int depthF = n1.level;
				int depthB = n2.level;
				if(depthB < candidateDepthB || (depthB == candidateDepthB && depthF < candidateDepthF)){
					candidateDepthF = depthF;
					candidateDepthB = depthB;
					c1 = n1;
					c2 = n2;
				}
			}	
		}

		Tree<CallgraphState> res = null;
		if(c1!=null && c2!=null){
			res = new Tree<>();
			Node<CallgraphState> cnode = c1;
			List<Node<CallgraphState>> nlist = new LinkedList<>();
			while(cnode != null){
				nlist.add(0, cnode);
				cnode = cnode.parent;
			}
			Node<CallgraphState> prev = new Node<CallgraphState>(nlist.get(0));
			prev.level = 0;
			nlist.remove(0);
			res.addHead(prev);
			for(Node<CallgraphState> n : nlist){
				prev = res.addChild(prev, n.value);
			}
			cnode = c2;
			while(cnode != null){
				prev = res.addChild(prev, cnode.value);
				cnode = cnode.parent;
			}
		}
		
		
		return res;
	}
	
	private static void analyzeAuthenticationRequired(Features features, SootContext SC){
		Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)", false, false);
		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter(SC,cl.sunit, 0);
			features.add("AuthenticationRequired", vv, cl, "", "KeyGenParameterSpec$Builder", SC.getInvokeExpr(cl.sunit));
		}
		usages = SC.getAPIUsage("android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationRequired(boolean)", false, false);
		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter(SC,cl.sunit, 0);
			features.add("AuthenticationRequired", vv, cl, "", "KeyProtection$Builder", SC.getInvokeExpr(cl.sunit));
		}
	}

	/*   zx     */
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

		usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)", false, false);
		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter_resolve(SC,cl.sunit, 0, cl);
			features.add("AuthenticationRequired", vv, cl, "", "KeyGenParameterSpec$Builder", SC.getInvokeExpr(cl.sunit));
		}
		usages = SC.getAPIUsage("android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationRequired(boolean)", false, false);
		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter_resolve(SC,cl.sunit, 0, cl);
			features.add("AuthenticationRequired", vv, cl, "", "KeyProtection$Builder", SC.getInvokeExpr(cl.sunit));
		}
	}

	public static boolean handleIntFlag(SootContext SC, CodeLocation cl, Value sv, int targetFlag, String matchType){
		int finalValue;
		String valueString = sv.toString();
		
		if(targetFlag == 0 & valueString.equals("null")){
			if(matchType.equals("equal")){
					return true;
			}
		}
		//   **********zx
		if(sv.getType().toString().equals("int")){
			if(valueString.startsWith("$")){
				print("***[SA: handlrIntFlag] $$$cl.smethod ***", cl.smethod.toString());
				Unit newUnit = SC.getDefUnit(valueString, cl.smethod, true);
				if(newUnit == null){
					print("***[SA] handlrIntFlag***", "getDefUnit returns null");
				}
				String newValue = "";
				for(ValueBox vb : newUnit.getUseBoxes()) {
					String boxType = vb.getClass().getSimpleName();
					InvokeExpr ie = SC.getInvokeExpr(newUnit); //we check this because LinkedRValueBox can be an ie
					boolean isNewAssignment = SC.isNewAssignment(newUnit);
					if (stringInList(boxType, Arrays.asList((new String[]{"ImmediateBox", "SValueUnitPair", "JimpleLocalBox", "IdentityRefBox"}))) ||
							(boxType.equals("LinkedRValueBox") && (ie == null || isNewAssignment))) {
						newValue = vb.getValue().toString();
						if (newValue.equals("")) {
							continue;
						} else if (isReg(newValue) || newValue.startsWith("@")) { //LinkedRValueBox contains bad things
							//newValue is a reg, we want to find it
							break;
						}
					}
				}

				int narg = Integer.parseInt(Utils.strExtract(newValue, "@parameter", ": "));

				Collection<CodeLocation> callers = SC.getCallers(cl.smethod);
				for(CodeLocation caller: callers) {
					if(caller != null){
						Value vv = SC.getInvokeExpr(caller.sunit).getArg(narg);
						if(vv.getType().toString().equals("int")) {
							finalValue = Integer.parseInt(vv.toString());
							print("***[SA: handleIntFlag] finalValue***", finalValue);
							if(matchType.equals("and")){
								if((finalValue & targetFlag)!=0){
									return true;
								}
							}else if(matchType.equals("equal")){
								if(finalValue == targetFlag){
									return true;
								}
							}
							return false;
						}
					}
				}
//				Collection<CodeLocation> callers = SC.getCallers(cl.smethod);
//				for(CodeLocation caller : callers){
////					Value vv = SC.getInvokeExpr(caller.sunit).getArg();
//					print("***[handleIntFlag]***", caller.toString());
//				}

//				Slicer ss = new Slicer(SC, cl.sunit, valueString, cl.smethod);
//				ss.followMethodParams = true;
//				print("***[handleIntFlag] ss***", cl.sunit, valueString, cl.smethod);
//				Tree<SlicerState>  stree = ss.run();
//				for(SlicerState st : stree.getLeaves()) {
//					print("***[handleIntFlag] stree***", st.toString());
//					if (st.unit != null) {
//						Value vv = getInvokeParameter(SC, st.unit, 0);
//						print("*** arg: ", vv.toString());
//					} else {
//						print("*** st.unit is null");
//					}
//				}

			}
			else {
				finalValue = Integer.valueOf(valueString);
				if (matchType.equals("and")) {
					if ((finalValue & targetFlag) != 0) {
						return true;
					}
				} else if (matchType.equals("equal")) {
					if (finalValue == targetFlag) {
						return true;
					}
				}
			}
		}
		//   **********zx END
		
//		if(sv.getType().toString().equals("int")){
//			finalValue = Integer.valueOf(valueString);
//			if(matchType.equals("and")){
//				if((finalValue & targetFlag)!=0){
//					return true;
//				}
//			}else if(matchType.equals("equal")){
//				if(finalValue == targetFlag){
//					return true;
//				}
//			}
//		}
//		else if(valueString.startsWith("$")){
//			Slicer ss = new Slicer(SC, cl.sunit, valueString, cl.smethod);
//			ss.run();		//zx: do slicing but no judging?? --return false?
//		}
		return false;
	}
	
	public static Value getInvokeParameter(SootContext SC, Unit uu, int argIndex){
		// 0 is the first arg and NOT "this"
//		print("*** getInvokeParameter", SC.getInvokeExpr(uu));
		return SC.getInvokeExpr(uu).getArgs().get(argIndex);
	}

	public static Value getInvokeParameter_resolve(SootContext SC, Unit uu, int argIndex, CodeLocation cl) {
		int finalValue;
		Value sv = SC.getInvokeExpr(uu).getArgs().get(argIndex);
		print("---[getInvokeParameter_resolve]---sv:", String.valueOf(sv));
		String valueString = sv.toString();
		if (!valueString.contains("$")) {
			return sv;
		} else if (valueString.startsWith("$")) {
			int cnt = 0;
			while (valueString.startsWith("$")){
				cnt += 1;
				if(cnt >= 100) {
					break;
				}
				print("***[SA: handlrIntFlag] $$$cl.smethod ***", cl.smethod.toString());
				Unit newUnit = SC.getDefUnit(valueString, cl.smethod, true);
				print("---[getInvokeParameter_resolve]---newUnit:", String.valueOf(newUnit));
				if (newUnit == null) {
					print("***[SA] handlrIntFlag***", "getDefUnit returns null");
				}
				String newValue = "";
				for (ValueBox vb : newUnit.getUseBoxes()) {
					String boxType = vb.getClass().getSimpleName();
					InvokeExpr ie = SC.getInvokeExpr(newUnit); //we check this because LinkedRValueBox can be an ie
					boolean isNewAssignment = SC.isNewAssignment(newUnit);
					if (stringInList(boxType, Arrays.asList((new String[]{"ImmediateBox", "SValueUnitPair", "JimpleLocalBox", "IdentityRefBox"}))) ||
							(boxType.equals("LinkedRValueBox") && (ie == null || isNewAssignment))) {
						newValue = vb.getValue().toString();
						print("---[getInvokeParameter_resolve]---newValue:", newValue);
						if (newValue.equals("")) {
							continue;
						} else if (isReg(newValue) || newValue.startsWith("@")) { //LinkedRValueBox contains bad things
							//newValue is a reg, we want to find it
							break;
						}
						if (newValue.equals("1") || newValue.equals("0")) {
							return vb.getValue();
						}
					}
				}

				if(newValue.startsWith("$")) {
					valueString = newValue;
					continue;
				}
				int narg = Integer.parseInt(Utils.strExtract(newValue, "@parameter", ": "));
				print("***[SA: getInvokeParameter_resolve] narg:***", String.valueOf(narg));

				Collection<CodeLocation> callers = SC.getCallers(cl.smethod);
				for (CodeLocation caller : callers) {
					if (caller != null) {
						Value vv = SC.getInvokeExpr(caller.sunit).getArg(narg);
						String vvString = vv.toString();
						valueString = vvString;
						print("***[SA: getInvokeParameter_resolve] caller_vv:***", vv.toString(), vv.getType().toString());
						if (vv.getType().toString().equals("boolean")) {
//							finalValue = Integer.parseInt(vv.toString());
//							print("***[SA: getInvokeParameter_resolve] finalValue***", finalValue);

							valueString = vv.toString();
							print("***[SA: getInvokeParameter_resolve] valueString***", valueString);
							if(valueString.equals("1") || valueString.equals("0")){
								return vv;
							}
//							return vv;
							if(valueString.startsWith("$")) {
								cl = caller;
								break;
							}
						}
						else if(vvString.equals("0") || vvString.equals("1")) {
							return vv;
						}
					}
				}
			}




//			print("***[SA: handlrIntFlag] $$$cl.smethod ***", cl.smethod.toString());
//			Unit newUnit = SC.getDefUnit(valueString, cl.smethod, true);
//			print("---[getInvokeParameter_resolve]---newUnit:", String.valueOf(newUnit));
//			if (newUnit == null) {
//				print("***[SA] handlrIntFlag***", "getDefUnit returns null");
//			}
//			String newValue = "";
//			for (ValueBox vb : newUnit.getUseBoxes()) {
//				String boxType = vb.getClass().getSimpleName();
//				InvokeExpr ie = SC.getInvokeExpr(newUnit); //we check this because LinkedRValueBox can be an ie
//				boolean isNewAssignment = SC.isNewAssignment(newUnit);
//				if (stringInList(boxType, Arrays.asList((new String[]{"ImmediateBox", "SValueUnitPair", "JimpleLocalBox", "IdentityRefBox"}))) ||
//						(boxType.equals("LinkedRValueBox") && (ie == null || isNewAssignment))) {
//					newValue = vb.getValue().toString();
//					print("---[getInvokeParameter_resolve]---newValue:", newValue);
//					if (newValue.equals("")) {
//						continue;
//					} else if (isReg(newValue) || newValue.startsWith("@")) { //LinkedRValueBox contains bad things
//						//newValue is a reg, we want to find it
//						break;
//					}
//					if (newValue.equals("1") || newValue.equals("0")) {
//						return vb.getValue();
//					}
//				}
//			}
//
//			int narg = Integer.parseInt(Utils.strExtract(newValue, "@parameter", ": "));
//
//			Collection<CodeLocation> callers = SC.getCallers(cl.smethod);
//			for (CodeLocation caller : callers) {
//				if (caller != null) {
//					Value vv = SC.getInvokeExpr(caller.sunit).getArg(narg);
//					if (vv.getType().toString().equals("boolean")) {
//						finalValue = Integer.parseInt(vv.toString());
//						print("***[SA: getInvokeParameter_resolve] finalValue***", finalValue);
//						return vv;
//					}
//				}
//			}
		}


		return sv;
	}

	// 多个入口方法
//	private CG buildCG(List<SootMethod> entryMethods){
//		CG.setSpark(false);
//		CG cg = new CG(entryMethods);
//		return cg;
//	}

	public Scene run(Map<String,String> config) throws Exception{
		String input = config.get("input_file");
		Options.v().set_process_dir(Collections.singletonList(input));
		
		if(config.get("input_format").equals("apk")){
			Options.v().set_android_jars(config.get("android_sdk")); // Android/Sdk/platforms
			Options.v().set_process_multiple_dex(true);
			Options.v().set_src_prec(Options.src_prec_apk);
		}else if(config.get("input_format").equals("jar")){
			Options.v().set_soot_classpath(config.get("soot_classpath"));
		}else{
			throw(new Exception("invalid input type"));
		}

		if(config.get("ir_format").equals("jimple")){
			Options.v().set_output_format(Options.output_format_jimple);
            Options.v().set_output_dir("/home/zzz/BioAuth/weak_config/my_sootAnalysis/test/output/");
		}else if(config.get("ir_format").equals("shimple")){
			Options.v().set_output_format(Options.output_format_shimple);
			Options.v().set_output_dir("/home/zzz/BioAuth/weak_config/my_sootAnalysis/test/output_vflynote/");
		}else{
			throw(new Exception("invalid ir format"));
		}
		
		Options.v().set_allow_phantom_refs(true);
		Options.v().setPhaseOption("cg", "all-reachable:true"); 
				
		Options.v().setPhaseOption("jb.dae", "enabled:false");
		Options.v().setPhaseOption("jb.uce", "enabled:false");
		Options.v().setPhaseOption("jj.dae", "enabled:false");
		Options.v().setPhaseOption("jj.uce", "enabled:false");
				
		Options.v().set_wrong_staticness(Options.wrong_staticness_ignore); //should be fixed in newer soot

		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();
//        PackManager.v().writeOutput();      // output
		System.gc();
		
		print("Soot is done!");

//		callGraph = Scene.v().getCallGraph();
//		print("Callgraph is done!");
		
		return Scene.v();
	}

	public Scene run_flowdroid(Map<String,String> config_para) throws Exception{
		String apk = config_para.get("input_file");
		String jarPath = config_para.get("android_sdk");
//		SetupApplication app = new SetupApplication(jarPath, apk);
//		app.getConfig().setMergeDexFiles(true);
//		app.constructCallgraph();



//		G.reset();
//		InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
//		configuration.getAnalysisFileConfig().setTargetAPKFile(apk);
//		configuration.getAnalysisFileConfig().setAndroidPlatformDir(jarPath);
//		configuration.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.RemoveSideEffectFreeCode);
//		configuration.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
//		SetupApplication setupApplication = new SetupApplication(configuration);
//		setupApplication.getConfig().setEnableReflection(true);
//		setupApplication.getConfig().setMergeDexFiles(true);
//
//		setupApplication.constructCallgraph();
//		Scene.v().loadNecessaryClasses();
//		callGraph = Scene.v().getCallGraph();
//		return Scene.v();


		/****************************************************/
		final InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
		config.getAnalysisFileConfig().setTargetAPKFile(apk);
		config.getAnalysisFileConfig().setAndroidPlatformDir(jarPath);
		config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
		config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA); // CHA or SPARK
		config.setMergeDexFiles(true);
		SetupApplication app = new SetupApplication(config);
		app.constructCallgraph();
		callGraph = Scene.v().getCallGraph();
		return Scene.v();




		/*if(config.get("ir_format").equals("jimple")){
			Options.v().set_output_format(Options.output_format_jimple);
			Options.v().set_output_dir("/home/zzz/BioAuth/weak_config/my_sootAnalysis/test/output/");
		}else if(config.get("ir_format").equals("shimple")){
			Options.v().set_output_format(Options.output_format_shimple);
			Options.v().set_output_dir("/home/zzz/BioAuth/weak_config/my_sootAnalysis/test/output_vflynote/");
		}else{
			throw(new Exception("invalid ir format"));
		}

		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Collections.singletonList(apk));
		Options.v().set_force_android_jar(jarPath + "/android-26/android.jar");
		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
//		Options.v().setPhaseOption("cg.spark verbose:true", "on");
		Scene.v().loadNecessaryClasses();

//		SootMethod entryPoint = app.getEntryPointCreator().createDummyMain();
//		Options.v().set_main_class(entryPoint.getSignature());
//		Scene.v().setEntryPoints(Collections.singletonList(entryPoint));
		PackManager.v().runPacks();
		//获取函数调用图
		callGraph = Scene.v().getCallGraph();

//        PackManager.v().writeOutput();      // output
//		System.gc();

		print("Callgraph is done!");

		return Scene.v();*/
	}
	
	public void stop(){
		System.exit(0);
	}
	
	public String connectionTest(String p1){
		return p1+" SUCCESS!";
	}
	
	public static String aaptResult(String fname){
		URL jarLocationUrl = SootAnalysis.class.getProtectionDomain().getCodeSource().getLocation();
		String jarLocation = new File(jarLocationUrl.toString().replace("file:","")).getParent();
//		String aaptLocation = new File(jarLocation).toString().concat("/aapt/aapt").toString();
//		String aaptLocation = new File(jarLocation).toString().concat("\\aapt\\aapt").toString();		//windows
		String aaptLocation = new File(jarLocation).toString().concat(File.separator + "aapt" + File.separator +"aapt").toString();		//windows
		String tstr = "";

		try {
//			String [] args = new String[] {aaptLocation, "dump", "badging", fname};
			String [] args = new String[] {"aapt", "dump", "badging", fname};			// linux
			print(Utils.join(" ", args));
			Process exec = Runtime.getRuntime().exec(args);
			BufferedReader stdOut = new BufferedReader(new InputStreamReader(exec.getInputStream()));

//			BufferedReader stderr = new BufferedReader(new InputStreamReader(exec.getErrorStream()));

//			exec.waitFor();
			String s = null;
			while ((s = stdOut.readLine()) != null) {
			    tstr += s + "\n";
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
//		catch (InterruptedException e) {
//			e.printStackTrace();
//		}
		return tstr;
	}
	
	public static boolean isSliceToConstant(Tree<SlicerState> stree) {
		SlicerState leaf = null;
		for(SlicerState ss : stree.getLeaves()){
			if(! String.valueOf(ss.reg).equals("return")){
				if(leaf != null){
					return false;
				}else{
					leaf = ss;
				}
			}
		}
		if(leaf!=null){
			if(leaf.unit.getUseBoxes().size() == 1){
				if(Constant.class.isAssignableFrom(leaf.unit.getUseBoxes().get(0).getValue().getClass())){
					return true;
				}
			}
		}
		
		return false;
	}

	// Broken Fingers
//	private static boolean isNullSliceForAuthenticate(Tree<SlicerState> stree) {
//
//		for(SlicerState ss : stree.getLeaves()){
//			if(stringInList(String.valueOf(ss.reg), Arrays.asList(new String[] {"field", "nullreg"}))){
//				continue;
//			}
//			if(String.valueOf(ss.reg).startsWith("@this")){
//				continue;
//			}
//			if(String.valueOf(ss.reg).equals("return")){
//				if(String.valueOf(ss.unit).contains("android.hardware.fingerprint.FingerprintManager$CryptoObject: void <init>")){
//					continue;
//				}
//			}
//			return false;
//		}
//		return true;
//	}

	/* zx   */  // determine whether the key is created as new every time (change-sensitive)
	public static boolean isNullSliceForAuthenticate(Tree<SlicerState> stree) {

		for(SlicerState ss : stree.getLeaves()){
			if(stringInList(String.valueOf(ss.reg), Arrays.asList(new String[] {"field", "nullreg"}))){
				continue;
			}
			if(String.valueOf(ss.reg).startsWith("@this")){
				continue;
			}
			if(String.valueOf(ss.reg).equals("return")){
				if(String.valueOf(ss.unit).contains("android.hardware.fingerprint.FingerprintManager$CryptoObject: void <init>")){
//					Value vv = getInvokeParameter();

					continue;
				}
			}
			return false;
		}
		return true;
	}
	/* zx   */
	
	//https://www.mkyong.com/java/java-md5-hashing-example/
	public static String computeMD5(String fname){
        MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
        FileInputStream fis = null;
		try {
			fis = new FileInputStream(fname);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}

        byte[] dataBytes = new byte[1024];
        int nread = 0;
        try {
			while ((nread = fis.read(dataBytes)) != -1) {
			  md.update(dataBytes, 0, nread);
			}
		} catch (IOException e) {
			e.printStackTrace();
		};
        byte[] mdbytes = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        StringBuffer hexString = new StringBuffer();
    	for (int i=0;i<mdbytes.length;i++) {
    		String hex=Integer.toHexString(0xff & mdbytes[i]);
   	     	if(hex.length()==1) hexString.append('0');
   	     	hexString.append(hex);
    	}
    	return hexString.toString();
    }	
}
