package scenery;

//import comm.Config;

import comm.UniqueUnit;
import fcm.layout.ResourceUtil;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.toolkits.graph.*;
import util.FileUtil;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import static scenery.UserInputApi.AndroidCallbackSet;
import static scenery.UserInputApi.getCallbackMethodName;
import static soot_analysis.Utils.print;
import static util.ApiUtil.isAndroidOrJavaClass;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Common {
    private static Logger logger = LogManager.getLogger(Common.class);

    // TODO:  maybe to coarse grain
    public static Map<SootMethod, Set<SootMethod>> CallerToCalleeMap = new HashMap<>();   // caller Method -> callee Method
    public static Map<String, Set<String>> CallerToCalleeMap_write = new HashMap<>();   // caller Method -> callee Method
    public static Map<String, Set<String>> CalleeToCallerMap_write = new HashMap<>();
    public static boolean write_map = true;

    public static Map<UniqueUnit, SootMethod> CallerUnitToCalleeMap = new HashMap<>();    // caller Unit   -> callee Method
    public static Map<SootMethod, Set<SootMethod>> CalleeToCallerMap = new HashMap<>();   // callee Method -> caller Method
    public static Map<SootMethod, Set<UniqueUnit>> CalleeToCallerUnitMap = new HashMap<>(); //callee -> caller unit

    public static Map<SootMethod, Set<SootMethod>> onClickToSetOnClickMap = new HashMap<>(); // OnClick -> setOnClickListener
    public static Map<UniqueUnit, SootMethod> onClickUnitToSetOnClickMap = new HashMap<>();

    public static Map<String, Set<String>> actionToReceiverMap = new HashMap<>();
    public static Set<String> androidCallbacks = new HashSet<>();
    // TODO: here we can place global data structure. for example, call graph

    public static void init(boolean write_map_arg) {
        // init the onClickListener mapper
        //new BridgeListener().bridge();
        CallerToCalleeMap.clear();
        CallerUnitToCalleeMap.clear();
        CalleeToCallerMap.clear();
        CalleeToCallerUnitMap.clear();
        onClickToSetOnClickMap.clear();
        actionToReceiverMap.clear();
        androidCallbacks.addAll(FileUtil.readFile("AndroidCallbacks.txt"));

        initActionToReceiverMap();
        // init call graph
        initCallGraph();
        // init lifecycle
        initLifecycle();
        // init setonclicklistener
        initCallback();
        initExtendsAndImplementRelation();

        // 使用 Gson 库将 Map 对象保存到文件，保存调用边map为文件
        write_map = write_map_arg;
        if(write_map) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (FileWriter writer = new FileWriter("CallerToCalleeMap.json")) {
                gson.toJson(CallerToCalleeMap_write, writer);
                System.out.println("Map saved to file successfully.");
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            try (FileWriter writer = new FileWriter("CalleeToCallerMap.json")) {
                gson.toJson(CalleeToCallerMap_write, writer);
                System.out.println("Map saved to file successfully.");
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }

        }
    }

    public static void initActionToReceiverMap() {
        //process manifest to init the actionToReceiverMap
        actionToReceiverMap.putAll(ResourceUtil.getActionToReceiverMap());      //z 隐式intent-filter
        //TODO: 处理动态注册的情况
        try {
            actionToReceiverMap.putAll(getDynamicBroadcastReceiverMap());
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

    public static Map<String, Set<String>> getDynamicBroadcastReceiverMap() throws Exception {
        Map<String, Set<String>> dynamicBroadcastReceiverMap = new HashMap<>();
        for (SootClass sootClass : Scene.v().getClasses()) {
            //if (! sootClass.getName().startsWith("com.bumptech.glide.manager.DefaultConnectivityMonitor")) continue;
            for (SootMethod method : sootClass.getMethods()) {
                if (!method.hasActiveBody()) continue;
                for (Unit unit : method.getActiveBody().getUnits()) {
                    Stmt s = (Stmt) unit;
                    if (s.containsInvokeExpr() && s.getInvokeExpr() instanceof JVirtualInvokeExpr) {
                        JVirtualInvokeExpr invokeExpr = (JVirtualInvokeExpr) s.getInvokeExpr();
                        if (invokeExpr.getMethod().toString().equals("<android.content.Context: android.content.Intent registerReceiver(android.content.BroadcastReceiver,android.content.IntentFilter)>")) {
                            if (invokeExpr.getArgCount() >= 1 && invokeExpr.getArg(0) instanceof FieldRef) {
                                System.out.println(invokeExpr.getArg(0).getType().toString());
                            }
                            // find register method
                            if (invokeExpr.getArgCount() != 2 ||
                                    !(invokeExpr.getArgs().get(0) instanceof JimpleLocal) ||
                                    !(invokeExpr.getArgs().get(1) instanceof JimpleLocal)) continue;

                            JimpleLocal intent = (JimpleLocal) invokeExpr.getArgs().get(1);
                            JimpleLocal broadCastReceiver = (JimpleLocal) invokeExpr.getArgs().get(0);
                            UnitGraph unitGraph = new BriefUnitGraph(method.getActiveBody());
                            String intentFilter = null;

                            // backtrace intent
                            Unit currentUnit = unit;
                            while (!unitGraph.getPredsOf(currentUnit).isEmpty()) {
                                currentUnit = unitGraph.getPredsOf(currentUnit).get(0);
                                Stmt curS = (Stmt) currentUnit;
                                if (curS.containsInvokeExpr()) {
                                    if (curS.getInvokeExpr().getMethodRef().tryResolve() == null)
                                        continue;
                                    SootMethod callee = curS.getInvokeExpr().getMethod();
                                    if (callee.getDeclaringClass().toString().equals("android.content.IntentFilter")
                                            && callee.getName().equals("<init>")
                                            && ((InvokeExpr) curS.getInvokeExpr()).getArgCount() == 1 &&
                                            ((InvokeExpr) curS.getInvokeExpr()).getArgs().get(0) instanceof StringConstant) {

                                        intentFilter = ((InvokeExpr) curS.getInvokeExpr()).getArgs().get(0).toString();
                                        intentFilter = intentFilter.substring(1, intentFilter.length() - 1);
                                        logger.debug("get Intent init " + intentFilter);
                                        break;
                                    }
                                }
                            }
                            if (intentFilter == null) continue;
                            // backtrace broadCastReceiver
                            Unit currentUnit2 = unit;
                            while (!unitGraph.getPredsOf(currentUnit2).isEmpty()) {
                                currentUnit2 = unitGraph.getPredsOf(currentUnit2).get(0);

                                if (currentUnit2 instanceof AssignStmt) {
                                    //logger.debug(curS2);
                                    AssignStmt assignStmt = (AssignStmt) currentUnit2;
                                    if (assignStmt.getDefBoxes().get(0).getValue() == broadCastReceiver) {
                                        if (assignStmt.getUseBoxes().get(0).getValue() instanceof JInstanceFieldRef) {
                                            // ri = r0.fieldRef -> we need to check the initiation of this field
                                            JInstanceFieldRef fieldRef = (JInstanceFieldRef) assignStmt.getUseBoxes().get(0).getValue();
                                            SootClass fieldRefDeclaringClass = fieldRef.getFieldRef().declaringClass();
                                            String fieldRefClassName = fieldRef.getFieldRef().name();
                                            logger.debug("fieldRefDeclaringClass name " + fieldRefDeclaringClass + fieldRefClassName);
                                            logger.debug("backtracking the constructor of fieldRefDeclaringClass");
                                            String receiverClassName = fieldInitTracking(fieldRefDeclaringClass, fieldRef);
                                            if (receiverClassName == null) break;
                                            if (dynamicBroadcastReceiverMap.containsKey(intentFilter)) {
                                                dynamicBroadcastReceiverMap.get(intentFilter).add(receiverClassName);
                                            } else {
                                                Set<String> valueSet = new HashSet<>();
                                                valueSet.add(receiverClassName);
                                                dynamicBroadcastReceiverMap.put(intentFilter, valueSet);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return dynamicBroadcastReceiverMap;
    }

    public static String fieldInitTracking(SootClass sootClass, FieldRef fieldRef) {
        if (sootClass.getName().contains("com.facebook.ads.internal.DisplayAdController")) {
            logger.debug("here");
        }
        SootMethod initMethod = null;
        try {
            initMethod = sootClass.getMethodByNameUnsafe("<init>");
        } catch (Exception e) {
            // TODO: only deal with zero argument constructor
            logger.debug("only deal with zero argument constructor");
            //logger.error(e);
        }
        if (initMethod == null || !initMethod.hasActiveBody()) return null;
        for (Unit unit : initMethod.getActiveBody().getUnits()) {
            // forward searching this.keyField = $tmp
            try {
                Stmt s = (Stmt) unit;
                if (s instanceof AssignStmt) {
                    AssignStmt assignStmt = (AssignStmt) s;
                    if (assignStmt.toString().contains(fieldRef.getField().getName()) &&
                            assignStmt.getDefBoxes().size() > 0 &&
                            ((JInstanceFieldRef) assignStmt.getDefBoxes().get(0).getValue()).getFieldRef().toString().equals(
                                    fieldRef.getField().toString())) {
                        //logger.debug("connectivityReceiver");
                        // hit this.keyField = $tmp, back tracking $tmp
                        if (assignStmt.getRightOp() instanceof JimpleLocal &&
                                assignStmt.getRightOp().getType() instanceof RefType) {
                            RefType tmpType = (RefType) assignStmt.getRightOp().getType();
                            if (!Scene.v().containsClass(tmpType.getClassName()))
                                return null;
                            SootClass receiverClass = Scene.v().getSootClass(tmpType.getClassName());

                            logger.debug("final we get receiver class " + receiverClass.getName());
                            return receiverClass.getName();
                        }
                    }
                }
            } catch (Exception e) {
                logger.debug("fail to cast JimpleLocal to JInstanceFieldRef");
            }
        }
        return null;
    }

    public static void initCallGraph() {
        for (SootClass sootClass : Scene.v().getClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (!method.hasActiveBody()) continue;
                for (Unit unit : method.getActiveBody().getUnits()) {
                    Stmt s = (Stmt) unit;
                    if (s.containsInvokeExpr()) {
                        SootMethod caller = method;
                        SootMethod callee = s.getInvokeExpr().getMethodRef().tryResolve();
                        if (callee == null)
                            continue;
                        // replaced with wrapper
                        addToCallGraph(new UniqueUnit(method, unit), caller, callee);

                        //deal special static class
                        if (callee.isStatic() && !isAndroidOrJavaClass(callee.getDeclaringClass())) {
                            SootClass staticClass = callee.getDeclaringClass();
                            if (staticClass.declaresMethod("void <clinit>()")) {
                                SootMethod curMethod = staticClass.getMethod("void <clinit>()");
                                addToCallGraph(new UniqueUnit(method, unit), caller, curMethod);
                            }
                        }
                        addBroadCastEdges(caller, s.getInvokeExpr());
                    }
                }
            }
        }
    }

    private static void initCallback() {
        boolean test = true;

        for (SootClass sootClass : Scene.v().getClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (!method.hasActiveBody()) continue;
                UnitGraph g = new ExceptionalUnitGraph(method.getActiveBody());
                Orderer<Unit> orderer = new PseudoTopologicalOrderer<>();
                for (Unit u : orderer.newList(g, false)) {
                    Stmt s = (Stmt) u;
                    if (s.containsInvokeExpr()) {
                        if (s.getInvokeExpr().getMethodRef().tryResolve() == null)
                            continue;
                        String calleeSig = s.getInvokeExpr().getMethod().getSubSignature();
                        if (AndroidCallbackSet.contains(calleeSig)) {
                            // z UserInputApi里面的回调，如果是里面的setxxx的话，找参数类对象listnerClass，然后看该类实现的接口是否符合，符合的话添加对应回调的cg边
                            // TEST
//                            if(test)
//                                continue;

//                            if(calleeSig.toLowerCase().contains("finger"))
//                                System.out.println("======== " + calleeSig);

                            SootClass listenerClass = backwardSliceToFindListener(g, u);

//                            if(calleeSig.toLowerCase().contains("finger")) {
//                                if (listenerClass == null)
//                                    System.out.println("======== listenerClass is null");
//                                else
//                                    System.out.println("========listenerclass " + listenerClass.toString());
//                            }

                            if (listenerClass != null) {
                                String callbackMethodSubSig = getCallbackMethodName(listenerClass, calleeSig);
                                if (callbackMethodSubSig == null) {
                                    onClickUnitToSetOnClickMap.put(new UniqueUnit(u, method), null);
//                                    if(calleeSig.toLowerCase().contains("finger"))
//                                        System.out.println("======== callbackMethodSubSig is null");
                                    continue;
                                }
                                SootMethod onClickMethod;
                                try {
                                    onClickMethod = listenerClass.getMethod(callbackMethodSubSig);
//                                    if(calleeSig.toLowerCase().contains("finger"))
//                                        System.out.println("======== onClickMethod: " + String.valueOf(onClickMethod));
                                } catch (Exception e) {
                                    onClickUnitToSetOnClickMap.put(new UniqueUnit(u, method), null);
                                    continue;
                                }
                                if (!onClickMethod.hasActiveBody()) {
                                    onClickUnitToSetOnClickMap.put(new UniqueUnit(u, method), null);
                                    continue;
                                }

                                addToCallGraph(new UniqueUnit(method, u), method, onClickMethod);

                                // collect all the onClick method,can be used to discover important api
                                onClickToSetOnClickMap.putIfAbsent(onClickMethod, new HashSet<>());
                                onClickToSetOnClickMap.get(onClickMethod).add(method);
                                onClickUnitToSetOnClickMap.put(new UniqueUnit(u, method), onClickMethod);
                            } else {
                                onClickUnitToSetOnClickMap.put(new UniqueUnit(u, method), null);
                            }
                        } else {
                            addSpecialCallbackApiCalls(u, method);
                        }
                    }
                }
            }
        }
    }

    public static void initLifecycle() {
        for (SootClass sootClass : Scene.v().getClasses()) {
            if (isAndroidOrJavaClass(sootClass)) continue;
            logger.debug("selfclass : " + sootClass);
            if (sootClass.hasSuperclass()) {
                logger.debug("superclass : " + sootClass.getSuperclass());
                SootClass superClass = sootClass.getSuperclass();
                if (superClass.getName().equals(LifecycleConstant.ACTIVITYCLASS)) {
                    logger.debug("find a activity class, now needs to add lifecycle");
                    // in our scenario, we only needs to deal with  `onCreate -> onStart -> onResume` for now.
                    // (maybe add onRestart in the future)
                    SootClass activityClass = sootClass;

                    SootMethod smOnCreate = activityClass.getMethodUnsafe(LifecycleConstant.ACTIVITY_ONCREATE);
                    SootMethod smOnStart = activityClass.getMethodUnsafe(LifecycleConstant.ACTIVITY_ONSTART);
                    SootMethod smOnResume = activityClass.getMethodUnsafe(LifecycleConstant.ACTIVITY_ONRESUME);

                    // add calledge to callgraph
                    if (smOnCreate != null && smOnStart != null)
                        addToCallGraph(null, smOnCreate, smOnStart);
                    if (smOnStart != null && smOnResume != null)
                        addToCallGraph(null, smOnStart, smOnResume);
                }

                //z 加入fragment生命周期建模
                SootMethod smOnCreateView = sootClass.getMethodUnsafe(LifecycleConstant.FRAGMENT_ONCREATEVIEW);
                SootMethod smfgOnCreate = sootClass.getMethodUnsafe(LifecycleConstant.ACTIVITY_ONCREATE);
                SootMethod smfgOnResume = sootClass.getMethodUnsafe(LifecycleConstant.ACTIVITY_ONRESUME);
                if(smOnCreateView != null && smfgOnCreate != null)
                    addToCallGraph(null, smfgOnCreate, smOnCreateView);
                if(smfgOnCreate != null && smfgOnResume != null)
                    addToCallGraph(null, smfgOnCreate,smfgOnResume);

            }
            for (SootClass ifaces : sootClass.getInterfaces()) {
                logger.debug("interfaces : " + ifaces);
            }
        }
        return;
    }

    public static void addToCallGraph(UniqueUnit srcUniqUnit, SootMethod caller, SootMethod callee) {
//        if(callee.getSignature().contains("zzajx") || caller.getSignature().contains("zzajx")){
//            System.out.println(caller);
//        }
        Set<SootMethod> calleeSet = CallerToCalleeMap.get(caller);
        if (calleeSet == null) {
            calleeSet = new HashSet<>();
            calleeSet.add(callee);
            CallerToCalleeMap.put(caller, calleeSet);
        } else {
            calleeSet.add(callee);
        }

        // write
        if(write_map) {
            Set<String> calleeStrSet = CallerToCalleeMap_write.get(caller.toString());
            if (calleeStrSet == null) {
                calleeStrSet = new HashSet<>();
                calleeStrSet.add(callee.toString());
                CallerToCalleeMap_write.put(caller.toString(), calleeStrSet);
            } else {
                calleeStrSet.add(callee.toString());
            }

            Set<String> callerStrSet = CalleeToCallerMap_write.get(callee.toString());
            if (callerStrSet == null) {
                callerStrSet = new HashSet<>();
                callerStrSet.add(caller.toString());
                CalleeToCallerMap_write.put(callee.toString(), callerStrSet);
            } else {
                callerStrSet.add(caller.toString());
            }
        }

        Set<SootMethod> callerSet = CalleeToCallerMap.get(callee);
        if (callerSet == null) {
            callerSet = new HashSet<>();
            callerSet.add(caller);
            CalleeToCallerMap.put(callee, callerSet);
        } else {
            callerSet.add(caller);
        }

        CallerUnitToCalleeMap.put(srcUniqUnit, callee);

        Set<UniqueUnit> callerUnitSet = CalleeToCallerUnitMap.get(callee);
        if (callerUnitSet == null) {
            callerUnitSet = new HashSet<>();
            callerUnitSet.add(srcUniqUnit);
            CalleeToCallerUnitMap.put(callee, callerUnitSet);
        } else {
            callerUnitSet.add(srcUniqUnit);
        }
    }

    // deal with callback
    private static void addSpecialCallbackApiCalls(Unit unit, SootMethod caller) {
        //z 找到该语句中调用的方法，获取该方法的类对应的接口类，若该接口类是安卓回调类，则找这个接口类中的接口方法，若该方法的类中有该接口方法，则建立caller到该回调方法的调用边
        //z 还会找该类继承的父类，对应父类中如果有该回调方法，则加入cg
        if (!((Stmt) unit).containsInvokeExpr())
            return;
        SootMethod invokedMethod = ((Stmt) unit).getInvokeExpr().getMethod();

        // TEST
//        if(!invokedMethod.toString().equals("<com.baidu.sapi2.SapiJsCallBacks$FingerprintCallback: void <init>()>"))
//            return;

//        if(invokedMethod.toString().toLowerCase().contains("finger"))
//            System.out.println("======== invokedMethod: " + String.valueOf(invokedMethod));
//        if(invokedMethod.toString().toLowerCase().contains("baseactivity$10")) {
//            System.out.println("======== invokedMethod: " + String.valueOf(invokedMethod));
//            SootClass sc = invokedMethod.getDeclaringClass();
//            if(sc.hasSuperclass()) {
//                System.out.println("@@@@@@ hasSuperClass: true");
//                System.out.println("@@@@@@ superclass:" + sc.getSuperclass().toString());
//            }
//            else
//                System.out.println("@@@@@@ hasSuperClass: false");
//        }

        if (invokedMethod.getName().equals("<init>") || invokedMethod.getName().equals("<clinit>")) {
            SootClass callbackClass = invokedMethod.getDeclaringClass();

//            System.out.println("------- callbackclass:" + callbackClass.toString());
//            System.out.println("------- interfaces: "+ callbackClass.getInterfaces().toString());
//            System.out.println("------- superclass: " + String.valueOf(callbackClass.getSuperclass()));
//            System.out.println("******* abstract class:" + getAbstractClass(callbackClass));

            SootMethod callee;
            for (SootClass iface : callbackClass.getInterfaces()) {

//                System.out.println("******** "+iface.toString());

                if (!androidCallbacks.contains(iface.toString().trim())
                        && !iface.toString().startsWith("kotlin.jvm.functions"))
                    continue;

                for (SootMethod ifaceMethod : iface.getMethods()) {
                    if (!callbackClass.declaresMethod(ifaceMethod.getSubSignature()))
                        continue;
                    callee = callbackClass.getMethod(ifaceMethod.getSubSignature());
                    addToCallGraph(new UniqueUnit(caller, unit), caller, callee);
                    onClickToSetOnClickMap.putIfAbsent(callee, new HashSet<>());
                    onClickToSetOnClickMap.get(callee).add(caller);
                }
            }
            if (callbackClass.hasSuperclass() && !callbackClass.getSuperclass().getName().equals("java.lang.Object")) {
                SootClass superClass = callbackClass.getSuperclass();
                if (androidCallbacks.contains(superClass.toString().trim())
                        || superClass.toString().startsWith("kotlin.jvm.functions")) {

//                    System.out.println("******** superClass: "+superClass.toString());

                    for (SootMethod superMethod : superClass.getMethods()) {
                        if (!superMethod.getName().equals("<init>") && callbackClass.declaresMethod(superMethod.getSubSignature())) {

//                            System.out.println("******** superMethod: "+superMethod.toString());

                            SootMethod curCallee = callbackClass.getMethod(superMethod.getSubSignature());
                            if (curCallee.hasActiveBody())
                                addToCallGraph(new UniqueUnit(caller, unit), caller, curCallee);

//                            if(invokedMethod.toString().toLowerCase().contains("finger"))
//                                System.out.println("======== caller, callee: " + String.valueOf(caller) + ",,," + String.valueOf(curCallee));
//                            if(invokedMethod.toString().toLowerCase().contains("baseactivity$10"))
//                                System.out.println("======== caller, callee: " + String.valueOf(caller) + ",,," + String.valueOf(curCallee));

                        }

                    }
                }
            }
        }
        // kotlin.jvm.functions.Function2
        // deal with android CountDownTimer
        if (invokedMethod.getName().equals("start")) {
            SootClass callbackClass = invokedMethod.getDeclaringClass();
            SootMethod callbackMethod;
            SootClass superclass = callbackClass.getSuperclass();
            if (superclass != null && superclass.toString().equals("android.os.CountDownTimer")) {
                try {
                    callbackMethod = callbackClass.getMethodByName("onFinish");
                    addToCallGraph(new UniqueUnit(unit, caller), caller, callbackMethod);
                } catch (Exception e) {
                }
            }
        }
    }

    public static void initExtendsAndImplementRelation() {
        for (SootClass sootClass : Scene.v().getClasses()) {
            if (isAndroidOrJavaClass(sootClass))
                continue;
            if (sootClass.getName().endsWith("Activity")) {
                continue;
            }
            if (sootClass.hasSuperclass() && !isAndroidOrJavaClass(sootClass.getSuperclass())) {
                SootClass superClass = sootClass.getSuperclass();
                for (SootMethod sootMethod : superClass.getMethods()) {
                    try {
                        SootMethod calleeMethod = sootClass.getMethod(sootMethod.getSubSignature());
                        addToCallGraph(null, sootMethod, calleeMethod);
                    } catch (Exception e) {
                        // logger.debug("Not be extended"+sootMethod.getSignature());
                    }
                }
            }

            for (SootClass ifac : sootClass.getInterfaces()) {
                if (isAndroidOrJavaClass(ifac))
                    continue;
                for (SootMethod sootMethod : ifac.getMethods()) {
                    try {
                        SootMethod calleeMethod = sootClass.getMethod(sootMethod.getSubSignature());
                        addToCallGraph(null, sootMethod, calleeMethod);
                    } catch (Exception e) {
                        //logger.debug("Not be implemented:"+sootMethod.getSignature());
                    }
                }
            }
        }
    }

    private static SootClass getAbstractClass(SootClass clazz) {
        while (clazz != null) {
            System.out.println("--> [getAbstractClass]:" + clazz.toString() +"---> isAbastract:"+ String.valueOf(clazz.isAbstract()));
            if (clazz.isAbstract()) {
                return clazz;
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }

    private static void addBroadCastEdges(SootMethod caller, InvokeExpr invokeExpr) {
        SootMethod callee = invokeExpr.getMethod();
        if (callee.getDeclaringClass().toString().equals("android.content.Intent") && callee.getName().matches("^<init>|setAction|setClass$")) {
            for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                ValueBox argBox = invokeExpr.getArgBox(i);
                //implicit intent
                if (argBox.getValue() instanceof StringConstant) {
                    String actionStr = ((StringConstant) argBox.getValue()).value;
                    if (!actionToReceiverMap.containsKey(actionStr))
                        continue;
                    for (String receiverName : actionToReceiverMap.get(actionStr)) {
                        if (!Scene.v().containsClass(receiverName))
                            continue;
                        SootClass receiverClass = Scene.v().getSootClass(receiverName);
                        if (receiverClass.declaresMethod("void onCreate(android.os.Bundle)")) {
                            addToCallGraph(null, caller, receiverClass.getMethod("void onCreate(android.os.Bundle)"));
                        }
                        if (receiverClass.declaresMethod("void onReceive(android.content.Context,android.content.Intent)")) {
                            addToCallGraph(null, caller, receiverClass.getMethod("void onReceive(android.content.Context,android.content.Intent)"));
                        }
                    }
                }
                //explicit intent
                if (argBox.getValue() instanceof ClassConstant) {
                    String activityStr = ((ClassConstant) argBox.getValue()).value;
                    String activityName = activityStr.substring(1, activityStr.length() - 1).replace("/", ".");
                    SootClass activity = Scene.v().getSootClass(activityName);
                    if (activity.declaresMethod("void onCreate(android.os.Bundle)")) {
                        addToCallGraph(null, caller, activity.getMethod("void onCreate(android.os.Bundle)"));
                    }
                }
            }
        }
    }

    public static SootClass backwardSliceToFindListener(UnitGraph g, Unit unit) {
        //z 找该类中，调用setlistener的该语句中的参数类
        Local targetLocal;
        try {
            targetLocal = (Local) ((Stmt) unit).getInvokeExpr().getArgBox(0).getValue();
        } catch (Exception e) {
            return null;
        }

        while (true) {
            List<Unit> pres = g.getPredsOf(unit);
            if (pres.size() == 0) break;
            if (pres.get(0) instanceof JInvokeStmt &&
                    ((JInvokeStmt) pres.get(0)).getInvokeExpr() instanceof JSpecialInvokeExpr) {
                JSpecialInvokeExpr sie = (JSpecialInvokeExpr) ((JInvokeStmt) pres.get(0)).getInvokeExpr();
                Local baseLocal = (Local) sie.getBaseBox().getValue();
                if (baseLocal.getName().equals(targetLocal.getName()) && sie.getMethod().getName().equals("<init>")) {
                    return sie.getMethodRef().getDeclaringClass();
                }
            } else if (pres.get(0) instanceof JAssignStmt && ((JAssignStmt) pres.get(0)).getLeftOp() == targetLocal) {
                JAssignStmt stmt = (JAssignStmt) pres.get(0);
                if (stmt.getRightOp() instanceof Local) {
                    targetLocal = (Local) stmt.getRightOp();
                }
                if (stmt.getRightOp() instanceof JCastExpr) {
                    JCastExpr expr = ((JCastExpr) stmt.getRightOp());
                    Value castValue = expr.getOp();
                    if (castValue instanceof Local) {
                        targetLocal = (Local) castValue;
                    }
                }
                if (stmt.getRightOp() instanceof FieldRef) {
                    return ((FieldRef) stmt.getRightOp()).getFieldRef().declaringClass();
                }
            } else if (pres.get(0) instanceof JCastExpr) {
                JCastExpr expr = (JCastExpr) pres.get(0);
                Value castValue = expr.getOp();
                if (castValue instanceof Local) {
                    targetLocal = (Local) castValue;
                }
            }
            unit = pres.get(0);
        }
        return null;
    }

    public static void main(String[] args) {
        //SootConfig.init(Config.appPath);
        // init all necessary data structure here
        Common.init(false);
    }
}
