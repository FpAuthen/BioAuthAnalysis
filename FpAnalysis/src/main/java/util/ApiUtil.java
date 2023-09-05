package util;

import com.alibaba.fastjson.JSONObject;
import soot.*;
import soot.jimple.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ApiUtil {
    /*private static JSONObject apiInfo = FileUtil.getJsonObjectFromFile("/apiInfo.json");

    public static List<String> getTargetMethods() {
        List<String> res = new ArrayList<>();
        for (String api : apiInfo.keySet()) {
            String classname = api.split(";")[0];
            if (classname.startsWith("L")) {
                classname = classname.substring(1).replace("/", ".");
            }
            if (!Scene.v().containsClass(classname))
                continue;
            SootClass sootClass = Scene.v().getSootClass(classname);
            String methodName = api.split(";")[1];
            if (sootClass.declaresMethodByName(methodName)) {
                for (SootMethod method : sootClass.getMethods()) {
                    if (method.getName().equals(methodName)) {
                        res.add(method.getSignature());
                    }
                }
            } else {
                // 如果class中没有该方法名，可能是由于混淆造成的，那么检查feature，即参数信息是否一致
                JSONObject featureInfo = apiInfo.getJSONObject(api);
                for (String feature : featureInfo.keySet()) {
                    if (!featureInfo.getBoolean(feature))
                        continue;
                    for (SootMethod sootMethod : sootClass.getMethods()) {
                        if (checkAPIFeature(sootMethod, feature))
                            res.add(sootMethod.getSignature());
                    }
                }
            }
        }
        return res;
    }*/

    public static boolean checkAPIFeature(SootMethod sootMethod, String feature) {
        String returnType = feature.split("\\|")[0];
        if (returnType.length() != 1 || returnType.equals("V")) {
            returnType = returnType.equals("V") ? "void" : returnType.contains("/") ? returnType.substring(1, returnType.length() - 1).replace("/", ".") : returnType;
        }
        if (!sootMethod.getReturnType().toString().equals(returnType) && returnType.length() != 1)
            return false;
        String paraListStr = feature.split("\\|")[1];
        String[] pareList = paraListStr.substring(1, paraListStr.length() - 1).split(",");
        List<Type> types = sootMethod.getParameterTypes();
        if (pareList.length != types.size())
            return false;
        for (int i = 0; i < pareList.length; i++) {
            if (pareList[i].trim().length() == 1)
                continue;

            String expectedType = pareList[i].trim().substring(1).replace("/", ".").replace(";", "");
            if (!expectedType.trim().equals(types.get(i).toString().trim()))
                return false;
        }
        return true;
    }

    public static Set<ReturnStmt> getReturnStmt(SootMethod sootMethod) {
        Set<ReturnStmt> result = new HashSet<>();
        if (sootMethod == null || !sootMethod.hasActiveBody()) {
            return result;
        }
        for (Unit unit : sootMethod.getActiveBody().getUnits()) {
            if (unit instanceof ReturnStmt) {
                ReturnStmt r = (ReturnStmt) unit;
                result.add(r);
            }
        }
        return result;
    }

    public static Value getTargetValueOfArg(Unit unit, int argIndex) {
        if (unit == null)
            return null;
        Stmt stmt = (Stmt) unit;
        if (stmt.containsInvokeExpr()) {
            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            if (invokeExpr.getArgCount() > argIndex) {
                return invokeExpr.getArg(argIndex);
            }
        }
        return null;
    }

    public static Value getBaseBox(InvokeExpr invokeExpr) {
        Value res = null;
        if (invokeExpr instanceof VirtualInvokeExpr)
            res = ((VirtualInvokeExpr) invokeExpr).getBaseBox().getValue();
        else if (invokeExpr instanceof SpecialInvokeExpr)
            res = ((SpecialInvokeExpr) invokeExpr).getBaseBox().getValue();
        else if (invokeExpr instanceof InterfaceInvokeExpr)
            res = ((InterfaceInvokeExpr) invokeExpr).getBaseBox().getValue();
        return res;
    }

    public static boolean isAndroidOrJavaClass(SootClass sootClass) {
        return (sootClass.getPackageName().startsWith("java.") || sootClass.getPackageName().startsWith("android.")
                || sootClass.getPackageName().startsWith("androidx.") || sootClass.getPackageName().startsWith("javax."))
                && !sootClass.getName().toLowerCase().contains("fingerprint") && !sootClass.getName().toLowerCase().contains("biometric");
    }

    public static boolean isGmsClass(SootClass sootClass) {
        return sootClass.toString().startsWith("com.google.firebase") || sootClass.toString().startsWith("com.google.android.gms");
    }
}
