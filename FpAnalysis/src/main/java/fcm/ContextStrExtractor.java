package fcm;

import soot.SootMethod;

import java.util.HashSet;
import java.util.Set;

public class ContextStrExtractor extends StrExtractor {
    private static String exceptNameRegex = "^.{0,3}|<init>|<clinit>$";

    public static void main(String[] args) {
        System.out.println("zza".matches(exceptNameRegex));
        System.out.println(new ContextStrExtractor().extractStr("aa.ss.dddf.ff"));
    }

    @Override
    public Set<String> extractStr(String activity) {
        Set<String> results = new HashSet<>();
        String[] splitStrArray = activity.split("\\.");
        String shortName = splitStrArray[splitStrArray.length-1];
        if(!shortName.matches(exceptNameRegex)){
            results.add(shortName);
        }
        return results;
    }

    @Override
    public Set<String> extractStrFromMethod(SootMethod sootMethod) {
        Set<String> results = new HashSet<>();
        if(!sootMethod.getName().matches(exceptNameRegex)){
            results.add(sootMethod.getName());
        }else if(sootMethod.getName().matches("^<init>|<clinit>$")){
            String className = sootMethod.getDeclaringClass().getShortName();
            if(!className.matches(exceptNameRegex)){
                results.add(sootMethod.getDeclaringClass().getShortName());
            }
        }
        return results;
    }
}
