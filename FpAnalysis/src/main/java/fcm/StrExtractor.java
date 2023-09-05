package fcm;

import soot.SootMethod;

import java.util.Set;

public abstract class StrExtractor {
    public abstract Set<String> extractStr(String activity);
    public abstract Set<String> extractStrFromMethod(SootMethod sootMethod);
}
