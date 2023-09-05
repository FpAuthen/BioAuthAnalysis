package fcm;

import fcm.layout.ResourceUtil;
import soot.SootMethod;

import java.util.HashSet;
import java.util.Set;

public class LayoutStrExtractor extends StrExtractor {

    @Override
    public Set<String> extractStr(String activity) {
        Set<String> texts = ResourceUtil.getLayoutTexts(activity);
        return texts;
    }

    @Override
    public Set<String> extractStrFromMethod(SootMethod sootMethod) {
        return new HashSet<>();
    }
}
