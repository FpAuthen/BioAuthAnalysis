package comm;

//import org.apache.log4j.Logger;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
import soot.*;
import soot.options.Options;

public class SootConfig {
//    private static Logger logger = LogManager.getLogger(SootConfig.class);

    public static void init() {
        init(Config.appPath);
    }

    public static void init(String appPath) {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        java.nio.file.Path p = java.nio.file.Paths.get(appPath);
        String filename = p.getFileName().toString();
        Options.v().set_full_resolver(true);
        Options.v().set_drop_bodies_after_load(false);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().ignore_resolution_errors();
        Options.v().set_no_writeout_body_releasing(true);
        Options.v().set_output_dir("./output/FpAnalysis/" + filename + "/");
        Options.v().set_output_format(Options.output_format_none);
//        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_whole_program(true);
        Options.v().set_process_multiple_dex(true);

//        Options.v().set_include(Common.includeList);    //z
        Options.v().set_exclude(Common.excludeList);


//        Options.v().set_oaat(false);     // false --> PackManager.v().writeOutput();  (下面Mian.main中设置)

        String[] sootArgs = new String[]{
                "-pp",
                "-android-jars", Config.androidPlatformPath,
                //projectConfig.apkBaseDir + "android_sdk/platforms"
                "-process-dir", appPath
        };
        Main.main(sootArgs);
    }
}
