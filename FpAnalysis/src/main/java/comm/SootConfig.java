package comm;

//import org.apache.log4j.Logger;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
import soot.*;
import soot.options.Options;

import java.util.Collections;

import static soot_analysis.Utils.print;

public class SootConfig {
//    private static Logger logger = LogManager.getLogger(SootConfig.class);

    public static void init() {
        init(Config.appPath, Config.format);
    }

    public static void init(String appPath, String format) {
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

        Options.v().set_whole_program(true);
        Options.v().set_process_multiple_dex(true);

        Options.v().set_exclude(Common.excludeList);

        //        Options.v().set_oaat(true);     // false --> PackManager.v().writeOutput();  (下面Mian.main中设置)

        if("shimple".equals(format)) {
            Options.v().set_output_format(Options.output_format_none);
//            Options.v().set_output_format(Options.output_format_shimple);   //删除所有指纹检测中使用
            // 删除所有指纹检测中，使用shimple开销太大，降低开销
            Options.v().setPhaseOption("cg", "enabled:false");
            Options.v().setPhaseOption("jb.dae", "enabled:false");
            Options.v().setPhaseOption("jb.uce", "enabled:false");
            Options.v().setPhaseOption("jj.dae", "enabled:false");
            Options.v().setPhaseOption("jj.uce", "enabled:false");

            String[] sootArgs = new String[]{
                    "-pp",
                    "-via-shimple",
                    "-android-jars", Config.androidPlatformPath,
                    //projectConfig.apkBaseDir + "android_sdk/platforms"
                    "-process-dir", appPath
            };
            Main.main(sootArgs);
//            Options.v().set_android_jars(Config.androidPlatformPath);
//            Options.v().set_process_dir(Collections.singletonList(appPath));
//
//            Options.v().set_whole_program(true);
//            Options.v().set_process_multiple_dex(true);
//
//            Scene.v().loadNecessaryClasses();
//            PackManager.v().runPacks();
//            System.gc();
//
//            print("Soot is done!");
        } else if ("jimple".equals(format)) {
//            Options.v().set_output_format(Options.output_format_jimple);
            Options.v().set_output_format(Options.output_format_none);
            String[] sootArgs = new String[]{
                    "-pp",
                    "-android-jars", Config.androidPlatformPath,
                    //projectConfig.apkBaseDir + "android_sdk/platforms"
                    "-process-dir", appPath
            };
            Main.main(sootArgs);
        }
    }
}
