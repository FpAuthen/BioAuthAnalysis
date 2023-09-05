package base;

import soot_analysis.SootAnalysis;
import soot_analysis.Utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

import static soot_analysis.Utils.print;

public class Aapt {

    public static String aaptResult(String fname){
        URL jarLocationUrl = SootAnalysis.class.getProtectionDomain().getCodeSource().getLocation();
        String jarLocation = new File(jarLocationUrl.toString().replace("file:","")).getParent();
        String aaptLocation = new File(jarLocation).toString().concat(File.separator + "aapt" + File.separator +"aapt").toString();		//windows
        String tstr = "";

        try {
//			String [] args = new String[] {aaptLocation, "dump", "badging", fname};
            String [] args = new String[] {"aapt", "dump", "badging", fname};			// linux
            print(Utils.join(" ", args));
            Process exec = Runtime.getRuntime().exec(args);
            BufferedReader stdOut = new BufferedReader(new InputStreamReader(exec.getInputStream()));

            String s = null;
            while ((s = stdOut.readLine()) != null) {
                tstr += s + "\n";
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return tstr;
    }
}
