package Analysis;

import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.util.SystemClassHandler;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

public class LauncherStatistics {
    public static String getActivityName(AXmlNode node) {
        AXmlAttribute<?> attr = node.getAttribute("name");
        String className = (String) attr.getValue();
        return className;
    }


    public static void main(String[] args) throws XmlPullParserException, IOException {
        // 指定包含字符串的txt文件路径
        String txtFilePath = "/home/zzz/BioAuth/weak_config/my_sootAnalysis/hw_BioAPI.txt"; // 替换为你的txt文件路径
        // 指定固定的文件夹路径
        String folderPath = "/mnt/iscsi/zzz/huawei_202210"; // 替换为你的文件夹路径
        File csvFile = new File("/home/zzz/BioAuth/FpAnalysis/launcher.csv");
        //第二步：通过BufferedReader类创建一个使用默认大小输出缓冲区的缓冲字符输出流
        BufferedWriter writeText = new BufferedWriter(new FileWriter(csvFile));
        Integer failcnt = 0;
        Integer cnt = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(txtFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if(line.equals("com.csii.sns.ui"))  continue;
                String apkpath = folderPath + File.separator + line + ".apk";
                String pkgname;
                String className;
                String isStart;
                Set<AXmlNode> launchableActivities;
                System.out.println(cnt);
                cnt += 1;
                System.out.println(apkpath);
                try {
                    ProcessManifest processMan = new ProcessManifest(apkpath);
                    pkgname = processMan.getPackageName();
                    className = "";
                    isStart = "0";
                    launchableActivities = processMan.getLaunchableActivities();

                    Set<String> launchableStr = new HashSet<>();
                    for (AXmlNode node : launchableActivities) {
                        className = getActivityName(node);
                        launchableStr.add(className);
                        if (className.startsWith(pkgname)) isStart = "1";
                    }
                    //调用write的方法将字符串写到流中
                    writeText.write(pkgname + "," + launchableStr.toString() + "," + isStart);
                    writeText.newLine();    //换行
                } catch (Exception e) {
                    System.out.println("[*] Exception: " + e.toString());
                    failcnt += 1;
                }
            }
            //使用缓冲区的刷新方法将数据刷到目的地中
            writeText.flush();
            //关闭缓冲区，缓冲区没有调用系统底层资源，真正调用底层资源的是FileWriter对象，缓冲区仅仅是一个提高效率的作用
            //因此，此处的close()方法关闭的是被缓存的流对象
            writeText.close();
            System.out.println("失败数量：" + failcnt.toString());
        } catch (IOException e) {
            System.err.println("Error reading or processing file: " + e.getMessage());
        }
    }
}
