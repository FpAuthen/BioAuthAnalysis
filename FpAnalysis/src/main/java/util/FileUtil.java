package util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileUtil {
    public static List<String> targetApis = null;
    public static List<String> targetClassApis = null;


    public static List<String> loadListFromResourceJson(String fileName) {
        List<String> fileLines = new ArrayList<>();
        String line;
        try {
            InputStream is = FileUtil.class.getResourceAsStream(fileName);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            while ((line = br.readLine()) != null) {
                fileLines.add(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (String lineStr : fileLines) {
            stringBuilder.append(lineStr);
        }

        return (List<String>) JSON.parse(stringBuilder.toString());
    }

    public static void writeFile(String fileName, String data) {
        try {
            File file = new File(fileName);
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(data);
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<String> readFile(String fileName) {
        List<String> fileLines = new ArrayList<>();
        File file = new File(fileName);
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                fileLines.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return fileLines;
    }

    public static JSONObject getJsonObjectFromFile(String jsonFile) {
        List<String> fileLines = new ArrayList<>();
        String line;
        try {
            InputStream is = FileUtil.class.getResourceAsStream(jsonFile);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            while ((line = br.readLine()) != null) {
                fileLines.add(line);
            }
            br.close();
            is.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (String lineStr : fileLines) {
            stringBuilder.append(lineStr);
        }
        return JSONObject.parseObject(stringBuilder.toString());
    }
}
