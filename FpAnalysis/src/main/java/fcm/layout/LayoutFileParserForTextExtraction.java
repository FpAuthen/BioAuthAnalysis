package fcm.layout;


import fcm.layout.LayoutTextTreeNode.ViewText;
import fcm.layout.LayoutTextTreeNode.ViewTextType;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import pxb.android.axml.AxmlVisitor;
import soot.SootClass;
import soot.*;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlHandler;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.axml.parsers.AXML20Parser;
import soot.jimple.infoflow.android.resources.ARSCFileParser;
import soot.jimple.infoflow.android.resources.ARSCFileParser.AbstractResource;
import soot.jimple.infoflow.android.resources.ARSCFileParser.ResConfig;
import soot.jimple.infoflow.android.resources.ARSCFileParser.ResType;
import soot.jimple.infoflow.android.resources.ARSCFileParser.StringResource;
import soot.jimple.infoflow.android.resources.AbstractResourceParser;
import soot.jimple.infoflow.android.resources.IResourceHandler;
import soot.jimple.infoflow.util.SootMethodRepresentationParser;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for analyzing the layout XML files inside an android application
 */
public class LayoutFileParserForTextExtraction extends AbstractResourceParser {

	private static final boolean DEBUG = false;
	
	//id -> [text1,text2, ...]
	private final Map<Integer, List<String>> id2Texts = new HashMap<Integer, List<String>>();
	private final Map<Integer, String> id2Type = new HashMap<Integer, String>();
	private final Map<Integer, LayoutTextTreeNode> id2Node = new HashMap<Integer, LayoutTextTreeNode>();
	//filename -> LayoutTextTree
	private final Map<String, LayoutTextTreeNode> textTreeMap = new HashMap<String, LayoutTextTreeNode>();
	private final Map<String, Set<Integer>> xmlEventHandler2ViewIds = new HashMap<String, Set<Integer>>();
	private final Map<String, Integer> decompiledValuesNameIDMap = new HashMap<String, Integer>();

	public final Map<String, Set<Integer>> layoutClasses =
			new HashMap<String, Set<Integer>>();

	public Map<String, Integer> getDecompiledValuesNameIDMap() {
		return decompiledValuesNameIDMap;
	}

	private final String packageName;
	private final ARSCFileParser resParser;
	private final Pattern eventPattern;
	private  String apkToolPath;
	private  String tmpDirPath;

	public LayoutFileParserForTextExtraction(String packageName, ARSCFileParser resParser, String apkToolPath, String tmppath) {
		this.packageName = packageName;
		this.resParser = resParser;
		this.eventPattern = Pattern.compile("^on[A-Z]\\w+$");
		this.apkToolPath = apkToolPath;
		this.tmpDirPath = tmppath;
		
	}

    public LayoutFileParserForTextExtraction(String packageName,ARSCFileParser resParser) {
        this.packageName = packageName;
        this.resParser = resParser;
        this.eventPattern = Pattern.compile("^on[A-Z]\\w+$");
    }

	/**
	 * Checks whether this invocation calls Android's Activity.setContentView
	 * method
	 * @param inv The invocaton to check
	 * @return True if this invocation calls setContentView, otherwise false
	 */
	protected boolean invokesSetContentView(InvokeExpr inv) {
		String methodName = SootMethodRepresentationParser.v().getMethodNameFromSubSignature(
				inv.getMethodRef().getSubSignature().getString());
        //System.out.println("mk "+methodName);
		if (!methodName.equals("setContentView")&&!methodName.equals("inflate"))
			return false;

		// In some cases, the bytecode points the invocation to the current
		// class even though it does not implement setContentView, instead
		// of using the superclass signature
		SootClass curClass = inv.getMethod().getDeclaringClass();
        //System.out.println("jkl "+curClass);
		while (curClass != null) {
			if (curClass.getName().startsWith("android.app")
                    ||curClass.getName().equals("androidx.appcompat.app.l")
					|| curClass.getName().startsWith("android.support.v7.app")
                    ||curClass.getName().equals("android.view.LayoutInflater"))
				return true;
			if (curClass.declaresMethod("void setContentView(int)"))
				return false;
			curClass = curClass.hasSuperclass() ? curClass.getSuperclass() : null;
		}
		return false;
	}

	/**
	 * Finds the mappings between classes and their respective layout files
	 */
	public void findClassLayoutMappings() {
		for (SootClass sc : Scene.v().getApplicationClasses()) {
			if (sc.isConcrete()) {
				for (SootMethod sm : sc.getMethods()) {
					if (!sm.isConcrete())
						continue;

					for (Unit u : sm.retrieveActiveBody().getUnits()) {
						if (u instanceof Stmt) {
							Stmt stmt = (Stmt) u;
							if (stmt.containsInvokeExpr()) {
								InvokeExpr inv = stmt.getInvokeExpr();
								if (invokesSetContentView(inv)) {
									for (Value val : inv.getArgs())
										if (val instanceof IntConstant) {
											IntConstant constVal = (IntConstant) val;
											Set<Integer> layoutIDs = this.layoutClasses.get(sm.getDeclaringClass().getName());
											if (layoutIDs == null) {
												layoutIDs = new HashSet<Integer>();
												this.layoutClasses.put(sm.getDeclaringClass().getName(), layoutIDs);
                                               // System.out.println("kkk: "+sm.getDeclaringClass().getName()+" "+layoutIDs);
											}
											layoutIDs.add(constVal.value);
										}
								}
							}
						}
					}
				}
			}
		}
	}


	private boolean isRealClass(SootClass sc) {
		if (sc == null)
			return false;
		return !(sc.isPhantom() && sc.getMethodCount() == 0 && sc.getFieldCount() == 0);
	}
	
	private SootClass getLayoutClass(String className) {
		// Cut off some junk returned by the parser
		if (className.startsWith(";"))
			className = className.substring(1);
		
		if (className.contains("(") || className.contains("<") || className.contains("/")) {
			System.err.println("Invalid class name " + className);
			return null;
		}
		
		
		SootClass sc = Scene.v().forceResolve(className, SootClass.BODIES);
		if ((sc == null || sc.isPhantom()) && !packageName.isEmpty())
			sc = Scene.v().forceResolve(packageName + "." + className, SootClass.BODIES);
		if (!isRealClass(sc))
			sc = Scene.v().forceResolve("android.view." + className, SootClass.BODIES);
		if (!isRealClass(sc))
			sc = Scene.v().forceResolve("android.widget." + className, SootClass.BODIES);
		if (!isRealClass(sc))
			sc = Scene.v().forceResolve("android.webkit." + className, SootClass.BODIES);
        if (!isRealClass(sc))
            sc = Scene.v().forceResolve(className, SootClass.BODIES);
		if (!isRealClass(sc)) {
   			logger.debug("Could not find layout class " + className);
   			return null;
		}
		
		return sc;		
	}
	
	private boolean isLayoutClass(SootClass theClass) {
		if (theClass == null)
			return false;
		
   		// To make sure that nothing all wonky is going on here, we
   		// check the hierarchy to find the android view class
   		boolean found = false;
   		for (SootClass parent : Scene.v().getActiveHierarchy().getSuperclassesOf(theClass))
   			if (parent.getName().equals("android.view.ViewGroup")) {
   				found = true;
   				break;
   			}
   		return found;
	}
	
	private boolean isViewClass(SootClass theClass) {
		if (theClass == null)
			return false;
		
		// To make sure that nothing all wonky is going on here, we
   		// check the hierarchy to find the android view class
   		boolean found = false;
   		for (SootClass parent : Scene.v().getActiveHierarchy().getSuperclassesOfIncluding(theClass))
   			if (parent.getName().equals("android.view.View")
   					|| parent.getName().equals("android.webkit.WebView")) {
   				found = true;
   				break;
   			}
   		if (!found) {
   			System.err.println("Layout class " + theClass.getName() + " is not derived from "
   					+ "android.view.View");
   			return false;
   		}
   		return true;
	}
	
	/**
	 * Checks whether the given namespace belongs to the Android operating system
	 * @param ns The namespace to check
	 * @return True if the namespace belongs to Android, otherwise false
	 */
	private boolean isAndroidNamespace(String ns) {
		if (ns == null)
			return false;
		ns = ns.trim();
		if (ns.startsWith("*"))
			ns = ns.substring(1);
		if (!ns.equals("http://schemas.android.com/apk/res/android"))
			return false;
		return true;
	}

	/**XIANG
	 * Parses all layout XML files in the given APK file and extract the text attributes.
	 */
	public void parseLayoutFileForTextExtraction(final String fileName) {
		handleAndroidResourceFiles(fileName, /*classes,*/ null, new IResourceHandler() {
				
			@Override
			public void handleResourceFile(final String fileName, Set<String> fileNameFilter, InputStream stream) {
				// We only process valid layout XML files
				if (!fileName.startsWith("res/layout"))
					return;
				if (!fileName.endsWith(".xml")) {
					System.err.println("Skipping file " + fileName + " in layout folder...");
					return;
				}
				
				// Get the fully-qualified class name
				String entryClass = fileName.substring(0, fileName.lastIndexOf("."));
				
				// We are dealing with resource files
				if (!fileName.startsWith("res/layout/"))
					return;
				entryClass = entryClass.substring(entryClass.lastIndexOf('/')+1);
				if (fileNameFilter != null) {
					boolean found = false;
					for (String s : fileNameFilter)
						if (s.equalsIgnoreCase(entryClass)) {
							found = true;
							break;
						}
					if (!found)
						return;
				}
				
				try {
					AXmlHandler handler = new AXmlHandler(stream, new AXML20Parser());
					//System.err.println("DEBUG parseLayoutFileForTextExtraction: parsing "+entryClass);
					
					LayoutTextTreeNode textTreeNode = new LayoutTextTreeNode("", null);
					textTreeMap.put(entryClass, textTreeNode);
					parseLayoutNode(entryClass, handler.getDocument().getRootNode(), textTreeNode, textTreeNode);
					
					updateNodeAllTextsAndId2XX(entryClass);
					updateNodeViewTextField(entryClass);
				}
				catch (Exception ex) {
					System.err.println("Could not read binary XML file: " + ex.getMessage());
					ex.printStackTrace();
				}
			}
		});
	}

	public void extractNameIDPairsFromCompiledValueResources(String filename){
		File apkF = new File(filename);
		if (!apkF.exists())
			throw new RuntimeException("file '" + filename + "' does not exist!");

		try {
			String fname = filename.toLowerCase();
			if(fname.contains(File.separator)){
				int idx = fname.lastIndexOf(File.separator);
				fname = fname.substring(idx+1, fname.length());
			}
			if(fname.endsWith(".apk"))
				fname = fname.substring(0, fname.length()-4);
			String path = tmpDirPath+fname;
			String cmd = "java -jar "+apkToolPath+" d "+filename +" -o "+path;
			System.out.println("Execute cmd: "+cmd);
			Process p = Runtime.getRuntime().exec(cmd);
		    p.waitFor(); 
		    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
		    String line = "";
		    while((line = reader.readLine()) != null)
		    	System.out.print("Decompiling APK: "+line + "\n");

		    path = path + "/res/values/";
		    File f = new File(path);
		    if(!f.isDirectory()){
		    	System.err.println("Error compiling: value folder doesn't exist");
		    	return ;
		    }
		    
		    SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();
			DefaultHandler handler = getValueResouceHandler();
		    for(String xmlFile : f.list()){
		    	xmlFile = f.getAbsolutePath()+"/"+xmlFile;
		    	if(!xmlFile.toLowerCase().endsWith(".xml"))
		    		continue;
		    	InputStream is = new FileInputStream(xmlFile);
		    	System.out.println("analyzing file "+xmlFile);
		    	try{
		    		saxParser.parse(is, handler);
		    	}
		    	catch(Exception e){
		    		System.out.println("Error analyzing file."+e.toString());
		    	}
		    }

		}
		catch (Exception e) {
			System.err.println("Error extractNameIDPairsFromCompiledValueResources in apk "
					+ filename + ": " + e);
			e.printStackTrace();
			if (e instanceof RuntimeException)
				throw (RuntimeException) e;
			else
				throw new RuntimeException(e);
		}
	}
	
	private DefaultHandler getValueResouceHandler(){
		DefaultHandler handler = new DefaultHandler() {
			public void startElement(String uri, String localName,String qName,
		                Attributes attributes) throws SAXException {
				String name = attributes.getValue("name");
				String id = attributes.getValue("id");
				if(name!=null && id!=null){
					try{
						name = name.trim();
						Integer idInt = null;
						if(id.toLowerCase().startsWith("0x")){
							Long tt = Long.parseLong(id.substring(2, id.length()), 16);
							idInt = tt.intValue();
						}
						else
							idInt = Integer.valueOf(id);
						
						decompiledValuesNameIDMap.put(name, idInt);
					}
					catch(Exception e){
						System.err.println("Error in converting integer: "+name+" "+id+" "+e.toString());
					}
				}
				//System.out.println("Start Element :" + qName+" N:"+name+" ID:"+id);
			}

			public void endElement(String uri, String localName,
				String qName) throws SAXException {

			}

			public void characters(char ch[], int start, int length) throws SAXException {

			}
		};
		   return handler;
	}
	
	/**
	 * Parses the layout file with the given root node
	 * @param layoutFile The full path and file name of the file being parsed
	 * @param rootNode The root node from where to start parsing
	 */
	private void parseLayoutNode(String layoutFile, AXmlNode rootNode, LayoutTextTreeNode textTreeNode, LayoutTextTreeNode root) {
		if (rootNode.getTag() == null || rootNode.getTag().isEmpty()) {
			System.err.println("Encountered a null or empty node name "
					+ "in file " + layoutFile + ", skipping node...");
			return;
		}
		//System.err.println("DEBUG: parseLayoutNode: "+rootNode.toString());
		String tname = rootNode.getTag().trim();
		textTreeNode.nodeType = tname;
		
		if (tname.equals("dummy")) {
			// dummy root node, ignore it
		}
		// Check for inclusions
		else if (tname.equals("include")) {
			parseIncludeAttributes(layoutFile, rootNode);
		}
		// The "merge" tag merges the next hierarchy level into the current
		// one for flattening hierarchies.
		else if (tname.equals("merge"))  {
			// do not consider any attributes of this elements, just
			// continue with the children
		}
		else if (tname.equals("fragment"))  {
			final AXmlAttribute<?> attr = rootNode.getAttribute("name");
			if (attr == null)
				System.err.println("Fragment without class name detected");
			else {
				if (attr.getType() != AxmlVisitor.TYPE_STRING)
					System.err.println("Invalid targer resource "+attr.getValue()+"for fragment class value");
//				getLayoutClass(attr.getValue().toString());
			}
		}
		else {
//			final SootClass childClass = getLayoutClass(tname);
//			if ((isLayoutClass(childClass) || isViewClass(childClass))){
//				parseLayoutAttributes(layoutFile, childClass, rootNode, textTreeNode, root);
			parseLayoutAttributes(layoutFile, null, rootNode, textTreeNode, root);
//		}
		}

		// Parse the child nodes
		for (AXmlNode childNode : rootNode.getChildren()){
			LayoutTextTreeNode childTextTreeNode = new LayoutTextTreeNode("null", textTreeNode);
			textTreeNode.addChildNode(childTextTreeNode);
			parseLayoutNode(layoutFile, childNode, childTextTreeNode, root);
		}
	}
	
	/**
	 * Parses the attributes required for a layout file inclusion
	 * @param layoutFile The full path and file name of the file being parsed
	 * @param rootNode The AXml node containing the attributes
	 */
	private void parseIncludeAttributes(String layoutFile, AXmlNode rootNode) {
		for (Entry<String, AXmlAttribute<?>> entry : rootNode.getAttributes().entrySet()) {
			String attrName = entry.getKey().trim();
			AXmlAttribute<?> attr = entry.getValue();
			
    		if (attrName.equals("layout")) {
    			if ((attr.getType() == AxmlVisitor.TYPE_REFERENCE || attr.getType() == AxmlVisitor.TYPE_INT_HEX)
    					&& attr.getValue() instanceof Integer) {
    				// We need to get the target XML file from the binary manifest
    				AbstractResource targetRes = resParser.findResource((Integer) attr.getValue());
    				if (targetRes == null) {
    					System.err.println("Target resource " + attr.getValue() + " for layout include not found");
    					return;
    				}
    				if (!(targetRes instanceof StringResource)) {
    					System.err.println("Invalid target node for include tag in layout XML, was "
    							+ targetRes.getClass().getName());
    					return;
    				}
    				String targetFile = ((StringResource) targetRes).getValue();
    				
    				// If we have already processed the target file, we can
    				// simply copy the callbacks we have found there
        			
    			}
    		}
		}
	}

	/**
	 * Parses the layout attributes in the given AXml node 
	 * @param layoutFile The full path and file name of the file being parsed
	 * @param layoutClass The class for the attributes are parsed
	 * @param rootNode The AXml node containing the attributes
	 */
	private void parseLayoutAttributes(String layoutFile, SootClass layoutClass, AXmlNode rootNode,
			LayoutTextTreeNode textTreeNode, LayoutTextTreeNode root) {
		int id = -1;
		for (Entry<String, AXmlAttribute<?>> entry : rootNode.getAttributes().entrySet()) {
			if (entry.getKey() == null)
				continue;
			
			String attrName = entry.getKey().trim();
			AXmlAttribute<?> attr = entry.getValue();

			if (attrName.isEmpty())
				continue;
			// Check that we're actually working on an android attribute
			if (!isAndroidNamespace(attr.getNamespace()))
				continue;
			
			// Read out the field data
			if (attrName.equals("id")
					&& (attr.getType() == AxmlVisitor.TYPE_REFERENCE || attr.getType() == AxmlVisitor.TYPE_INT_HEX)){
				id = (Integer) attr.getValue();
				String name = getResourceNameBaseOnId(id);
				textTreeNode.nodeID = id;
				textTreeNode.name = name;
			}
			else if(attrName.startsWith("on")){ //add event listener
				Matcher m = eventPattern.matcher(attrName);
				if(m.matches() && rootNode.getAttribute("id")!=null && rootNode.getAttribute("id").getValue()!=null && attr.getValue()!=null){
					
					try{
						String clsName = (String)attr.getValue();
						Integer nodeID = Integer.valueOf(rootNode.getAttribute("id").getValue().toString());

						if(xmlEventHandler2ViewIds.containsKey(clsName))
							xmlEventHandler2ViewIds.get(clsName).add(nodeID);
						else{
							Set<Integer> tmp = new HashSet<Integer>();
							tmp.add(nodeID);
							xmlEventHandler2ViewIds.put(clsName, tmp);
						}
						//System.out.println("ALERTALERT: onClick:"+clsName+" -> "+nodeID);
					}
					catch(Exception e){
						System.err.println("NULIST: error "+e.toString());
					}
				}
				//listenerCls2Ids
			}
			else if(attrName.equals("name")){
				System.out.println("NAME:"+attr.getValue().toString());
			}
			else if (attr.getType() == AxmlVisitor.TYPE_STRING && attrName.matches("^text|hint|textOn|textOff$")) {
				// To avoid unrecognized attribute for "text" field
				textTreeNode.texts.add(attr.getValue().toString().trim());
			}
			else if (DEBUG && attr.getType() == AxmlVisitor.TYPE_STRING) {
				System.out.println("Found unrecognized XML attribute:  " + attrName);
			}
			else if(attr.getType()==AxmlVisitor.TYPE_INT_HEX && attrName.matches("^text|hint|textOn|textOff$")){
				//System.err.println("DEBUG ID TEXT ATTR: "+attr.toString()+" "+ attr.getType()+" "+getTextStringBasedOnID((Integer)attr.getValue()) );
				textTreeNode.texts.addAll(getTextStringBasedOnID((Integer)attr.getValue()));
			}
            else if(attr.getType()==AxmlVisitor.TYPE_INT_HEX && attrName.matches("^src|icon")){
                //System.err.println("DEBUG ID TEXT ATTR: "+attr.toString()+" "+ attr.getType()+" "+getTextStringBasedOnID((Integer)attr.getValue()) );
                textTreeNode.texts.add(getResourceNameBaseOnId((Integer)attr.getValue()));
            }
		}
		
		// Register the new user control
		//addToMapSet(this.userControls, layoutFile, new LayoutControl(id, layoutClass, isSensitive));
	}
	
	private void parseValueAttributes(AXmlNode rootNode) {
		int id = -1;
		String name = "";
		for (Entry<String, AXmlAttribute<?>> entry : rootNode.getAttributes().entrySet()) {
			if (entry.getKey() == null)
				continue;
			
			String attrName = entry.getKey().trim();
			AXmlAttribute<?> attr = entry.getValue();
			//System.err.println("DEBUG parseLayoutAttributes: "+attrName+" "+entry.getValue());
			// On obfuscated Android malware, the attribute name may be empty
			if (attrName.isEmpty())
				continue;
			
			// Check that we're actually working on an android attribute
			if (!isAndroidNamespace(attr.getNamespace()))
				continue;
			
			// Read out the field data
			if (attrName.equals("id")
					&& (attr.getType() == AxmlVisitor.TYPE_REFERENCE || attr.getType() == AxmlVisitor.TYPE_INT_HEX)){
				id = (Integer) attr.getValue();
			}
			else if(attrName.equals("name")){
				name = attr.getValue().toString();
				System.out.println("NAME:"+attr.getValue().toString());
			}
		}
		
		System.out.println("Parse value attributes: "+name+" => "+id);
	}
	
	public Set<String> getTextStringBasedOnID(int id){
	    Set<String> results = new HashSet<>();
		if(id2Node.containsKey(id)){
			LayoutTextTreeNode node = id2Node.get(id);
			results.add(node.name.trim());
			for(String s: node.allTexts){
				results.add(s.trim().replace("\"",""));
			}
		}
		for(ARSCFileParser.ResPackage rp : resParser.getPackages()){
			for (ResType rt : rp.getDeclaredTypes()){
//				if(!rt.getTypeName().equals("string"))
//					continue;
				for (ResConfig rc : rt.getConfigurations())
					for (AbstractResource res : rc.getResources()){
						if(res.getResourceID() == id){
							results.add(res.getResourceName().trim());
							if(res instanceof StringResource)
								results.add(((StringResource)res).getValue().trim().replace("\"",""));
							return results;
						}
					}
				}
		}
		return results;
	}
    public String getResourceNameBaseOnId(int id){
        for(ARSCFileParser.ResPackage rp : resParser.getPackages()){
            for (ResType rt : rp.getDeclaredTypes()){
                for (ResConfig rc : rt.getConfigurations())
                    for (AbstractResource res : rc.getResources()){
                        if(res.getResourceID() == id){
                            return " "+res.getResourceName();
                        }
                    }
            }
        }
        return "";
    }


	/**
	 * Checks whether this name is the name of a well-known Android listener
	 * attribute. This is a function to allow for future extension.
	 * @param name The attribute name to check. This name is guaranteed to
	 * be in the android namespace.
	 * @return True if the given attribute name corresponds to a listener,
	 * otherwise false.
	 */
	private boolean isActionListener(String name) {
		return name.equals("onClick");
	}
	
	
	/** XIANG **/
	public Map<Integer, List<String>> getId2Texts() {
		return id2Texts;
	}
	
	public Map<Integer, String> getId2Type(){
		return id2Type;
	}
	
	public Map<Integer, LayoutTextTreeNode> getId2Node(){
		return id2Node;
	}

	public Map<String, LayoutTextTreeNode> getTextTreeMap() {
		return textTreeMap;
	}
	
	public Map<String, Set<Integer>> getXmlEventHandler2ViewIds() {
		return xmlEventHandler2ViewIds;
	}
	
	private void updateNodeViewTextField(String filename){
		if(!textTreeMap.containsKey(filename)){
			System.err.println("Error: no text tree for file: "+filename);
			return;
		}
		traverseTextTreeToUpdateViewTextField(textTreeMap.get(filename));
	}
	private void traverseTextTreeToUpdateViewTextField(LayoutTextTreeNode node){
		if(!node.texts.isEmpty()){
			//ViewTextType textType, String viewType, String texts
			ViewText viewText = node.new ViewText(ViewTextType.VIEW_TEXT, node.nodeType, node.texts);
			node.textObj = viewText;
		}
		else if(!node.allTexts.isEmpty()){
			ViewText viewText = node.new ViewText(ViewTextType.VIEW_TEXT, node.nodeType, node.allTexts);
			node.textObj = viewText;
		}
		else {
			LayoutTextTreeNode parent = node.parent;
			ViewText viewText = null;
			while(parent != null){
				if(!parent.allTexts.isEmpty()){
					if(parent.parent==null)
						viewText = node.new ViewText(ViewTextType.LAYOUT_TEXT, node.nodeType, parent.allTexts);
					else
						viewText = node.new ViewText(ViewTextType.PARENT_TEXT, node.nodeType, parent.allTexts);
					break;
				}
				parent = parent.parent;
			}
			if(viewText == null)
				viewText = node.new ViewText(ViewTextType.NO_TEXT, node.nodeType, new HashSet<>());
			node.textObj = viewText;
		}
		if(node.children != null)
			for(LayoutTextTreeNode child : node.children)
				traverseTextTreeToUpdateViewTextField(child);
	}
	
	private void updateNodeAllTextsAndId2XX(String filename){
		if(!textTreeMap.containsKey(filename)){
			System.err.println("Error: no text tree for file: "+filename);
			return;
		}
		//System.out.println("DEBUG traverseTextTree: "+filename);
		traverseTextTreeHelper(textTreeMap.get(filename), 0);
	}
	
	private void traverseTextTreeHelper(LayoutTextTreeNode node, int level){
		if(node.nodeID != 0){
			id2Type.put(node.nodeID, node.nodeType);
			id2Node.put(node.nodeID, node);
		}
		
		List<String> texts = new ArrayList<>();
	
		if(node.nodeID!=0 && !node.texts.isEmpty()){
			if (id2Texts.containsKey(node.nodeID)){
				texts.addAll(id2Texts.get(node.nodeID));
			}
			else{
				texts = new ArrayList<String>(1);
				id2Texts.put(node.nodeID, texts);
			}
			texts.addAll(node.texts);
		}
		String space = new String(new char[level*2]).replace('\0', ' ');
		//System.out.println("DEBUG: "+space+node.toString());
		Set<String> allTexts = node.texts;
		if(node.children != null){
			for(LayoutTextTreeNode child : node.children){
				traverseTextTreeHelper(child, level+1);
				allTexts.addAll(child.allTexts);
			}
		}
		node.allTexts = allTexts;
	}
}