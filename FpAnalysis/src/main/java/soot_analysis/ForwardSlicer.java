package soot_analysis;

import scenery.Common;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static soot_analysis.Utils.print;

public class ForwardSlicer {
	
	Unit startUnit;
	String startReg;
	SootMethod containerMethod;
	SootContext SC;
	int maxNNodes = 200;
	
	public ForwardSlicer(SootContext SC, Unit startUnit, String startReg, SootMethod containerMethod){
		this.SC = SC;
		this.startUnit = startUnit;
		this.startReg = startReg;
		this.containerMethod = containerMethod;
	}	

	public Tree<SlicerState> run(){
		return run(maxNNodes);
	}
	
	
	public Tree<SlicerState> run(int nnodes){
		Tree<SlicerState> tree = new Tree<SlicerState>();
		Node<SlicerState> headNode = new Node<SlicerState>(0);
		headNode.value = new SlicerState(startReg, startUnit, containerMethod);
		tree.addHead(headNode);
		
        LinkedList<Node<SlicerState>> queue = new LinkedList<Node<SlicerState>>();
        queue.add(headNode);

        while (queue.size() > 0 && tree.nodeMap.size() <= nnodes){
            Node<SlicerState> cn = queue.poll();
            SlicerState sstate_pre = cn.value;
            Collection<Tuple<Unit, SootMethod>> toExploreUnits;
        	toExploreUnits = new LinkedList<>();

            if(sstate_pre.reg.equals("return")){
            	for(CodeLocation cl : SC.getCallers(sstate_pre.containerMethod)){
            		toExploreUnits.add(new Tuple(cl.sunit, cl.smethod));
            	}
            }else{
            	for(Unit newUnit : SC.getUseUnits(sstate_pre.reg, sstate_pre.containerMethod)){
            		toExploreUnits.add(new Tuple(newUnit, sstate_pre.containerMethod));
            	}
            }
            
            for(Tuple<Unit, SootMethod> tstate : toExploreUnits){
				boolean added = false;
				print("--- ForwardSlicer:", String.valueOf(tstate));
            	for(ValueBox vb : unitToBoxes(tstate.x)){
            		String uureg = vb.getValue().toString();
            		print("------- uureg:", uureg);
            		if(! uureg.startsWith("$")){
            			continue;
            		}
            		added = true;
            		Node<SlicerState> nn = tree.addChild(cn, new SlicerState(uureg, tstate.x, tstate.y));
            		if(nn != null){
            			queue.add(nn);
            		}
            	}
            	if(! added){
            		if(tstate.x.getClass().getSimpleName().equals("JReturnStmt")){
                		Node<SlicerState> nn = tree.addChild(cn, new SlicerState("return", tstate.x, tstate.y));
                		if(nn != null){
                			queue.add(nn);
                		}
            		}else{
            			tree.addChild(cn, new SlicerState(null, tstate.x, tstate.y));
            		}
            	}
            }
        }
                
        return tree;
	}


	/*********************** zx **************************/
	// 追踪hasEnrolledFingerprints返回值
	public Tree<SlicerState> run_track(int nnodes) {
		Tree<SlicerState> tree = new Tree<SlicerState>();
		Node<SlicerState> headNode = new Node<SlicerState>(0);
		headNode.value = new SlicerState(startReg, startUnit, containerMethod);
		tree.addHead(headNode);

		LinkedList<Node<SlicerState>> queue = new LinkedList<Node<SlicerState>>();
		queue.add(headNode);

		while (queue.size() > 0 && tree.nodeMap.size() <= nnodes) {
			print("QUEUE ###############", String.valueOf(queue));
			Node<SlicerState> cn = queue.poll();
			SlicerState sstate_pre = cn.value;
			Collection<Tuple<Unit, SootMethod>> toExploreUnits = new LinkedList<>();
			boolean last_return = false;

//			if (sstate_pre.reg.equals("return")) {
			if (sstate_pre.reg.startsWith("return")) {
				last_return = true;
				for (CodeLocation cl : newGetCallers(SC, sstate_pre.containerMethod)) {
					toExploreUnits.add(new Tuple(cl.sunit, cl.smethod));
				}
			} else {
				for (Unit newUnit : SC.getUseUnits(sstate_pre.reg, sstate_pre.containerMethod)) {
					toExploreUnits.add(new Tuple(newUnit, sstate_pre.containerMethod));
//					break;		//TEST
				}
			}

			for (Tuple<Unit, SootMethod> tstate : toExploreUnits) {
				boolean added = false;
				print("--- ForwardSlicer:", String.valueOf(tstate));

				////// zx
				Unit newUnit = tstate.x;
				print("*************** useUnit:", String.valueOf(newUnit));
				Stmt smt = (Stmt) newUnit;

				if (smt instanceof IfStmt) {
					print("**************** type: IfStmt");            // this

					//分析if语句的target后面干了啥
					print("**************** target:", String.valueOf((((IfStmt) smt)).getTarget()));
					Stmt target = ((IfStmt) smt).getTarget();
					Node<SlicerState> nn;
					Node<SlicerState> nnn = null;
					Node<SlicerState> suc_nnn = null;
					if (target instanceof ReturnStmt) {        // 有返回值
						print("------ target type: ReturnStmt");
						// 调用API检查的结果作为返回值一部分，找该方法的caller
						nn = tree.addChild(cn, new SlicerState("return", newUnit, tstate.y));
						if (nn != null) {
							queue.add(nn);
						}
//						queue.add(nn);
					} else if (target instanceof RetStmt) {        //无返回值 void ---未处理检查结果，不安全
						print("------ target type: RetStmt, WEAK");
						nn = tree.addChild(cn, new SlicerState("WEAK", newUnit, tstate.y));
					} else {                                        //要分析的点，根据检查结果判断处理
						print("------ target else:", String.valueOf(target));
						nn = tree.addChild(cn, new SlicerState("if", newUnit, tstate.y));
//						print("------------ TYPE:", String.valueOf(((PhiExpr)((JAssignStmt)target).getRightOp()).getValue(0).getType()));
//						print("------------ TYPE:", String.valueOf(((PhiExpr)((JAssignStmt)target).getRightOp()).getValue(2).getType()));
						// 处理Phi，继续获取后继，直到找到new intent语句
						if (String.valueOf(target).contains("Phi(")) {		//看target后续是否有new intent
							print("============ Phi", String.valueOf(target));
							String intent_res = get_intent_classPara(tstate.y, target);
							if (intent_res != null) {
								if(intent_res.equals("return")) {
									// 调用API检查的结果作为返回值一部分，找该方法的caller
									print("---------------- intent_res: return, ");
									nnn = tree.addChild(nn, new SlicerState("return", newUnit, tstate.y));
								}
								else{
									nnn = tree.addChild(nn, new SlicerState(intent_res, target, tstate.y));
								}
							}
							// 获取当前语句的后继语句列表

//							List<Unit> succs = g.getSuccsOf(target);
//							print("");
//							print(String.valueOf(succs));
//							print("");
//
//							// 遍历后继语句列表，查找是否有满足条件的语句
//							for (Unit succ : succs) {
//								// 判断后继语句是否为new intent语句
//								if (succ instanceof InvokeStmt) {
//									InvokeExpr invokeExpr = ((InvokeStmt) succ).getInvokeExpr();
//									if (invokeExpr instanceof SpecialInvokeExpr) {
//										SootMethodRef methodRef = invokeExpr.getMethodRef();
//										if (methodRef.getSubSignature().equals("<android.content.Intent: void <init>()>")) {
//											// 找到符合条件的语句
//											Value para = invokeExpr.getArgs().get(1);
//											print("============= new intent:", String.valueOf(para));
//											Node<SlicerState> nnn = tree.addChild(cn, new SlicerState("intent:" + para, succ, tstate.y));
//											break;
//										}
//									}
//								}
//							}
						}
					}

					//分析if语句后继（非target分支）干了啥
					print("***************** not target");
					String suc_intent_res = get_intent_classPara(tstate.y, smt);
					if(suc_intent_res != null) {
						if(suc_intent_res.equals("return")) {
							print("---------------- suc_intent_res: return, ");
							// 调用API检查的结果作为返回值一部分，找该方法的caller
							suc_nnn = tree.addChild(nn, new SlicerState("return_suc", smt, tstate.y));		//addChild如果新加入的节点值已存在，则返回null
							print("---------------- suc_nnn: ", String.valueOf(suc_nnn));

//							if (nn != null) {
//								queue.add(nnn);
//							}
						}
						else{
							nnn = tree.addChild(nn, new SlicerState(suc_intent_res, smt, tstate.y));
						}
					}
					print("--------------- nnn: ", String.valueOf(nnn));
					if(nnn != null && nnn.value.reg.equals("return")) {
						print("------------- return: add queue", String.valueOf(nnn));
						queue.add(nnn);
					}
					else if(suc_nnn != null && suc_nnn.value.reg.equals("return_suc")) {
						print("------------- return_suc: add queue", String.valueOf(suc_nnn));
						queue.add(suc_nnn);
					}

				}
				if (smt instanceof RetStmt) {
					print("**************** type: RetStmt, WEAK");
					Node<SlicerState> nn = tree.addChild(cn, new SlicerState("WEAK", newUnit, tstate.y));
				}
				if (smt instanceof ReturnStmt) {
					print("**************** type: ReturnStmt");
					Node<SlicerState> nn = tree.addChild(cn, new SlicerState("return", newUnit, tstate.y));
					if (nn != null) {
						queue.add(nn);
					}
				}
				InvokeExpr inv = SC.getInvokeExpr(newUnit);
				if (inv != null) {  // 调用函数获取返回值语句
					print("**************** type: InvokeExpr");
					if (newUnit.getDefBoxes().size() > 0) {
						Value reg = newUnit.getDefBoxes().get(0).getValue();
						print("**************** reg:", String.valueOf(reg));
						Node<SlicerState> nn = tree.addChild(cn, new SlicerState(String.valueOf(reg), newUnit, tstate.y));
						if (nn != null) {
							queue.add(nn);
						}
					}
					else if(last_return) {	//返回值未被赋值
						print("------ invoke after return: WEAK, ", String.valueOf(newUnit));
						Node<SlicerState> nn = tree.addChild(cn, new SlicerState("WEAK", newUnit, tstate.y));
					}
				}

					////// zx end

//				for(ValueBox vb : unitToBoxes(tstate.x)){
//					String uureg = vb.getValue().toString();
//					print("------- uureg:", uureg);
//					if(! uureg.startsWith("$")){
//						continue;
//					}
//					added = true;
//					Node<SlicerState> nn = tree.addChild(cn, new SlicerState(uureg, tstate.x, tstate.y));
//					if(nn != null){
//						queue.add(nn);
//					}
//				}
//				if(! added){
//					if(tstate.x.getClass().getSimpleName().equals("JReturnStmt")){
//						Node<SlicerState> nn = tree.addChild(cn, new SlicerState("return", tstate.x, tstate.y));
//						if(nn != null){
//							queue.add(nn);
//						}
//					}else{
//						tree.addChild(cn, new SlicerState(null, tstate.x, tstate.y));
//					}
//				}

			}
		}
			return tree;

	}

	// 新改的找caller的方式
	public Collection<CodeLocation> newGetCallers(SootContext SC, SootMethod method) {
		Collection<CodeLocation> res = new LinkedList<>();
		if (!Common.CalleeToCallerMap.containsKey(method) || Common.CalleeToCallerMap.get(method).isEmpty())
			return null;
		Collection<SootMethod> callers_m = Common.CalleeToCallerMap.get(method);
		for(SootMethod tm : callers_m){
			if(tm.hasActiveBody()){
				Body bb = tm.getActiveBody();
				for(Unit uu : bb.getUnits()){
					InvokeExpr ie = SC.getInvokeExpr(uu);
					if(ie != null){
						//at least the subsignature must be the same
						if(ie.getMethod().toString().equals(method.toString())){
							List<SootMethod> targets = SC.getCallees(ie, tm);
							if(targets.contains(method)){
								res.add(new CodeLocation(tm.getDeclaringClass(), tm , uu));
							}
						}
					}
				}
			}
		}
		return res;
	}

	public String get_intent_classPara(SootMethod smethod, Stmt target) {
		// 获取方法的body
		Body body = smethod.retrieveActiveBody();
		UnitGraph g = new BriefUnitGraph(body);

		Stmt currentStmt = target;
		while(currentStmt != null) {
			// 获取当前语句的后继语句列表
			List<Unit> succs = g.getSuccsOf(currentStmt);
			print("");
			print(String.valueOf(succs));
			print("");
			if(succs.isEmpty()) {
				break;
			}

			// 遍历后继语句列表，查找是否有满足条件的语句
//			for (Unit succ : succs) {
			Unit succ = succs.get(0);
				// 判断后继语句是否为new intent语句
				print(String.valueOf(succ.getClass()));
				Stmt stmtsuc = (Stmt) succ;
				if (stmtsuc instanceof InvokeStmt) {
					InvokeExpr invokeExpr = ((InvokeStmt) stmtsuc).getInvokeExpr();

					// 判断是否new intent开启新的activity
					String signature = invokeExpr.getMethod().getSignature();
					print(signature);
					if(signature.contains("android.content.Intent: void <init>")){
						// 找到new intent的语句
						Value para = invokeExpr.getArgs().get(1);
						print("============= new intent:", String.valueOf(para));
						return "intent:" + para;
					}

					// 判断是否调用authenticate函数
					String subSignature = invokeExpr.getMethod().getSubSignature();
					print(subSignature);
					if(subSignature.contains("authenticate")) {
						print("============= authenticate", String.valueOf(stmtsuc));
						return "authenticate:" + String.valueOf(succ);
					}

				}
				else if (stmtsuc instanceof InvokeExpr) {
					print("succ instanceof InvokeExpr");
				}
				// 处理api调用结果后续作为函数返回值返回的情况
				else if(stmtsuc instanceof ReturnStmt) {
					return "return";
				}

				// 更新当前语句为后继语句
				currentStmt = (Stmt) succ;
//			}
		}
		return "";
	}
	
	public Collection<ValueBox> unitToBoxes(Unit uu){
		LinkedList<ValueBox> vblist = new LinkedList<>(uu.getDefBoxes());
		InvokeExpr ie = SC.getInvokeExpr(uu); //add this, to deal with e.g., constructors
		if(ie != null){


			if(ie instanceof InstanceInvokeExpr){
				InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
				ValueBox newBox = iie.getBaseBox();
				if(! (vblist.contains(newBox))){
					vblist.add(iie.getBaseBox());
				}
			}
		}
		return vblist;
	}
}

