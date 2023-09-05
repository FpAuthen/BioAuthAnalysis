package soot_analysis;

import soot.SootMethod;

import java.util.Collection;
import java.util.LinkedList;

public class BackwardCallgraph {
	
	SootMethod startMethod;
	SootContext SC;
	boolean skipLibraries = false;
	int maxNNodes = 1000;
	
	public BackwardCallgraph(SootContext SC, SootMethod startMethod){
		this.SC = SC;
		this.startMethod = startMethod;
	}	

	public Tree<CallgraphState> run(){
		return run(maxNNodes);
	}
	
	public Tree<CallgraphState> run(int nnodes){
		Tree<CallgraphState> tree = new Tree<CallgraphState>();
		Node<CallgraphState> headNode = new Node<CallgraphState>(0);
		headNode.value = new CallgraphState(startMethod);
		tree.addHead(headNode);
		
        LinkedList<Node<CallgraphState>> queue = new LinkedList<Node<CallgraphState>>();
        queue.add(headNode);
        while (queue.size() > 0 && tree.nodeMap.size() <= nnodes){
            Node<CallgraphState> cn = queue.poll();
                     
            Collection<CodeLocation> callers = new LinkedList<>();
            callers = SC.getCallers(cn.value.method);
            for(CodeLocation cl : callers){
				Node<CallgraphState> nn = tree.addChild(cn, new CallgraphState(cl.smethod, cl.sunit));
				if(nn!=null){
					if(!skipLibraries || (! Utils.isLibraryMethod(nn.value.method))){
						queue.add(nn);
					}
				}
            }
        }
        return tree;
	}
}


