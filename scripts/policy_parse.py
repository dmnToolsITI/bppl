import xml.etree.ElementTree as ET
from collections import defaultdict

#import networkx as nx
from networkx import DiGraph, topological_sort, simple_cycles
import argparse
import sys
import pdb
import json
import sys
import os

name_graph = DiGraph()
num_objects = 0

function_dict = {}
global_dict = {}

data_object_dict = {}

class DataObject():
    def __init__(self, name, imported, obj_type, compute):
        global num_objects
    
        self.id = num_objects
        num_objects += 1 

        self.name = name
        self.imported = True if imported in ('True','true','T','t') else False

        # if imported check for existence in global_dict
        if self.imported:
            if name not in global_dict:
                print(name,'listed as imported but not found in import dict')
                exit(1) 

            self.obj = global_dict[name]
            if isinstance( self.obj, list):
                self.obj_type = 'list'
            if isinstance( self.obj, dict):
                self.obj_type = 'dict'
            
        else:
            self.obj = None
            self.obj_type = obj_type

        self.compute  = compute

def parseFunctionCall(functionStr):
    functionStr = functionStr.strip()
    startPos = functionStr.find('(')

    # all the text to the arguments is the function name
    funcName = functionStr[:startPos]

    # make sure we recognize it. NB one of the things to be loaded from the user side
    if funcName not in function_dict:
        print('function name',funcName,'not recognized')
        exit(1)

    endPos   = functionStr[startPos+1:].find(')')

    # string between ( and ) are the arguments, comma-separated
    argsStr  = functionStr[startPos+1:startPos+endPos+1]
    argList  = argsStr.split(',')
    for idx,arg in enumerate(argList):
        argList[idx] = arg.strip()
    
    rtnList = [funcName]
    rtnList.extend( argList )
    return rtnList

class evaluationArg():
    def __init__(self,arg):

        if arg.find('@') > -1: 
            self.eval_type = 'element'
            arg = arg.replace('@','')
            self.arg_ref = arg
            self.arg_obj = None
        elif arg.find('\'') > -1:
            self.eval_type = 'constant'
            self.arg_ref = arg
            self.arg_obj = arg
        else:
            # argument is either a list or a dictionary
            self.eval_type = 'name'
            self.arg_ref   = arg
            self.arg_obj   = None
       
class PolicyRule():
    def __init__(self, name, quantifier, evaluation):
        self.name = name
        self.quantifier = quantifier
        func_params = parseFunctionCall( evaluation )
        self.evaluate_func = function_dict[ func_params[0] ]
        self.funcArgs = []

        for obj_ref in func_params[1:]:
            self.funcArgs.append( evaluationArg(obj_ref) )

        self.satisfied = None

    # work through all combinations of objects or lists from objectsets 
    def evaluate(self):

        def indexVector(code):
            indexv = []
            wrk_idx = code
            for _,func_arg in enumerate(self.funcArgs):
                if not func_arg.eval_type == 'element':
                    indexv.append(-1) 
                else:
                    data_object = func_arg.arg_obj
                    numObjects = len( data_object )
                    idx = wrk_idx%numObjects
                    indexv.append(idx)
                    wrk_idx = int( wrk_idx/numObjects )

            return indexv
     
        lengths = []
        totalObjects = 1
        failedArgs = [] 

        nameOrder = {}

        for idx, func_arg in enumerate(self.funcArgs):
            if self.funcArgs[idx].eval_type == 'element':
                data_object      = data_object_dict[ func_arg.arg_ref ].obj
                func_arg.arg_obj = data_object                
                totalObjects *= len(data_object) 

                if isinstance(data_object,dict):
                    nameOrder[ idx ] = list( data_object.keys() )
                else:
                    nameOrder[ idx ] = [ num for num in range(0,len(data_object.obj)) ]

            elif self.funcArgs[idx].eval_type == 'name':
                data_object  = data_object_dict[ func_arg.arg_ref ].obj

                func_arg.arg_obj = data_object                

        for code in range(0,totalObjects):
            indexv  = indexVector( code )
            objv    = []
            argName = []
            for pos, idx in enumerate(indexv):

                # these are pushing dictionaries or lists of dictionaries onto a list
                #
                if idx == -1:
                    if self.funcArgs[pos].eval_type in ('name','constant'):
                        objv.append( self.funcArgs[pos].arg_obj)
                        argName.append( self.funcArgs[pos].arg_ref ) 
                else:
                    obj = self.funcArgs[pos].arg_obj[ nameOrder[ pos ][ idx ] ]
                    objv.append( obj )
                    argName.append( '{}[ {} ]'.format( self.funcArgs[pos].arg_ref, nameOrder[pos][idx]  )) 

            argName = ','.join(argName)

            # objv is now argument vector for evaulation i
            #
            passed = self.evaluate_func( objv )

            # quantifier exists|not_exists|for_all|not_forall
            #
            if passed and self.quantifier == 'not_forall':
                self.satisfied = True
                return True,''

            if not passed and self.quantifier == 'for_all':
                self.satisfied = False
                failedArgs.append( argName )

            if passed and self.quantifier == 'not_exists':
                self.satisfied = False
                failedArgs.append( argName )

            if passed and self.quantifier == 'exists':
                self.satisfied = True
                return True,''

        # remaining cases
        #  not_exists: shortcircuit any True return --> reaching here means all returns are False so quantification is True
        #  for_all: shortcircuit any False return --> reaching here means all returns are True so quanitification is True
        #
        if len(failedArgs) == 0 and self.quantifier in ('not_exists','for_all'):
            self.satisfied = True 
            return True,''

        #  not_for_all: shortcircuit any False return --> reaching here means means all returns are True so quantification is False
        #  exists: shortcircuit any True return --> reaching here means all returns are False so quanitification is False
        #
        self.satisfied = False

        return False, '%!%'.join(failedArgs)


def gatherDataObjects( root ):
    global data_object_dict

    # get names of dictionaries and ObjectLists
    data_object_dict = {}
    dictionaries = root.findall('Dictionary')
    for d in dictionaries:
        name = d.get('name')
        imported = d.get('imported')
        compute  = d.get('compute')
        data_object = DataObject(name, imported, 'dict', compute)
        data_object_dict[ name ] = data_object
        name_graph.add_node( name )

    obj_lists = root.findall('ObjectList')
    for obj in obj_lists:
        name = obj.get('name')
        imported = obj.get('imported')
        compute  = obj.get('compute')
        data_object = DataObject(name, imported, 'list', compute)
        data_object_dict[ name ] = data_object
        name_graph.add_node( name )

    # visit each object_list or dict that is not imported and
    # get names of object_lists or dictionaries upon which it is dependent
    # and create an edge in the graph
    #
    for name, data_obj in data_object_dict.items():
        if data_obj.imported:
            continue

        fc = data_obj.compute
        call_params = parseFunctionCall(fc)

        # ensure that function being called is known
        for arg in call_params[1:]:
            if arg.find('\'') == 0 and arg.count('\'') == 2 and arg.rfind('\'') == len(arg)-1:
                continue

            if arg not in data_object_dict:
                print('undefined function argument',arg)
                exit(1)
            name_graph.add_edge(arg,name)

    # check for circular dependencies
    cg = simple_cycles( name_graph )
    for cycle in cg:
        print('cycle detected in object_set graph', repr(g))
        exit(1)

    # check that every reference to data_object in function calls of policy rules are known
    rules = root.findall('PolicyRule')
    for rule in rules:
        call = rule.get('evaluate') 
        call_params = parseFunctionCall(call)
        for arg in call_params[1:]:
            arg = arg.replace('@','')
            if arg not in data_object_dict:
                print('undefined evaluation argument',arg)
                exit(1)

    # after a topological sort evaluate the function calls and put the 
    # resulting data_objects in their respective data structures
    #
    tg = topological_sort(name_graph)
    for name in tg:
        data_obj = data_object_dict[ name ]
        if data_obj.imported:
            continue
        fc = data_obj.compute
        call_params = parseFunctionCall(fc)
        call_refs = [ data_object_dict[name].obj if name in data_object_dict else name.replace("'","") for name in call_params[1:]]

        # compute the data object as directed
        #
        data_obj.obj = function_dict[ call_params[0] ]( call_refs )

    return data_object_dict
  
# input is policy file in xml format, a dict of function pointers (name of function maps to function pointer),
# and a systemDict that has keys corresponding to pre-defined object classes such as 'devices', 'networks', 'flows'.
# All the arguments used in the policy evaluation come from dictionaries in systemDict
#
def parsePolicy( pf, functions, dictionaries):
    global function_dict, global_dict

    function_dict.update( functions )
    global_dict.update( dictionaries )

    # extract the policy description using the ElementTree formalism
    root = ET.parse(pf)
    root = root.getroot()
    
    # build the data objects
    data_objects_dict = gatherDataObjects( root )

    # evaluate the policy rules
    allPolicyRules = root.findall('PolicyRule')

    policyRuleList = []
    for rule in allPolicyRules:
        name       = rule.get('name')
        quantifier = rule.get('quantifier')
        evaluate   = rule.get('evaluate')        
        policyRuleList.append( PolicyRule(name, quantifier, evaluate) )

    return data_objects_dict, policyRuleList

