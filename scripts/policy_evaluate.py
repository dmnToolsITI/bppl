#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse
import sys
import pdb
import json
import sys
import os
from policy_parse import parsePolicy
from NP_policy_defs import functionDict
from NP_policy_ds import Flow, cleanseSystemDict, cleanseFlowDict

xml_file = None
flows_file = None
network_file = None
systemDict = None

def getArguments(cmdline):
    parser = argparse.ArgumentParser()
    parser.add_argument('-xml', metavar='xml file with policy statement', dest='xml_file', required=True)
    parser.add_argument('-flows', metavar='json file with flow description', dest='flows_file', required=False)
    parser.add_argument('-network', metavar='json file with devices and network description', dest='network_file', required=True)
    args = parser.parse_args(cmdline)

    xml_file     = args.xml_file
    flows_file   = args.flows_file
    network_file = args.network_file

    return xml_file, flows_file, network_file


# xml_file    is the name of a file with an XML policy description
# flows_file  is the name of a json file of flows (possibly created from NP paths, but in the flows format)
# system_file is the name of a json file of devices and networks objects
#
def evaluatePolicy(xml_file_name, flows_file_name, system_file_name):
    global systemDict

    # extract the networks and device dictionaries
    with open(system_file_name,'r') as nf:
        systemDict = json.load(nf)
        cleanseSystemDict( systemDict )


    # are there flows coming in or paths?
    with open(flows_file_name,'r') as ff:
        flowsJson = json.load(ff)
        flowsDict = {} 
        for flowDict in flowsJson['flows']:
            cleanseFlowDict( flowDict )
            #flowsList.append( Flow.from_json( flowDict ) )
            flowsDict[ flowDict['pathNumber']] = flowDict 
        systemDict.update( {'flows':flowsDict } )

    # Lots goes on when parsing the policy.  The object groups the policy references are filtered
    # from the dictionaries in systemDict, the filtering is performed using functions pointed to in functionDict.
    # The reason for passing the dictionary in rather than asking parsePolicy to just use functionDict is to provide
    # separation from code that might be used by any way of defining functions and object dictionaries, and the way it is 
    # done using NP
    #
    data_objects_dict, PolicyRuleDict = parsePolicy( xml_file_name, functionDict, systemDict )

    # policy holds if every policy rule evaluates to True
    #
    num_errors = 0
    for idx, policyRule in enumerate(PolicyRuleDict):
        result, failureString = policyRule.evaluate()
        if not result:
            num_errors = num_errors + 1
            print('Policy rule',idx,'fails on inputs')
            error_msgs = failureString.split('%!%')
            for err in error_msgs:
                print('\t',err)

    if num_errors == 0:
        print('Policy ruleset passes')


def main():
    global xml_file, flows_file, system_file
    xml_file, flows_file, system_file = getArguments(sys.argv[1:])

    evaluatePolicy( xml_file, flows_file, system_file )
     

if __name__ == "__main__":
    main()
 

