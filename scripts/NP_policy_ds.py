import json
from NP_utils import cvr
from NP_utils import buildElement
from NP_utils import Device
from NP_utils import Network
from ipn import IPValue, maxIPv4
import xml.etree.ElementTree as ET

class Flow(object):

    def __init__(self):
        return

    ### the path read in from the json file is turned into a dictionary
    def fromPathDict( self, flowDict ):

        ### we'll extract information and push back modifications using the ElementTree API
        pD = buildElement('Flow', flowDict)

        ### Flows will be grouped by their connection code, meaning same source and destination
        connectionCode = pD.get('connectionCode')

        srcNetId, dstNetId = connectionCode.split('%')
        self.srcNet = Flow.IdToIP( srcNetId )
        self.dstNet = Flow.IdToIP( dstNetId )

        ### local index, will change after we're done with this
        self.pathNumber = int(pD.get('pathNumber'))
 
        self.protocol = pD.get(u'protocol')
        endpoints = pD.findall(u'PathEndpoint') 

        IPR = endpoints[0].find(u'IPRange')
        low  = IPR.get(u'first')
        high = IPR.get(u'last')

        self.srcIPrange = cvr( IPValue(low), IPValue(high), wc=(low==0 and high == maxIPv4), empty=(low>high))
        self.srcIP = low+'-'+high

        srcIncludes = IPR.get(u'include')
        # transform srcIncludes to IP or CIDR using IP_dict
        if srcIncludes:
            self.srcIncludes = [ Flow.IdToIP(srcInc) for srcInc in srcIncludes.split(',')]
        else:
            self.srcIncludes = []


        IPt = endpoints[0].find(u'PortRange')
        low  = IPt.get(u'first')
        high = IPt.get(u'last')
        self.srcPtrange = cvr(int(low),int(high), wc=(low==0 and high==65535))
        self.srcPt = low+'-'+high

        IPR = endpoints[1].find(u'IPRange')
        low  = IPR.get(u'first')
        high = IPR.get(u'last')

        self.dstIPrange = cvr( IPValue(low), IPValue(high), wc=(low==0 and high == maxIPv4), empty=(low>high))
        self.dstIP = low+'-'+high

        # transform dstIncludes to IP or CIDR using IP_dict
        dstIncludes = IPR.get(u'include')
        if dstIncludes:
            self.dstIncludes = [ Flow.IdToIP(dstInc) for dstInc in dstIncludes.split(',')]
        else:
            self.dstIncludes = []

        IPt = endpoints[1].find(u'PortRange')
        low  = IPt.get(u'first')
        high = IPt.get(u'last')
        self.dstPtrange = cvr(int(low),int(high), wc=(low==0 and high==65535))
        self.dstPt = low+'-'+high

        PP = pD.findall('PathPoint')
        self.pathPoints = {}

        self.devices = []
        pDesc = pD.find('PathDescription')

        self.service     = pDesc.get('service')
        self.application = pDesc.get('application')
        self.user        = pDesc.get('user')

    def to_json(self):
        flowDict = {}
        flowDict['srcNet'] = self.srcNet
        flowDict['dstNet'] = self.dstNet
        flowDict['pathNumber'] = self.pathNumber
        flowDict['protocol'] = self.protocol
        flowDict['srcIP']    = self.srcIP
        flowDict['srcPt']    = self.srcPt
        flowDict['dstIP']    = self.dstIP
        flowDict['dstPt']    = self.dstPt
        flowDict['srcIncludes'] = self.srcIncludes
        flowDict['dstIncludes'] = self.dstIncludes
        flowDict['devices']  = self.devices
        flowDict['service']  = self.service
        flowDict['application']  = self.application
        flowDict['user']     = self.user
        return flowDict

    @staticmethod
    def from_json(flowDict):
        fd = Flow()
        fd.srcNet         = flowDict['srcNet']
        fd.dstNet         = flowDict['dstNet']
        fd.pathNumber     = flowDict['pathNumber']
        fd.protocol       = flowDict['protocol']

        fd.srcIP          = flowDict['srcIP']
        lowIP, highIP     = fd.srcIP.split('-')
        lowIPv            = IPValue(lowIP)
        highIPv           = IPValue(highIP)
        fd.srcIPrange     = cvr(lowIPv,highIPv, wc=(lowIPv==0 and highIPv==maxIPv4))

        fd.dstIP          = flowDict['dstIP']
        lowIP, highIP     = fd.dstIP.split('-')
        lowIPv            = IPValue(lowIP)
        highIPv           = IPValue(highIP)
        fd.dstIPrange     = cvr(lowIPv,highIPv, wc=(lowIPv==0 and highIPv==maxIPv4))

        fd.srcPt          = flowDict['srcPt']
        lowPt, highPt     = fd.srcPt.split('-')
        lowPtv            = int(lowPt)
        highPtv           = int(highPt)
        fd.srcPtrange     = cvr(lowPtv,highPtv, wc=(lowPtv==0 and highPtv==65535))

        fd.dstPt          = flowDict['dstPt']
        lowPt, highPt     = fd.dstPt.split('-')
        lowPtv            = int(lowPt)
        highPtv           = int(highPt)
        fd.dstPtrange     = cvr(lowPtv,highPtv, wc=(lowPtv==0 and highPtv==65535))

        fd.srcIncludes    = flowDict['srcIncludes']
        fd.dstIncludes    = flowDict['dstIncludes']

        fd.devices        = flowDict['devices']
        fd.service        = flowDict['service']
        fd.application    = flowDict['application']
        fd.user           = flowDict['user']
        return fd

def parsePathsDict(pathFileName ):
    allFlows = {} 

    with open(pathFileName,'r') as rf:
        for line in rf.readlines():
            pathDict = json.loads(line)

            ### we can tell whether this is a blob describing a path or not by looking for key 'PathDescription'
            if u'PathDescription' not in pathDict:
                continue

            pF = Flow()
            pF.fromPathDict( pathDict )
            name = pF.pathNumber

            ### allFlows is a global dictionary, indexed by path number, with values equal to these Flow instances.
            ### Useful given a path number to get at the Flow instance and the data structures it holds
            ###
            allFlows[ name ] = pF 
        
    return allFlows

def markCriticalNetworks(name_dict):

    # networks faced by interfaces that have name matching EMS are deemed critical and all the
    # hosts they contain are deemed critical
    #
    criticalNetworks = set()
    lowSecurityNetworks = set()
    highSecurityNetworks = set()

    for devName, devDict in name_dict['devices'].items():
        if devDict['deviceType'] == 'firewall':
            for intrfcDict in devDict['interface']:
                if 'name' in intrfcDict: 
                    if intrfcDict['name'].find('EMS') > -1 and 'facing' in intrfcDict:
                        criticalNetworks.add( intrfcDict['facing'] )
                    if intrfcDict['name'].find('inside') > -1:
                        highSecurityNetworks.add( intrfcDict['name'])
                    if intrfcDict['name'].find('outside') > -1:
                        lowSecurityNetworks.add( intrfcDict['name'])

    # mark hosts that are in criticalNetworks as being critical
    for faced in sorted(criticalNetworks):
        netDict = name_dict['networks'][faced]
        netDict['critical'] = True
        for ip in netDict['ips']:
            hostDict = name_dict['devices'][ip]
            hostDict['critical'] = True

# clean up system dictionary (input with devices and networks) as needed
def cleanseSystemDict( systemDict ):

    for devName, devDict in systemDict['devices'].items():
        if 'interface' not in devDict:
            continue
        rmI = []
        for idx,intrfc in enumerate(devDict['interface']):
            if 'facing' in intrfc and intrfc['facing'].find('/32') > -1:
                rmI.append(idx)
            elif 'facing' in intrfc and intrfc['facing'].find('127.0.0.0') > -1:
                rmI.append(idx)

        for idx in reversed(range(0,len(rmI))):
            devDict['interface'].pop(idx)

    removeNetworks = ('0.0.0.0/0','127.0.0')
    rn = []
    for netName, netDict in systemDict['networks'].items():
        for rmN in removeNetworks:
            if netName.find(rmN) > -1:
                rn.append(netName)

    for rmN in rn:
        del(systemDict['networks'][rmN])


def cleanseFlowDict( flowDict ):
    return

