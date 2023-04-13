from ipn import IPValue, Int2IP, isCIDR, cidrRange 
import copy 

# print functions for objects and lists to report policy failures

def flowToString(flow):
        return 'flow '+ str(flow['pathNumber'])

def networkToString(networkDict):
    return networkDict['CIDR']
 
def deviceToString(devDict):
    devType = devDict['deviceType']
    if devType == 'firewall':
        return 'firewall '+ obj['name']
    
    return obj['deviceType']+obj['ipName']


# these definitions link network objects and flows generated
# by the NP engine to functions called by the (open) policy
# evaluation framework
#
# 
systemDict = {}

def setSystemDict( sysDict ):
    global systemDict
    systemDict = sysDict

    for objType in systemDict:
        if objType == 'flows':
            for flow in systemDict['flows']:
                flow['obj_ref'] = flowToString
            continue

        if objType == 'devices':
            for _, deviceDict in systemDict['devices'].items():
                deviceDict['obj_ref'] = deviceToString
            continue

        if objType == 'networks':                
            for _, networkDict in systemDict['networks'].items():
                networkDict['obj_ref'] = networkToString
            continue

# inESP accepts a dictionary describing a device and determines
# whether it is inside of the ESP
#
def inESP(argList):
    devices = argList[0]
    ESP     = argList[1]
    rtn     = {}

    # for every interface in every device check whether interface IP falls within some network in the ESP
    for devName, devDict in devices.items():
        for intrfc in devDict['interface']:

            if 'IP' not in intrfc:
                continue

            ipv = IPValue(intrfc['IP'])
            for espNet in ESP:
                low, high = cidrRange(espNet)
                if low <= ipv <= high:
                    rtn[devName] = espNet 

    return rtn

def identifyZones(argList):
    firewallDict = argList[0]
    networkDict  = argList[1]
    rtn ={}

    zones = {}
    for fw,fwDict in firewallDict['firewall']:
        # go through interfaces looking for names involving 'EMS'
        for intrfcDict in fwDict['interface']:
            if 'name' in intrfcDict and intrfcDict['name'].find('EMS') > -1:
                found_zone = zones[ intrfcDict['facing'] ]
                zones[ found_zone ] = networkDict[ found_zone ] 

    return {'zones':zones}

def PLCs(argList):
    devDict = argList[0] 
    rtn = {}
    for name,dev in devDict.items():
        if dev['deviceType'] == 'PLC':
            rtn.update({name:dev})
 
    return rtn 

def deviceType(argList):
    dtype   = argList[0] 
    devDict = argList[1] 

    rtn = {}
    for name,dev in devDict.items():
        if dev['deviceType'] == dtype:
            rtn.update({name:dev})
 
    return rtn



def targetESP(argList):
    # get the target destination range of the flow
    #
    allFlowsDict = argList[0]
    ESPDict      = argList[1]
    rtn = {}

    for name,flowDict in allFlowsDict.items():
        dstNet = flowDict['dstNet']
        if dstNet in ESPDict:
            rtn.update({name:flowDict})

    return rtn

def firewalls(devDict):
    rtn = {}
    for dev in devDict:
        if dev['deviceType'] == 'firewall':
            rtn[ dev['name'] ] = copy.deepcopy(dev)

    return {'firewalls':rtn }

# for each flow check whether every IP address in destination range
# maps to a device that has been tagged as critical
#   Input is the flow to check, and a list of devices that _have_ been tagged as critical
#
def checkTargetCriticality(funcArgs):

    def nxtIP( thisIP ):
        nxtIPv = IPValue( thisIP )+1
        return IntToIP( nxtIPv )

    flowDict = funcArgs[0]
    devList  = funcArgs[1]

    dstRange = flowDict['dstIP']
    dstLowIP, dstHighIP = dstRange.split('-')
    dstLow  = IPValue( dstLowIP )
    dstHigh = IPValue( dstHighIP )

    checkIP = dstLow
    while True:
        if checkIP not in devList or 'critical' not in devList[checkIP]:
            return False
        
        if checkIP == dstHigh:
            break
        checkIP = nxtIP( checkIP )
 
    return True

def protocolTerminates(funcArgs):
    flowDict = funcArgs[0]
    if not flowDict or not 'devices' in flowDict:
        return True

    if flowDict['devices'] == 1:
        return True

    return False

def identifyESP(funcArgs):
    firewalls = funcArgs[0]
    networks  = funcArgs[1]
    rtn = {}
    for fname,fdev in firewalls.items():
        for intrfc in fdev['interface']:
            if intrfc['name'].find('EMS') > -1 and 'IP' in intrfc:
                name = intrfc['facing']
                rtn[name] = networks[name]    

    return rtn

def identifyZones(funcArgs):
    devDict = funcArgs[0]
    netDict = funcArgs[1]

    netRange = {}

    for name,net in netDict.items():
        ip,dim = name.split('/')

        if not 0<int(dim)<=32:
            import pdb
            pdb.set_trace()
            x = dim
 
        low = IPValue(ip)
        high = (1<<(32-int(dim))) - 1
        netRange[name] = (low, high)

    rtn = {}
    for fname,fdev in devDict.items():
        for intrfc in fdev['interface']:

            if 'facing' in intrfc:
                facingNet = intrfc['facing']
                zone = copy.deepcopy( netDict[ facingNet] )
                # put a security rating here based on interface name

            else:
                # find the smallest network the interface IP 'fits' in
                #
                zone = None
                if 'IP' in intrfc:
                    ipv = IPValue( intrfc['IP'] )
                    smallest = None
                    for netName,(low,high) in netRange.items():
                        if low <= ipv <= high and (not smallest or high-low+1 < smallest):
                            smallest = high-low+1
                            zone = copy.deepcopy( netDict[netName] )
                if zone:
                    rtn[ zone['CIDR'] ] = zone
                    zone['security_level'] = 'medium'
                    if intrfc['name'].find('EMS') > -1 or intrfc['name'].find('inside') > -1:
                        zone['security_level'] = 'high'
                    if intrfc['name'].find('outside') > -1:
                        zone['security_level'] = 'low'

    return rtn
 

def securityLessThan(a1,a2):
    if a1=='low' and a2 != 'low':
        return True

    if a1=='medium' and a2 == 'high':
        return True

    return False

def checkHighToLow(funcArgs):
    flowDict = funcArgs[0]
    zones    = funcArgs[1]

    for pathNumber, flow in flowDict.items():
        srcNet = flow['srcNet']
        dstNet = flow['dstNet']
        if srcNet in zones and dstNet in zones and securityLessThan(zones['srcNet'],zones['dstNet']):
            return False

    return True
 

functionDict = {'inESP':inESP, \
                'PLCs':PLCs, \
                'targetESP':targetESP, \
                'checkTargetCriticality':checkTargetCriticality,\
                'protocolTerminates':protocolTerminates, 
                'firewalls':firewalls,
                'identifyESP':identifyESP,
                'identifyZones':identifyZones,
                'checkHighToLow':checkHighToLow,
                'deviceType':deviceType }

