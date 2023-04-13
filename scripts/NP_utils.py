class Network():

    def __init__(self, netId, ipa, nmsk): 

        self.netId = netId
        self.ipa = ipa
        self.nmsk = nmsk
 
deviceId = 1

# class Device is a base class for devices that have interfaces, finite state machines
# and interact with routing logic
#
class Device(object):
    def __init__(self,dtype):
        global deviceId

        self.devId = deviceId
        deviceId += 1
        self.devType = dtype
 
def buildElement(tag, d):

    elem  = ET.Element(tag)
    if 'tag' in d:
        elem.tag = d['tag'].strip()
    if 'tail' in d:
        elem.tail = d['tail'].strip()
    if 'text' in d:
        elem.text = d['text'].strip()

    for (k, v) in list(d.items()):

        # attrib should be the only dictionary
        if k == 'attrib':
            for atb in v:
                try:
                    elem.set(atb, v[atb].strip())
                except:
                    elem.set(atb, v[atb])

        elif isinstance(v, str) or type(v) == str:
            elem.set(k, v.strip())

        else:
            for item in v:
                elem.append(buildElement(k, item))

    return elem

### base class for ipRange and PortRange.  Attributes
###    low, high --- lower and upper bounds of range described
###    empty     --- no meaningful range here, coded by having lower>upper
###    wc        --- indicates whether this describes the entire range, hence is a wildcard.  A super class knows
###                  whether the range is wc or not because the superclass knows the upper bound of the range, different for Ports than IP
###    excludes  --- index into shared array coding ranges that are excluded from this one
###
class cvr:
    def __init__(self, low, high, wc=False):

        self.low   = int(low)
        self.high  = int(high)
        self.wc    = wc
 
    @property
    def first(self):
        return self.low

    @property
    def last(self):
        return self.high

    ### True if 'this' cvr contains the argument cvr, else False
    def contains(self,vr):
  
        ### matter of definition, like the proposition 'if False then any-thing-is-true', we will call it True
        if self.empty:
            return True

        ### matter of definition.  A non-empty cvr contains the empty one, just as the empty set is a subset of any other set.
        if vr.empty:
            return True

        ### as both cvrs have actual ranges, do the ordinary comparison
        return self.low <= vr.low and vr.high <= self.high


    ### determine whether 'this' cvr's range has intersection with another's, passed as argument
    ### 
    def intersects(self,vr):

        ### True by logic if either cvr is a wildcard, True by defintion
        ### if either argument is empty
        if self.wc or vr.wc:
            return True

        ### usual intersection comparison
        return max(self.low,vr.low) <= min(self.high,vr.high)

    # compute the intersection of two value_range's, return Empty cvr
    # if intersection is empty
    #
    def intersection(self,vr):

        ### intersection with wildcard is just the range itself
        if self.wc: 
            return vr

        if vr.wc:
            return self

        ### if the intersection range inverts the order of low and high then the
        ### range is empty, so we can just compute the range and pass off to the constructor 
        return cvr( max(self.low,vr.low), min(self.high,vr.high), wc=False)

    def copy(self):
        return cvr( self.low, self.high, empty=self.empty, wc=self.wc, excludes=self.excludes)

