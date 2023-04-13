
maxIPv4 = (1<<32)-1
maxIP   = maxIPv4


def Int2IP(ipnum):
    if isinstance(ipnum,IPAddress):
        return str(ipnum)
    ipn  = int(ipnum)

    o4   = ipn % 256
    ipn  = int(ipn>>8)
    o3   = ipn % 256
    ipn  = int(ipn>>8)
    o2   = ipn % 256
    ipn  = int(ipn>>8)
    o1   = ipn

    #o1 = int(ipnum / 16777216) % 256
    #o2 = int(ipnum / 65536) % 256
    #o3 = int(ipnum / 256) % 256
    #o4 = int(ipnum) % 256

    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()


def isCIDR( adrs ):
    prefix = None
    if adrs.find('/') > -1:
        adrs,prefix = adrs.split('/')

    try:
        if prefix and (int(prefix)<0 or int(prefix)>32):
            return False
    except:
        return False

    try:
        pieces = adrs.split('.')
        if len(pieces) != 4:
            return False
    except:
        return False

    try:
        for p in pieces:
            v = int(p)
            if not -1 < v and v < 256:
                return False
        return True
    except:
        return False

def IPValue(ip):
    if isinstance(ip,int) or isinstance(ip,int):
        return ip
    if ip.find('/') > -1:
        ip,dim = ip.split('/')
    try:
        [high,midhigh,midlow,low] = ip.split('.')

        v = int(high)*16777216
        v = v+int(midhigh)*65536
        v = v+int(midlow)*256
        v = v+int(low)
    except:
        return None
    return v


def cidrRange(cidr):
    ip, dimStr = cidr.split('/')
    ipv = IPValue(ip)
    dim = 32-int(dimStr)

    ipv = (ipv>>dim)<<dim
    return ipv, ipv+(1<<dim) - 1 


