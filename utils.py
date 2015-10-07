import types
import radiusd

def log(level, msg):
  radiusd.radlog(level, "%s: %s" % ("radser", msg))

def ldbg(msg):
  log(radiusd.L_DBG, msg)

def linfo(msg):
  log(radiusd.L_INFO, msg)

def lerr(msg):
  log(radiusd.L_ERR, msg)

class URISet(list):
  def __init__(self, default_addr=None):
    list.__init__(self)
    self.default_addr = default_addr

  def append(self, user, addr=None):
    if not addr or addr == "0.0.0.0":
      addr = self.default_addr
    list.append(self, [user, addr])

  def GetURI(self):
    return ["sip:%s@%s" % (v[0], v[1]) for v in self]


def RadPacketToDict(t):
  r = {}
  for k, v in t:
    v = v.strip('"')
    if k in r:
      if isinstance(r[k], types.ListType):
        r[k].append(v)
      else:
        r[k] = [r[k], v]
    else:
      r[k] = v
  return r

def DictToRadPacket(d):
  r = []
  for k, v in d.items():
    if isinstance(v, types.ListType):
      for vl in v:
        r.append((k, vl))
    else:
      r.append((k, v))
  return tuple(r)

def MakePacket(code, reply, config):
  return (code, DictToRadPacket(reply), DictToRadPacket(config))

def GetUserFromURI(uri):
  return uri.split('@')[0][4:]

def MakeAVP(dset, rpid):
  ruri_h = '#42'
  rpid_h = '#43'
  avp = []

  if rpid:
    avp.append("%s:sip:%s" % (rpid_h, rpid))
  for u in dset.GetURI():
    avp.append("%s:%s" % (ruri_h, u))
  return avp

def CheckExceptionNumbers(number, exceptions):
    return number in exceptions

def CheckACL(number, access, exceptions=None):
    if exceptions and CheckExceptionNumbers(number, exceptions):
        linfo("ACL PASS: number: %s, access: %s, exceptions: %s." % (number, access, exceptions))
        return 1
    if access == "international":
        pass
    elif access == "intercity" and number[:3] != '810':
        pass
    elif access == "intracity" and number[:1] != '8':
        pass
    elif access == "intracity" and number[:4] == '8800':
        pass
    else:
       linfo("ACL FAIL: number: %s, access: %s, exceptions: %s." % (number, access, exceptions))
       return 0
    linfo("ACL PASS: number %s, access: %s, exceptions: %s." % (number, access, exceptions))
    return 1

