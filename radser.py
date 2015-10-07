import radiusd

import utils, storage
import ConfigParser
from utils import MakePacket, MakeAVP
from utils import ldbg, linfo, lerr, log

class Auth(object):
  def __init__(self, storage):
    self.storage = storage

  def Authorize(self, user):
    ldbg("Class Auth. Function Authorize")
    ldbg("Variable's user -> %s" % user)
    reply = {}
    config = {}

    creds = self.storage.GetGWCreds(user)
    ldbg("Class Auth. Function Authorize. post get creds")
    if not creds:
      creds = self.storage.GetUserCreds(user)
      if not creds:
        linfo("REJECT: user '%s' unknown" % user)
        reply['Reply-Message'] = "Unknown"
        return MakePacket(radiusd.RLM_MODULE_REJECT, reply, config)

      if creds['locked']:
        linfo("REJECT: user '%s' locked" % user)
        reply['Reply-Message'] = "Locked"
        return MakePacket(radiusd.RLM_MODULE_REJECT, reply, config)

    linfo("ACCEPT: user '%s' enabled, prepare for authenticating" % user)
    config['Auth-Type'] = 'Digest'
    config['Cleartext-Password'] = creds['password']
    return MakePacket(radiusd.RLM_MODULE_UPDATED, reply, config)

  def AuthInvite(self, src, dst, proxy_address):
    config = {}
    reply = {}
    rpid = None

    linfo("INFO: processing call: '%s' -> '%s'" % (src, dst))

    if dst[0] == '9':
      num = dst[1:]
    else:
      num = dst

    dset = self.storage.GetDset(num, proxy_address)

    if not dset and dst[0] == '9':
      dset = self.storage.GetGatewayDset(num)
      creds = self.storage.GetUserCreds(src)

      number = dset[0][0]

      if not creds or not utils.CheckACL(number, creds['ACL'], creds['ACLExceptions']):
        linfo("REJECT: user '%s' has not permission call to '%s', or unknown" % (src , str(dset)))
        reply['Reply-Message'] = "Forbidden"
        return MakePacket(radiusd.RLM_MODULE_OK, reply, config)
      rpid = '78452' + creds['exnum']

    if not dset:
      linfo("REJECT: destination '%s' unknown" % dst)
      reply['Reply-Message'] = "Dset fail"
    else:
      linfo("ACCEPT: '%s' call to '%s'" % (src, str(dset)))
      reply['Sip-Avp'] = MakeAVP(dset, rpid)
    return MakePacket(radiusd.RLM_MODULE_OK, reply, config)

class Acct(object):
  def __init__(self, storage):
    self.storage = storage

  def Account(self, d):
    if self.storage.Insert(d):
      return radiusd.RLM_MODULE_OK
    lerr("FAIL: Couldn't account call")
    return radiusd.RLM_MODULE_INVALID

auth = None
acct = None

def ParseConfig(cfg):
  res = {}
  res['acct'] = []
  res['auth'] = []

  db_cfg = dict(cfg.items('database'))

  dbs = db_cfg['acct'].split()
  for d in dbs:
    res['acct'].append(dict(cfg.items(d)))

  dbs = db_cfg['auth'].split()
  for d in dbs:
    res['auth'].append(dict(cfg.items(d)))

  return res


def instantiate(data):
  global auth, acct
  ldbg("instantiate data: %s" % str(data))

  cfg = ConfigParser.ConfigParser()
  cfg.read("/etc/radser.cfg")

  db = ParseConfig(cfg)
  ldbg("db config: %s" % str(db))

  auth = Auth(storage.UnetmapAuthStorage(db['auth']))
  acct = Acct(storage.AcctStorage(db['acct']))

def accounting(data):
  ldbg("accounting packet: %s" % str(data))

  d = utils.RadPacketToDict(data)

  if ('Service-Type' not in d) or (d['Service-Type'] != 'Sip-Session'):
    linfo("Service-Type is not Sip-Session, noop")
    return radiusd.RLM_MODULE_NOOP

  return acct.Account(d)

def authorize(data):
  ldbg("authorize data: %s" % str(data))
  ldbg("function authorize")
  d = utils.RadPacketToDict(data)
  
  ldbg("function authorize (d variable) => %s " % d)

  if 'Service-Type' not in d:
    linfo("Service-Type is not present, noop")
    ldbg("function authorize: Service-Type is not present")
    return radiusd.RLM_MODULE_NOOP
  ldbg("function authorize: post check Service-Type")

  if d['Service-Type'] == 'Sip-Session':
    user = d.get("User-Name")
    ldbg("function authorize: User-Name -> %s " % user)
    if not user:
      lerr("FAIL: couldn't extract 'User-Name' from packet")
      ldbg("function authorize: couldn't extract User-Name")
      return radiusd.RLM_MODULE_FAIL
    ldbg("function authorize: post check User-Name and Sip-Session")
    ldbg("process for get user-name by split -> %s " % user.split('@')[0])
    kek = auth.Authorize(user.split('@')[0])
    ldbg("function authorize: get kek -> %s " % str(kek))
#    return auth.Authorize(user.split('@')[0])
    return kek

  linfo("Unknown Service-Type")
  return radiusd.RLM_MODULE_NOOP

def authenticate(data):
  '''using as Post-Auth'''
  ldbg("authenticate data: %s" % str(data))
  ldbg("function authenticate")
  d = utils.RadPacketToDict(data)

  if 'Service-Type' not in d:
    linfo("Service-Type is not present, noop")
    return radiusd.RLM_MODULE_NOOP

  if 'Digest-Method' not in d:
    linfo("Digest-Method is not present, noop")
    return radiusd.RLM_MODULE_NOOP

  if d['Service-Type'] == 'Sip-Session':
    if d['Digest-Method'] == 'INVITE':
      src = d.get("Sip-Uri-User")
      if not src:
        lerr("FAIL: couldn't extract 'Sip-Uri-User' from packet")
        return radiusd.RLM_MODULE_FAIL

      dst = d.get("Digest-URI")
      if not dst:
        lerr("FAIL: couldn't extract 'Sip-Uri-User' from packet")
        return radiusd.RLM_MODULE_FAIL
      dst = dst.split('@')[0][4:]

      proxy = d.get("NAS-IP-Address")
      if not proxy:
        lerr("FAIL: couldn't extract 'Sip-Uri-User' from packet")
        return radiusd.RLM_MODULE_FAIL

      return auth.AuthInvite(src, dst, proxy)

  return radiusd.RLM_MODULE_NOOP

