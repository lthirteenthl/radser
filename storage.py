from __future__ import with_statement
from datetime import datetime
import MySQLdb
from utils import lerr, ldbg
from utils import URISet
import db


class UnetmapAuthStorage(object):
  def __init__(self, config):
    self.engine = db.Engine()
    self.engine.Register(config)
    self.engine.Connect()

  def getDict(self, query, params):
    ldbg("storage module. Function getDict")
    ldbg("storage module. query => %s | params => %s " % (query, params))
    conn = self.engine.Connect()
    ldbg("storage module. Function GetDict. post engine.Connect")
    ldbg("storage module. Function GetDict. print conn => %s " % conn)
    """if conn:
      with conn.lock:
        try:
          #cu = conn.cursor(MySQLdb.cursors.DictCursor)
          cu = conn.cursor()
          ldbg("storage module. Function GetDict. post conn.cursor => %s " % cu)
          ldbg("query => %s " % query)
          ldbg("params => %s " % params)
          ldbg('SQL REQUEST: %s' % query % params)
          cur = cu.execute(query)
          cur = cu.
          ldbg("storage module. Function GetDict. post execute query cu [type:%s ; value: %s]" % (type(cur), str(cur)))
          return cur.fetchone()
        except MySQLdb.Error, e:
          ldbg("hello! I'm here!")
          lerr("FAILED: %s" % e)
    """
    if conn:
      try:
        cur = conn.cursor()
        cur.execute(query, (params,))
        ldbg("storage module. Function GetDict. post execute query cu [type:%s ; value: %s]" % (type(cur), str(cur)))
        return cur.fetchall()
      except MySQLdb.Error, e:
        ldbg("hello! I'm here!")
        lerr("FAILED: %s" % e)





  def getMetaDset(self, exnum, addr, id, sgid, default_addr):
    query = """
      SELECT Phones.internalnumber AS inum, Phones.disabled AS locked
      FROM phones_phone AS Phones
      WHERE Phones.phonegroup_id = %s AND Phones.servergroup_id !=%s
    """
    res = self.getDict(query, (id, sgid))
    dset = self.makeDset(res, default_addr)
    dset.append(exnum, addr)
    return dset

  def getGroupDset(self, id, default_addr):
    query = """
      SELECT Phones.internalnumber AS inum, Phones.disabled AS locked
      FROM phones_phone AS Phones
      WHERE Phones.phonegroup_id = %s
    """
    res = self.getDict(query, id)
    return self.makeDset(res, default_addr)
  
  def getPhoneDset(self, num, default_addr):
    query = """
      SELECT Phones.internalnumber AS inum, Phones.disabled AS locked, INET_NTOA(SG.ip) AS addr
      FROM phones_phone AS Phones
      LEFT JOIN phones_servergroup AS SG
      ON SG.id = Phones.servergroup_id
      WHERE Phones.internalnumber = %s OR Phones.externalnumber = %s
    """
    res = self.getDict(query, (num, num))
    # hack for stations
    for r in res:
      if r['addr'] != '0.0.0.0':
        r['inum'] = num
    return self.makeDset(res, default_addr)

  def getGatewayAddr(self):
    query = """
      SELECT INET_NTOA(SG.ip)
      FROM phones_servergroup AS SG
      WHERE
      SG.name = %s
    """
    conn = self.engine.Connect()
    if conn:
      with conn.lock:
        cu = conn.cursor()
        cu.execute(query, 'as5350')
        return cu.fetchall()[0][0]

  def makeDset(self, set, default_addr=None):
    dset = URISet(default_addr)
    for r in set:
      if r.get('locked'):
        continue
      dset.append(r['inum'], r.get('addr'))
    if len(dset):
      return dset

  def GetUserCreds(self, user):
    query = """
      SELECT Phones.internalnumber AS inum, Phones.password AS password, Phones.permit AS ACL, Phones.disabled AS locked, Phones.externalnumber AS exnum
      FROM phones_phone AS Phones
      WHERE Phones.internalnumber = %s
      LIMIT 1
    """
    exception_numbers_q = """
      SELECT e.number AS number FROM phones_phone AS p, phones_exception AS e WHERE p.internalnumber = %s AND e.phone_id = p.id
    """
    r = self.getDict(query, user)
    if len(r):
      creds = r[0]
    else:
      return None
    ex = self.getDict(exception_numbers_q, user)
    if len(ex):
      exceptions = []
      for row in ex:
        exceptions.append(row['number'])
      creds['ACLExceptions'] = exceptions
    else:
      creds['ACLExceptions'] = []
    return creds

  def GetGWCreds(self, user):
    ldbg("storage module. Function GetGWCreds")
    query = "SELECT SG.password AS password FROM phones_servergroup AS SG WHERE SG.name = %s LIMIT 1" % user
    ldbg("storage module. Function GetGWCreds. get query => %s and user => %s " % (query,user))
    r = self.getDict(query, user)
    ldbg("storage module. Funtion GetGWCreds. post function self.getDict")
    if len(r):
      return r[0]

  def GetDset(self, num, default_addr):
    query = """
      SELECT PG.id, PG.groupnumber AS inum, PG.externalnumber AS exnum, PG.servergroup_id AS sgid, INET_NTOA(SG.ip) AS addr, SG.name as sg, PG.metagroup AS is_meta
      FROM phones_phonegroup AS PG
      LEFT JOIN phones_servergroup AS SG
      ON SG.id = PG.servergroup_id
      WHERE PG.groupnumber = %s OR PG.externalnumber = %s
      LIMIT 1
    """
    res = self.getDict(query, (num, num))

    if len(res):
      info = res[0]
      if info['is_meta']:
        ldbg("call to meta-group '%s'" % info['exnum'])
        return self.getMetaDset(num, info['addr'], info['id'], info['sgid'], default_addr)
      if info['sg'] != "opensers":
        ldbg("call to PBX '%s@%s" % (num, info['addr']))
        dset = URISet()
        dset.append(num, info['addr'])
        return dset
      ldbg("call to group '%s'" % num)
      return self.getGroupDset(info['id'], default_addr)
    dset = self.getPhoneDset(num, default_addr)
    if dset:
      ldbg("call to phone '%s'" % num)
    return dset

  def GetGatewayDset(self, num):
    addr = self.getGatewayAddr()
    if addr:
      dset = URISet()
      dset.append(num, addr)
      return dset
    else:
      lerr("FAIL: couldn't get gateway address")


class AcctStorage(object):
  def __init__(self, config):
    self.engine = db.Engine()
    self.engine.Register(config)
    self.engine.Connect()

  def Insert(self, data):
    query = """
            INSERT statistics_radacct
            (AcctTime, AcctStatusType, SipToTag, SipFromTag, AcctSessionId, SipMethod, SipResponseCode, CalledStationId, CallingStationId)
            VALUES
            (%(Event-Timestamp)s, %(Acct-Status-Type)s, %(Sip-To-Tag)s, %(Sip-From-Tag)s, %(Acct-Session-Id)s, %(Sip-Method)s, %(Sip-Response-Code)s, %(Called-Station-Id)s, %(Calling-Station-Id)s)
    """
    data['Event-Timestamp'] = datetime.strptime(data['Event-Timestamp'], "%b %d %Y %H:%M:%S %Z")
    conn = self.engine.Connect()
    if conn:
      with conn.lock:
        cu = conn.cursor()
        try:
          cu.execute(query, data)
          return 1
        except MySQLdb.Error, e:
          lerr(e)
        except KeyError, e:
          lerr(e)
          lerr("Bad data: %s" % data)
    else:
      lerr("Could not connect to db")

