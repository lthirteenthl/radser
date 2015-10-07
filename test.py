from __future__ import with_statement
from datetime import datetime
import MySQLdb
import db

class UnetmapAuthStorage(object):
  def __init__(self, config):
    self.engine = db.Engine()
    self.engine.Register(config)
    self.engine.Connect()

  def getDict(self, query, params):
#    ldbg("storage module. Function getDict")
#    ldbg("storage module. query => %s | params => %s " % (query, params))
    conn = self.engine.Connect()
#    ldbg("storage module. Function GetDict. post engine.Connect")
#    ldbg("storage module. Function GetDict. print conn => %s " % conn)
    if conn:
      with conn.lock:
        try:
          cu = conn.cursor(MySQLdb.cursors.DictCursor)
#          ldbg("storage module. Function GetDict. post conn.cursor => %s " % cu)
#          ldbg("query => %s " % query)
#          ldbg("params => %s " % params)
          cu.execute(query, (params,))
###          ldbg("storage module. Function GetDict. post execute query cu => %s " % kekcu)
          kekret = cu.fetchall()
#	  ldbg("returns valuser => %s " % kekret)
###          return cu.fetchall()
#          ldbg("result cu.fetchall => %s " % kekdb )
          return kekdb
###        except MySQLdb.Error, e:
###          lerr("FAILED: %s" % e)
###    ldbg("storage module. Function GetDict did not return")
