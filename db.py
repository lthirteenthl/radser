from __future__ import with_statement
import types, threading
import MySQLdb

from utils import lerr

class Connection(object):
  def __init__(self, config):
    self.db = None
    try:
      self.db = MySQLdb.connect(**config)
      self.db.lock = threading.RLock()
    except MySQLdb.Error, e:
      lerr(e)

  def is_valid(self):
    if self.db:
      with self.db.lock:
        try:
          self.db.ping()
        except MySQLdb.Error, e:
          return 0
        return 1

class Engine(object):
  def __init__(self):
    self.__connection_pool = {}
    self.__configs = {}

  def Register(self, config, name=''):
    if isinstance(config, types.ListType):
      for c in config:
        self._add_config(name, c)
    else:
      self._add_config(name, config)

  def Connect(self, name=''):
    if name in self.__configs:
      conn = self.__connection_pool.get(name)
      if conn:
        if conn.is_valid():
          return conn.db
        else:
          del self.__connection_pool[name]
      # new connection
      for c in self.__configs[name]:
        conn = Connection(c)
        if conn.is_valid():
          self.__connection_pool[name] = conn
          return conn.db
      else:
        lerr("Couldn't connect to db")

  def _add_config(self, name, config):
    if name in self.__configs:
      self.__configs[name].append(config)
    else:
      self.__configs[name] = [config]

