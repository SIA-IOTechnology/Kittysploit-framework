from core.base.base_module import BaseModule 
from core.output_handler import *

class Registry(BaseModule):
  
  def shell_registry_cmd(self, suffix):
    cmd = "cmd.exe /c reg"
    rep = self.cmd_exec(f"{cmd} {suffix}")
    return rep

  def registry_enumkeys(self, key):
    rep = self.shell_registry_cmd(f"query \"{key}\"")
    if "Error" in rep:
      return False
    return rep
  
  def registry_getvalinfo(self, key, val):
    """ Enumerate registry keys """

    rep = self.registry_enumkeys(f'query "{key}" /v "{val}"')
    if rep:
      pass

  def registry_getvaldata(self, key, val):
    rep = self.registry_getvalinfo(key, val)
    return rep["Data"]


