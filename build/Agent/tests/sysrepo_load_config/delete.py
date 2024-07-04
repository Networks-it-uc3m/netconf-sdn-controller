from ncclient import manager

server=manager.connect(host="localhost",
     port="830", timeout=30, username="netconf", password="netconf", hostkey_verify=False)
conf = open('del_spd.xml').read()
server.edit_config(target = "running", config = conf)

conf = open('del_sad.xml').read()
server.edit_config(target = "running", config = conf)