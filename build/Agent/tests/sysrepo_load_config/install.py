from ncclient import manager

server=manager.connect(host="localhost",
     port="830", timeout=30, username="netconf", password="netconf", hostkey_verify=False)
# conf = open('add_spd.xml').read()
# server.edit_config(target = "running", config = conf)


conf = open('add_sad.xml').read()
server.edit_config(target = "running", config = conf)


0x286b8099b6907e99dcdda5017792a21ea1cfdf94
0x286B8099B6907e99DcdDa5017792a21ea1cfDF94