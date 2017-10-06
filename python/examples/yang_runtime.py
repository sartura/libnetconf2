import libyang as ly
ctx = ly.Context("/etc/sysrepo/yang")
module = ctx.load_module("turing-machine")
node = ctx.parse_data_path("/etc/sysrepo/data/turing-machine.startup", ly.LYD_XML, ly.LYD_OPT_CONFIG)
import netconf2
print("this will fail becasue of wrong type")
netconf2.parse_lyd_data(node)
print("this will succeed")
netconf2.parse_lyd_data(node.C_lyd_node())
