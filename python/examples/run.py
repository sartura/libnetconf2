import libyang as ly
import netconf2 as nc
ssh = nc.SSH('root')
session = nc.Session('localhost', 830, ssh)
data = session.rpcGetConfig(nc.DATASTORE_RUNNING)
schema = data.schema()
print(schema.name())
