# import FullSQLEnrichSecChecks
import metadata
import sys

# p1 = FullSQLEnrichSecChecks.EnrichFullSQLES("param_data.json")


loc_param="/home/context22/Context22/CT22_Common/sqlite/sqlitect22"


p1 = metadata.MetaData(loc_param)

df = p1.readsqlstowatchTable()

# p1.GetMetaData()

print(df)
