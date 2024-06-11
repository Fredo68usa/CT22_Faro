import metadata
import Extractions
import secChecks
import sys

loc_param = "../CT22_Common/sqlite/sqlitect22"


prog = str(sys.argv[1])


# --- secChecks
if prog == '3' :
    p3 = secChecks.secChecks(loc_param, 'param_data.json')
    nextSQLhash2 = '968c3ede97d8466333059c677f187f88'
    p3.checkPred(nextSQLhash2, 2021,102)
    exit(0)


# --- Extractions
if prog == '2' :
    p2 = Extractions.UpdateSqlCounters(loc_param)
    nextSQLhash1 = '075268b9080b86bc2b7d4d5096de9178'
    nextSQLhash2 = '968c3ede97d8466333059c677f187f88'
    year = 2021
    dayofyear = 102
    # 13373539409
    p2.updateExtracts(nextSQLhash2, year,dayofyear, 200000)
    exit(0)

# --- Test data
if prog == '1' :
    p1=metadata.MetaData(loc_param)

    p1.get_Agents()
    p1.get_Colls()
    p1.get_DBUsers()
    p1.get_nodes()
    # p1.get_nodes()
    p1.get_predsTable()
    exit(0)

