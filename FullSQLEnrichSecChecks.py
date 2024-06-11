import sys
import pdb
from icecream import ic
import Extractions as ec
import json
import os
from elasticsearch import Elasticsearch, helpers
import pandas as pd
import metadata
import glob
import time               # For Performance Timing
import datetime as dt     # For Time Manipulation
import hashlib
import calendar



class EnrichFullSQLES:



  # --- Constructor ------
  def __init__(self,param_json):

    # self.process = psutil.Process(os.getpid())
    self.collector = str(sys.argv[1])

    # --- Getting parameters from Param File
    with open(param_json) as f:
         self.param_data = json.load(f)

    self.path = self.param_data["path"]
    self.pathlength=len(self.path)
    self.pathProcessed = self.param_data["pathProcessed"]
    self.confidentialityPolicyRule = self.param_data["confidentialityPolicyRule"]
    self.datafileNotinserted=self.pathProcessed + "NotInserted"

    self.esServer = self.param_data["ESServer"]
    self.esUser = self.param_data["ESUser"]
    self.esPwd = self.param_data["ESPwd"]

    self.ExcessiveExtractionCheck = self.param_data["ExcessiveExtractionCheck"]
    self.ecsCompatibility = self.param_data["ecsCompatibility"]

    self.es = Elasticsearch([self.esServer], http_auth=(self.esUser, self.esPwd))

    self.index = self.param_data["index"]
    self.sqlite = self.param_data["sqlite"]
    print('Number of arguments:', len(sys.argv), 'arguments.')
    print('Argument List:', str(sys.argv))

    # --- Set up the Kanban - Semaphore for "Process in progress"
    self.InProg = self.path + 'FullSQL_Enrichment_In_Progress_'+ self.collector
    if os.path.exists(self.InProg) == True :
       print ('Process in Progress - Exiting')
       exit(0)
    else:
       os.system('touch ' + self.InProg)

    # --- Initialization of Arrays
    self.fullSQLMany=[]
    self.DAMDataRec=[]
    field_list=[]
    self.SonarGSource = None
    self.myListAuthConn = []

    self.myListIPs = []
    self.myListDBUsers = []
    self.myListSrcPrg = []
    self.myListSelectType = []
    self.myListCommands = []
    self.myListAuthConn = []
    self.nodesList = []
    self.line = 0
    self.df_guardecs = []

    # --- Instantiation of ec.UpdateSqlCounters for Detection of Excessive Extractions
    self.p1 = ec.UpdateSqlCounters(self.sqlite)

    self.anomalyDF = pd.DataFrame(columns=['hash','Qty','Year','DayOfWeek','Timestamp','Threshold'])

    # print ("ec : " , dir( ec))
    # print ("self.p1 : " , dir(self.p1))
    # print(inspect.getmembers(OptionParser, predicate=inspect.isfunction))



  # -----------------------------
  #       MAIN PROCESS
  # -----------------------------

  def mainProcess(self):
    print("Start Full SQL ES Enrichment")

    # ---- Get All Metadata
    self.GetMetaData()


    # ---- Get list of files
    DataFiles = self.DataFile_List()
    print ('Nbr of Files to Process : ' , len(DataFiles))
    if len(DataFiles) == 0 :
       print ("NO file to process for Coll : " , self.collector)
       os.system('rm -f ' + self.InProg)
       exit(0)

    # ---- Process ALL  file
    self.process_all_files(DataFiles)

    print("End of Full SQL ES Enrichment")

  # --- Getting the Metadata  ----
  def GetMetaData(self):

    p1=metadata.MetaData(self.sqlite)

    print ("In MetaData")
    # ---- Get A_IPs
    # print(myListIPs)
    self.myListIPs = p1.get_nodes()
    # print(type(self.myListIPs), " -- " ,self.myListIPs)
    # self.nodesList = self.myListIPs.columns.values.tolist()

    # ---- Get A_DB_USERS
    self.myListDBUsers = p1.get_DBUsers()
    # print(type(self.myListDBUsers), " -- " , self.myListDBUsers)

    # ---- Get A_SEL_TYP
    # print(myListSelectType)
    self.myListSeltyp = p1.get_seltyp()
    # breakpoint()

    # ---- Get ecs mapping
    self.df_guardecs=p1.readguardecsTable()
    # print(type(self.df_guardecs), " -- " , self.df_guardecs)

    # ---- Get sqls to watch
    self.df_sqlstowatch=p1.readsqlstowatchTable()
    # print(type(self.df_guardecs), " -- " , self.df_guardecs)

    # ---- Get preds
    self.df_preds=p1.get_predsTable()
    # print(type(self.df_preds), " -- " , self.df_preds)

    # breakpoint()

    return()


  # --- Getting the DAM Files to be Processed  ----
  def DataFile_List(self):
    DataFile=[]
    DataFiles=[]
    csvFiles=glob.glob(self.path + "*" + self.collector + "*FSQL*.csv")
    for file in csvFiles:
       if "FSQL" in file:
         COLL = file.split('_')[1]
         DataFile.append(COLL)
         DataFile.append(file)
         DataFiles.append(DataFile)
         DataFile=[]
    return (DataFiles)

  # --- insert_many_Elastic
  def insert_many_Elastic(self):
      # print (self.fullSQLMany)
      # breakpoint()
      try:
           # response = helpers.bulk(self.es,self.fullSQLMany, index='enriched_full_sql')
           response = helpers.bulk(self.es,self.fullSQLMany, index=self.index)
           print ("\nRESPONSE:", response)
      except Exception as e:
           print("\nERROR in insert many Elastic:", e)

  # --- Process All Files
  def process_all_files(self,DataFiles):
    # --- Loop for each DAM data file
    for datafile in DataFiles:
        print('Will be Processing : ',datafile)
        os.system('printf "' + datafile[1] + '\n" >> ' + self.InProg )
        self.SonarGSource =  datafile[0]

        # -- Process One File
        self.fullSQLMany=[]
        doc_count=self.process_one_file(datafile)

        # -- Upload into ES (ETL)
        print("Nbr of Docs to be Inserted", doc_count)
        # print (" list SQLCounters ALL FILES " , self.p1.listSqlCounters)
        if doc_count > 0 :
           # --- insert enrich full sql
           self.insert_many_Elastic()
           # --- Update counters of Extraction
           # self.p1.write_PosGres()
           # --- insert anomaly of extractions
           # self.insert_many_Elastic_excess()

        os.system('rm -f ' + self.InProg)

        self.rename_file(datafile)

  def process_one_file(self,datafile):
        print ('Processing' , datafile)
        # --- Initialization
        doc_count=0
        self.fullSQLMany=[]
        self.DAMDataRec=[]
        # --- Getting the file and put them into a DataFrame
        csv_file = datafile[1]
        df = pd.read_csv (csv_file)
        df.rename(columns={ df.columns[0]: "UTC Offset" }, inplace = True)
        df = df.fillna("")
        self.field_list=df.columns

        for i in range(df.shape[0]):
            line = df.iloc[[i]]
            # print (type(line), " -- " , line )
            self.process_one_line(line)

        return(len(self.fullSQLMany))

  # ------ Process One Line ------
  def process_one_line(self,line):

         if line.shape[1] != 29 :
            print ('Wrong Line')
            return()
         if line.iloc[0]['Access Rule Description'] != self.confidentialityPolicyRule :
            print ('Wrong Policy')
            return()

         # Convert the DataFrame to a dictionary, using the 'records' orient
         lineDict = line.to_dict(orient='records')[0]

         lineDict['SonarG Source']=self.SonarGSource
         item_count = 0

         # ---- Call to enrich 1 line ----
         line_meta = self.enrich_one_line(lineDict)

         # print (line_meta)
         # breakpoint()
         # Conversion to ecs before adding to the lines to be recorded
         if self.ecsCompatibility == True:
            line_meta=self.rename_ecs(line_meta)

         self.fullSQLMany.append(line_meta)

         return()

  def enrich_one_line(self,line_meta):
      # -- Conversion into Integers -----
      line_meta['Records Affected']=int(line_meta['Records Affected'])
      line_meta['Response Time']=int(line_meta['Response Time'])
      # --- Timestamp to be converted into UTC time
      ts = line_meta['Timestamp']
      utc_h = int(line_meta["UTC Offset"])
      new_ts=dt.datetime.strptime(ts[:19],'%Y-%m-%dT%H:%M:%S')
      line_meta['Timestamp'] = new_ts - dt.timedelta(hours=utc_h)

      # --- Timestamp to be converted into UTC time
      ts = line_meta['Session Start']
      new_ts=dt.datetime.strptime(ts[:19],'%Y-%m-%dT%H:%M:%S')
      line_meta['Session Start'] = new_ts - dt.timedelta(hours=utc_h)
      # print ('utc_h' , utc_h, "ts : " , ts, "new ts : " , lineDict['Session Start'] )

      # --- Enrichment of the Line as a Dctionary
      line_meta = self.enrich_by_metadata(line_meta)

      # --- Computation of Total extraction per SQL
      # newSQL = [lineDict['HashHash'],lineDict['Records Affected'],lineDict['Year'],lineDict['DayOfYear']]
      # breakpoint()
      if self.ExcessiveExtractionCheck == True :
         # newSQL = [line_meta['HashHash'],line_meta['Records Affected'],line_meta['Year'],line_meta['DayOfYear'],line_meta['Timestamp']]
         # If the SQL in the list of SQLs to be watched ?
         hsh = line_meta['HashHash']
         extract = line_meta['Records Affected']
         year = line_meta['Year']
         doy = line_meta['DayOfYear']
         # breakpoint()
         self.line = self.line + 1

         # --- check whether the SQL is under watch
         sel_sqltowatch = self.df_sqlstowatch[self.df_sqlstowatch['hsh']==hsh]
         # --- if so Update the counter
         if sel_sqltowatch.empty != True :
            res = self.p1.updateExtracts(hsh, year, doy, extract)
            # sel_pred = self.df_preds[self.df_preds['hash']==hsh]
            breakpoint()
            sel_pred = self.df_preds[(self.df_preds['hash']==hsh) & (self.df_preds['year']==year) & (self.df_preds['dayofyear']==doy)]
            if sel_pred.empty != True :
                if (sel_pred['preds'][0] + sel_pred['preds_interval'][0]) <= res:
                    print ("Excessive extractions")
                    line_meta['excess']=res
                    line_meta['Threshold']= sel_pred['preds'][0] + sel_pred['preds_interval'][0]
                    line_meta['pred']=sel_pred['preds'][0]
                    line_meta['pred_interval']=sel_pred['preds_interval'][0]


      return(line_meta)

  # --- Enrich line with Metadata
  def enrich_by_metadata(self,line):
    # --- To Be Done 
    line = self.enrich_server(line)
    line = self.enrich_client(line)
    line = self.enrich_Sel_Type(line)

    line = self.enrich_DB_User(line)
    line = self.enrich_misc(line)
    # line = self.confidence_level(line)

    return(line)


  def rename_ecs(self,line_meta):

      # ic("In rename ecs ")
      for key in list(line_meta.keys()):
          # If the key is the old label, replace it with the new label
          sel_col = self.df_guardecs[self.df_guardecs["guardium"]==key]["ecs"]
          if sel_col.empty != True :
             # print (type(sel_col),sel_col.iloc[0])
             new_col_name = sel_col.iloc[0]
             # print (new_col_name)
             value = line_meta[key]
             del line_meta[key]
             line_meta[new_col_name] = value

      return(line_meta)

  def enrich_Sel_Type(self,line):

    # --- Select Type
    if "Original SQL" in line:
       # print(len(line['Original SQL']))
       SEL_TYP = line['Original SQL']
    else:
       SEL_TYP = None

    # print("Select Type " , SEL_TYP)
    # sel_metadata = p1.lookup_A_SELECT(SEL_TYP)
    for i in range(0,len(self.myListSeltyp)):
        sel_metadata = self.myListSeltyp[self.myListSeltyp['Select_Type']==SEL_TYP]
        if sel_metadata.empty == False:
            break
    # print('sel_metadata : ' , sel_metadata )
    if sel_metadata.empty == True:
       line["Select Type"] = "Wild - No Restriction -"

    if sel_metadata.empty == False :
       line["Select Type"] = sel_metadata["Comment"]

    # if line["Select Type"] == "Not Peculiar":
    #    sel_metadata = p1.lookup_A_SELECT(SEL_TYP.upper())
    #    line["Select Type"] = sel_metadata

    return(line)


  # ------ Enrich DB User ------
  def enrich_DB_User(self,line):
      # --- DB User
    if "DB User Name" in line:
       DB_USER = line['DB User Name']
       DB_USER_t = DB_USER.split('\\')
       # print ('DB User Split ',DB_USER_t)
       if len(DB_USER_t) > 1:
          DB_USER_2 = DB_USER_t[0] + "&" + DB_USER_t[2]
       else:
          DB_USER_2 = DB_USER
    else:
       DB_USER = None

    db_user_metadata = self.lookup_A_DB_USER(DB_USER)
    db_user_metadata = db_user_metadata.to_dict(orient='records')[0]
    line["DB User Metadata"] = db_user_metadata
    line["DB User Name 2"] = DB_USER_2

    return(line)

  def lookup_A_DB_USER(self,DB_USER):
    if DB_USER != None:
       # print ("Youpi ...",DB_USER)
       select_DBUser = self.myListDBUsers[self.myListDBUsers['DB User Name']==DB_USER]
       return(select_DBUser)
       # breakpoint()

  # ------ Enrich Server ------
  def enrich_server(self,lineDict):
    # --- Server
    # controls to be added fro original in CT22_EK_FullSQL
    # ic( lineDict )
    # ic(self.myListIPs)
    # breakpoint()
    server_metadata = self.myListIPs[self.myListIPs['Hostname']==lineDict['Server Host Name']]
    # ic (select_server)
    if server_metadata.empty == True :
        # --- Return ---
        return(lineDict)
    else:
        server_metadata = server_metadata.to_dict(orient='records')[0]
        # -- Make it a Dict ---
        lineDict["Server Metadata"] = server_metadata
        # --- Return ---
        return(lineDict)

  # ------ Enrich Client ------
  def enrich_client(self,lineDict):
    # --- Server
    # controls to be added fro original in CT22_EK_FullSQL
    # ic( lineDict )
    # ic(self.myListIPs)
    client_metadata = self.myListIPs[self.myListIPs['Hostname']==lineDict['Client Host Name']]
    # ic (client_metadata)
    # breakpoint()
    if client_metadata.empty == True :
        # --- Return ---
        return(lineDict)
    else:
        # -- Make it a Dict ---
        client_metadata = client_metadata.to_dict(orient='records')[0]
        # -- Add meta ---
        lineDict["Client Metadata"] = client_metadata
        # --- Return ---
        return(lineDict)


  # ------ Enrich Miscellaneous ------
  def enrich_misc(self, line_meta):
      # --- MD5
      y = line_meta["Original SQL"]
      result = hashlib.md5(y.encode()).hexdigest()
      line_meta['HashHash'] = result
      line_meta['HashHash User Datastore'] = result+":"+line_meta['DB User Name 2']+":"+line_meta['Server IP']+":"+line_meta['Service Name']+":"+line_meta['Database Name']
      # print(line_meta['HashHash User Datastore'])
      DayOfWeek=line_meta['Timestamp'].weekday()
      line_meta['DayOfWeek']=calendar.day_name[DayOfWeek]
      DayOfYear=line_meta['Timestamp'].timetuple().tm_yday
      line_meta['DayOfYear']=DayOfYear
      WeekOfYear=line_meta['Timestamp'].isocalendar()[1]
      line_meta['WeekOfYear']=WeekOfYear
      Year=line_meta['Timestamp'].year
      line_meta['Year']=Year

     #print(WeekOfYear)
      return (line_meta)


  # --- Move FullSQL csv file to Processed Folder
  def rename_file(self,datafile):

      shortname=datafile[1][self.pathlength:]
      print ("Rename as processed" , shortname)
      os.rename(datafile[1],self.pathProcessed + shortname)


