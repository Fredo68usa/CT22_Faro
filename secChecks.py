import pandas as pd
import sqlite3
from elasticsearch import Elasticsearch, helpers
import json


class secChecks:


  def __init__(self,loc_param, param_json):

     # --- parameter file
     # --- Getting parameters from Param File
     with open(param_json) as f:
         self.param_data = json.load(f)

     self.esServer = self.param_data["ESServer"]
     self.esUser = self.param_data["ESUser"]
     self.esPwd = self.param_data["ESPwd"]

     # --- Access sqlite
     self.conn = sqlite3.connect(loc_param)
     self.cursor = self.conn.cursor()

     # --- Get the Preds ---- 
     self.cursor.execute('SELECT * FROM preds LIMIT 1500')
     data = self.cursor.fetchall()
     column_names = [description[0] for description in self.cursor.description]
     self.df_preds = pd.DataFrame(data, columns=column_names)
     print(self.df_preds)

     # --- Access ElasticSearch
     self.es = Elasticsearch([self.esServer], http_auth=(self.esUser, self.esPwd))
     


  def checkPred(self,hsh,year, doy ):

     # ---- Get the current Extraction in sqlite and the pred in the DataFrame
     # ---- Read sqlite for the current amount of extraction on that day as recorded in SQLite
     selectSQLs_query = """SELECT * from extracts  WHERE hash = ? and year = ? and dayofyear = ?"""
     hash_2 = hsh
     year_2 = str(year)
     doy_2 = str(doy)
     self.cursor.execute(selectSQLs_query, (hash_2,year_2, doy_2,))
     self.listextractsSQLs = self.cursor.fetchall()
     column_names = [description[0] for description in self.cursor.description]
     df_extract = pd.DataFrame(self.listextractsSQLs, columns=column_names)
     print(df_extract)
     # return()

     # ---- Match the Pred
     pred = self.df_preds[(self.df_preds['hash']==hsh) & (self.df_preds['year']==year) & (self.df_preds['dayofyear']==doy)]
     if (self.df_preds['preds'][0] * 1.05) >= df_extract['extract'][0]:
         return()
     else:
     # --- Record Excess in Elastic
         self.es.index(
            index='excess-extract',
            document={
                'hash': hsh,
                'year': year,
                'dayofyear': doy
                })


         # --- Send an Alert



