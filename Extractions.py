import sqlite3
import pandas as pd


class UpdateSqlCounters:

  def __init__(self, loc_param ):

      self.listSqlCounters = []
      self.listsqlstowatch = []

      # Access to sqlite
      self.conn = sqlite3.connect(loc_param)

      self.cursor = self.conn.cursor()

      # --- Verify whether the SQL is under watch
      sqlstowatch_query = """ SELECT * FROM sqlstowatch"""
      self.cursor.execute(sqlstowatch_query)
      self.listsqlstowatch = self.cursor.fetchall()
      column_names = [description[0] for description in self.cursor.description]
      self.df_listsqltowatch = pd.DataFrame(self.listsqlstowatch, columns=column_names)

  def updateExtracts(self, hsh , year , doy, extract):
      # --- Retrieve Corresponding Counter
      selectSQLs_query = """SELECT * from extracts  WHERE hash = ? and year = ? and dayofyear = ?"""
      hash_2 = hsh
      year_2 = str(year)
      doy_2 = str(doy)
      self.cursor.execute(selectSQLs_query, (hash_2,year_2, doy_2,))
      self.listextractsSQLs = self.cursor.fetchall()
      column_names = [description[0] for description in self.cursor.description]
      # breakpoint()
      df_extract = pd.DataFrame(self.listextractsSQLs, columns=column_names)

      # --- the record for extractions on that day doesn't exist
      if df_extract.empty == True :
          # create the Cumul record
          insert_statement = "INSERT INTO extracts (hash, year, dayofyear, extract) VALUES (?, ?, ?, ?)"
          self.cursor.execute(insert_statement, (nextSQLhash, str(year), str(dayofyear), str(extract)))
          # Commit your changes
          self.conn.commit()
      # --- the record exists  needs updating    
      else :
          # --- compute new extract
          newExtract = extract + df_extract['extract'][0]

          # --- lock DB then update record, then commit to unlock (unlock is at this stage optional)
          updateSQLs_query = """UPDATE extracts SET extract = ? WHERE hash = ? and year = ? and dayofyear = ?"""
          self.cursor.execute(updateSQLs_query, (str(newExtract), hash_2,year_2, doy_2,))

          # Commit your changes
          self.conn.commit()

      # --- return
      res=newExtract
      return(res)


