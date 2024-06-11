import sqlite3
import pandas as pd


class MetaData :


  def __init__(self,loc_param):


    # conn = sqlite3.connect('sqlite/sqlitect22')
    self.conn = sqlite3.connect(loc_param)

    self.cursor = self.conn.cursor()

  def readsqlstowatchTable(self):
     self.cursor.execute('SELECT * FROM sqlstowatch LIMIT 1000')
     data = self.cursor.fetchall()
     column_names = [description[0] for description in self.cursor.description]
     df_sqlstowatch = pd.DataFrame(data, columns=column_names)
     # print (df_guardecs)
     return (df_sqlstowatch)

  def readguardecsTable(self):
     self.cursor.execute('SELECT * FROM guardecs LIMIT 1000')
     data = self.cursor.fetchall()
     column_names = [description[0] for description in self.cursor.description]
     df_guardecs = pd.DataFrame(data, columns=column_names)
     # print (df_guardecs)
     return (df_guardecs)

  def get_seltyp(self):
    # --- DB Users
    select_seltyp = """ Select * from seltyp"""
    self.cursor.execute(select_seltyp)
    ListSeltyp = self.cursor.fetchall()
    # print (ListSeltyp)
    column_names = [description[0] for description in self.cursor.description]
    df_seltyp = pd.DataFrame(ListSeltyp, columns=column_names)
    # print (df_seltyp)
    return(df_seltyp)


  def get_Agents(self):

    select_staps = """ Select * from staps"""
    # --- Staps
    self.cursor.execute(select_staps)
    ListStaps = self.cursor.fetchall()
    # print (ListStaps)
    column_names = [description[0] for description in self.cursor.description]
    df_staps = pd.DataFrame(ListStaps, columns=column_names)
    # print (df_staps)
    return(df_staps)

  def get_Colls(self):
    # --- Colls
    select_colls = """ Select * from colls"""
    self.cursor.execute(select_colls)
    ListColls = self.cursor.fetchall()
    # print (ListColls)
    column_names = [description[0] for description in self.cursor.description]
    # print (column_names)
    df_colls = pd.DataFrame(ListColls , columns=column_names)
    # print (df_colls)
    return(df_colls)
    # exit(0)

  def get_DBUsers(self):
    # --- DB Users
    select_staps = """ Select * from dbusers"""
    self.cursor.execute(select_staps)
    ListDBUsers = self.cursor.fetchall()
    # print (ListStaps)
    column_names = [description[0] for description in self.cursor.description]
    df_dbusers = pd.DataFrame(ListDBUsers, columns=column_names)
    # print (df_dbusers)
    return(df_dbusers)

  def get_nodes(self):
    # --- Nodes
    select_nodes = """ Select * from nodes"""
    self.cursor.execute(select_nodes)
    ListNodes = self.cursor.fetchall()
    # print (ListStaps)
    column_names = [description[0] for description in self.cursor.description]
    df_nodes = pd.DataFrame(ListNodes, columns=column_names)
    # print (df_nodes)
    return(df_nodes)

  def get_predsTable(self):
    # --- Preds
    select_nodes = """ Select * from preds"""
    self.cursor.execute(select_nodes)
    ListPreds = self.cursor.fetchall()
    print (ListPreds)
    column_names = [description[0] for description in self.cursor.description]
    df_preds = pd.DataFrame(ListPreds, columns=column_names)
    print (df_preds)
    return(df_preds)


