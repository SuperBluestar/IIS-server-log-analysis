# -*- coding: utf-8 -*-
"""
Created on Sun Apr 11 02:37:10 2021

@author: Lucy
"""


import os
import zipfile
import pathlib
from dateutil.parser import parse
from datetime import datetime
import calendar
import numpy as np
from mysql.connector import connect, Error
import mysql.connector
from ip2geotools.databases.noncommercial import DbIpCity

# If you want to format db and install, set reset value as true
reset = False
g_myhost = "localhost"
g_myusername = "root"
g_mypassword = ""

g_dir_name = "logs"

g_extensions = ['.aspx','.jpg','shtml','git','css','txt','html','png','uk', '.php']
g_countries = ['US','UK','Qatar','Netherlands','Finland','Australia','Germany','Sweden','Belgium']
g_cities = ['Vienna, Virgini','Palo Alto, Cali','Schaumburg, ill','Norwalk, Conner','Falls Church, V','Boca Raton, Flo','Medofrd, Oredon','San Francisco','San Francisco','Redmond, Washin']
g_timesteps = [0.01,0.02,0.05,0.1,0.2,0.5,1,2,5,1000]
g_errors = ['404','406','403','303','304']
g_oss = ['Windows','known robots','OS known','Macintosh', 'others']
g_browsers = ['MSIE','Netscape','Firefox','msnbot', 'panscient.com', 'Baiduspider', 'Yandex', 'Safari', 'Sogou web spyder', 'others']
g_hosts = ['66.249.65.241','66.249.65.245','66.249.65.9','66.249.65.44', '67.195.110.170', '67.195.111.153', '72.14.164.169', '77.88.43.25', '131.111.37.76', '213.120.115.56','others']

g_mysql_db_name = "pydb_log_analysis"
g_tbl_dfe_req = "tbl_dfe_reqs"
g_tbl_users_per_visits = "tbl_users_per_visits"
g_tbl_focus_url = "tbl_focus_url"
g_tbl_active_countries = "tbl_active_countries"
g_tbl_active_cities = "tbl_active_cities"
g_tbl_year_reqs = "tbl_year_reqs"
g_tbl_monthp_reqs = "tbl_monthp_reqs"
g_tbl_month_reqs = "tbl_month_reqs"
g_tbl_date_reqs = "tbl_date_reqs"
g_tbl_weekday_reqs = "tbl_weekday_reqs"
g_tbl_hour_reqs = "tbl_hour_reqs"
g_tbl_timetaken = "tbl_timetaken"
g_tbl_client_error = "tbl_client_error"
g_tbl_os_info = "tbl_os_info"
g_tbl_browser_info = "tbl_browser_info"
g_tbl_host_info = "tbl_host_info"

g_focused_page ={
            '/Darwin/Place.aspx',
            '/Darwin/Home.aspx',
            '/Darwin/Plant.aspx',
            '/Darwin/PlantIndex.aspx',
            '/Darwin/style.css',
            '/Darwin/ImageIframe.aspx',
            '/Darwin/Page.aspx',
            '/Darwin/Image.aspx',
            '/Darwin/MyAccount.aspx',
            '/darwin/plant.aspx',
            '/darwin/myaccount.aspx"',
            '/darwin/image.aspx',
            '/darwin/place.aspx',
            '/getimageex.aspx',
            '/darwin/style.css',
            '/darwin/home.aspx',
            '/darwin/header.jpg',
            '/darwin/culogo.gif',
            '/darwin/print.css',
            '/favicon.ico',
            '/robots.txt',
            'others',
        }

def is_date(string, fuzzy=False):
    """
    Return whether the string can be interpreted as a date.

    :param string: str, string to check for date
    :param fuzzy: bool, ignore unknown tokens in string if True
    """
    try: 
        parse(string, fuzzy=fuzzy)
        return True

    except ValueError:
        return False

def leap_year(year):
    if year % 400 == 0:
        return True
    if year % 100 == 0:
        return False
    if year % 4 == 0:
        return True
    return False

def days_in_month(month, year):
    if month in {1, 3, 5, 7, 8, 10, 12}:
        return 31
    if month == 2:
        if leap_year(year):
            return 29
        return 28
    return 30

# Obj of total zipped files
class node():
    def __init__(self, path, depth = 0):
        self.path = path;
        self.depth = depth;
        self.sub_dir = [];
        self.sub_file = [];
        self.set_sub_dirs();
    
    def set_sub_dirs(self):
        if not os.path.isdir(self.path):
            return
        subpath_list = os.listdir(self.path)
        for subpath in subpath_list:
            if os.path.isfile(self.path + '\\' + subpath) == True:
                self.sub_file.append(self.path + '\\' + subpath)
            elif os.path.isdir(self.path + '\\' + subpath) == True:
                self.sub_dir.append(node(path = self.path + '\\' + subpath, depth = self.depth + 1))
                
                
    def explorer(self):
        for sub_dir_node in self.sub_dir:
            sub_dir_node.explorer()
        for sub_file_node in self.sub_file:
            self.extract_load(sub_file_node)
            
    def extract_load(self, path):
        if '.zip' == pathlib.Path(path).suffix:
            zf = zipfile.ZipFile(path)
            for info in zf.infolist():
                content = zf.read(info.filename)
                for txt_line in content.splitlines():
                    logdataObj.analysis_one(txt_line)
            zf.close()
    
# Obj to store all data of log
class logdataObj():
    def __init__(self):
        self.logdatalines = []
        self.prev_date = ""
        self.pages_perday = []
        self.users = {}
        self.dates = {}
        self.dates_pages = {}
        
    # txt_line : each line of log files
    def analysis_one(self, txt_line):
        items = txt_line.split()
        
        # date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
        # 2010-04-23 
        # 00:02:02 
        # 134.36.36.75 
        # GET 
        # /Darwin/Plant.aspx 
        # p=25&ix=344&pid=8&prcid=26&ppid=1502 
        # 80 
        # - 
        # 67.195.110.170 
        # Mozilla/5.0+(compatible;+Yahoo!+Slurp/3.0;+http://help.yahoo.com/help/us/ysearch/slurp) 
        # 200 
        # 0 
        # 0 
        # 651
            
        if len(items) > 13 and is_date(items[0]):
            # To get users
            if items[7].decode('utf-8') != '-' and items[7].decode('utf-8') not in self.users.keys():
                self.users[items[7].decode('utf-8')] = 0
            
            # To get pages and requests of everydays BEGIN
            # 
            if self.prev_date == "":
                self.prev_date = items[0].decode('utf-8')
            elif self.prev_date != items[0].decode('utf-8'):
                self.pages_perday = []

            if items[0].decode('utf-8') not in self.dates.keys():
                self.dates[items[0].decode('utf-8')] = 1
            else:
                self.dates[items[0].decode('utf-8')] += 1

            logdataObjs1 = []
            for exten_page in ['.aspx','.php']:
                logdataObjs1.append(exten_page in str(items[4]))
            if any(logdataObjs1):
                if str(items[4]) not in self.pages_perday:
                    self.pages_perday.append(str(items[4]))
                    self.dates_pages[items[0].decode('utf-8')] = 1
                else:
                    self.dates_pages[items[0].decode('utf-8')] += 1
            # To get pages and requests of everydays END
                    
            # save read data to structured variable
            self.logdatalines.append({
                "date": items[0],
                "time": items[1],
                "sip": items[2],
                "csmethod": items[3],
                "csuristem": items[4].decode('utf-8'),
                "csuriquery": items[5],
                "sport": items[6],
                "csusername": items[7].decode('utf-8'),
                "cip": items[8],
                "csuseragent": items[9],
                "scstatus": items[10],
                "scsubstatus": items[11],
                "scwin32status": items[12],
                "timetaken": items[13],
            })
        return
    
    # count reqs and timetaken of special extensions
    def downloaded_filetypes(self):
        extens_reqs = {}
        extens_timetaken = {}
        for extension in g_extensions:
            extens_reqs[extension] = 0
            extens_timetaken[extension] = 0
        for item in self.logdatalines:
            pageurl = str(item["csuristem"])
            for exten in extens_reqs.keys():
                if pageurl.endswith(exten):
                    extens_reqs[exten] += 1
                    extens_timetaken[exten] += int(item["timetaken"])
        
        return extens_reqs, extens_timetaken
    
    # count special pages
    def focused_url_analysis(self):
        specials = {}
        specials404 = {}
        for page in g_focused_page:
            specials[page] = 0
            specials404[page] = 0
        for item in self.logdatalines:
            pageurl = str(item["csuristem"])
            others = True
            for page in specials.keys():
                if page in pageurl:
                    specials[page] += 1
                    if item["scstatus"] == 404:
                        specials404[page] += 1
                    others = False
            if others:
                specials['others'] += 1
                if item["scstatus"] == 404:
                    specials404['others'] += 1
        
        return specials, specials404
        
    # get number of users per number of visits
    def getUsersPerVisits(self):
        for item in self.logdatalines:
            for user in self.users.keys():
                if item["csusername"] == user:
                    self.users[user] += 1

        visits = [*range(1,11)]
        userspervisit = {}
        for visit in visits:
            for uservs in self.users:
                if visit == self.users[uservs]:
                    if str(visit) in userspervisit.keys():
                        userspervisit[str(visit)] += 1
                    else:
                        userspervisit[str(visit)] = 1

        return userspervisit

    # get active countries
    def getActiveCountries(self):
        activecountries = {}
        for country in g_countries:
            activecountries[country] = 0
        for item in self.logdatalines:
            country1 = DbIpCity.get(item["cip"], api_key='free').country
            for country in g_countries:
                if country1 == country:
                    activecountries[country] += 1

        return activecountries

    # get active cities
    def getActiveCities(self):
        activecities = {}
        for city in g_cities:
            activecities[city] = 0
        for item in self.logdatalines:
            city1 = DbIpCity.get(item["cip"], api_key='free').city
            for city in g_cities:
                if city1 == city:
                    activecities[city] += 1

        return activecities

    # get avaliable
    def get_year(self):
        year_start = 4000
        year_end = 0
        for item in self.logdatalines:
            year = parse(item["date"]).year
            if year < year_start:
                year_start = year
                if year_end == 0:
                    year_end = year
            if year > year_start:
                year_end = year
        return year_start, year_end
    
    # get requests and pages definite period
    # year: definited year
    #       ex] year = 2009
    # fmonth: start month
    # tmonth: end month
    def get_req_pages_year_month(self, year, fmonth = 1, tmonth = 12):
        cnt_request = 0
        cnt_pages = 0
        if fmonth < 10:
            fmonth1 = "0" + str(fmonth)
        else: 
            fmonth1 = fmonth
        if tmonth < 10:
            tmonth1 = "0" + str(tmonth)
        else: 
            tmonth1 = tmonth
        str_fdate = str(days_in_month(fmonth,year)) + "/" + str(fmonth1) + "/" + str(year)
        str_tdate = str(days_in_month(tmonth,year)) + "/" + str(tmonth1) + "/" + str(year)
        str_fdate_obj = datetime.strptime(str_fdate, '%d/%m/%Y')
        str_tdate_obj = datetime.strptime(str_tdate, '%d/%m/%Y')
        for item in self.logdatalines:
            date_obj = parse(item["date"]).date()
            if date_obj > str_fdate_obj.date() and date_obj < str_tdate_obj.date():
                cnt_request += 1
                if ".aspx" in str(item["csuristem"]):
                    cnt_pages += 1
                    
        return cnt_request, cnt_pages
    
    # get activity levels on weekdays
    def getActivitiesWeekday(self):
        cnt_week = np.zeros(7)
        for item in self.logdatalines:
            date_obj = parse(item["date"]).date()
            weekday = calendar.weekday( date_obj.year, date_obj.month, date_obj.day)
            if weekday >= 0 and weekday <= 6:
                cnt_week[weekday] += 1
                
        return cnt_week
    
    # get activity levels of hours a day
    def getActivitiesOfHour(self):
        hours = [*range(0,24)]
        activities_hours = np.zeros(24)
        for item in self.logdatalines:
            time_obj = parse(item["time"]).time()
            for hour in hours:
                if time_obj.hour == hour:
                    activities_hours[hour] += 1
        
        return activities_hours
    
    # get time_taken 
    def getTimeTaken(self):
        timesteps = g_timesteps
        cnt_timesteps = [*range(0,10)]
        for item in self.logdatalines:
            try:
                timetaken = int(item["timetaken"])/1000
            except (TypeError, ValueError):
                timetaken = 0
            else:
                timetaken = 0
            timestep = 0
            for timestep in timesteps:
                if timetaken > timestep:
                    break
            num = timesteps.index(timestep)
            cnt_timesteps[num] += 1
        
        return cnt_timesteps
    
    # count errors of request
    def getClientErrors(self):
        errors = {}
        for errorcode in g_errors:
            errors[errorcode] = 0
        for item in self.logdatalines:
            try:
                status = int(item["scstatus"])
            except:
                status = 404
            else:
                status = 404
            for key in errors.keys():
                if str(status) == str(key):
                    errors[key] += 1
    
        return errors
    
    # get os information
    def getOsInfo(self):
        oss = {}
        for osi in g_oss:
            oss[osi] = 0
        for item in self.logdatalines:
            agency = str(item["csuseragent"])
            others = True
            for key in oss.keys():
                if key in (agency):
                    oss[key] += 1
                    others = False
            if others:
                oss['others'] += 1
    
        return oss
    
    # get browser information
    def getBrowserInfo(self):
        browsers = {}
        for browser in g_browsers:
            browsers[browser] = 0
        for item in self.logdatalines:
            agency = str(item["csuseragent"])
            others = True
            for key in browsers.keys():
                if key in (agency):
                    browsers[key] += 1
                    others = False
            if others:
                browsers['others'] += 1
    
        return browsers
        
    # get host information
    def getHostInfo(self):
        hosts = {}
        for host in g_hosts:
            hosts[host] = 0
        for item in self.logdatalines:
            host = str(item["cip"])
            others = True
            for key in hosts.keys():
                if key in (host):
                    hosts[key] += 1
                    others = False
            if others:
                hosts['others'] += 1
    
        return hosts
 
logdataObj = logdataObj()

class mysql_ctrl():
    def __init__(self, conn, db_name):
        self.conn = conn
        self.mycursor = conn.cursor()
        # create database
        query = "CREATE DATABASE IF NOT EXISTS  " + db_name
        self.mycursor.execute(query)
        # select database
        query = "USE " + db_name
        self.mycursor.execute(query)

    def execute(self, query = ""):
        self.mycursor.execute(query)
        self.conn.commit()

    def disconnect(self):
        self.conn.disconnect()


def main():
    # get data
    dir_name = os.getcwd()
    if g_dir_name != "":
        dir_name = g_dir_name
    current_node = node(path=dir_name)
    current_node.explorer()
    
    if len(logdataObj.logdatalines) == 0:
        print("No data")
        return

    # mysql coding START
    try:
        with connect(
            host=g_myhost,
            user=g_myusername,
            password=g_mypassword,
        ) as connection:
            myconn = mysql_ctrl(conn = connection, db_name = g_mysql_db_name)

            if reset:
                # create table and insert data
                query = "DROP TABLE IF EXISTS " + g_tbl_dfe_req + ", " + g_tbl_users_per_visits + ", " + g_tbl_focus_url + ", " + g_tbl_active_countries + ",\
                    " + g_tbl_active_cities + ", " + g_tbl_year_reqs + ", " + g_tbl_year_reqs + ", " + g_tbl_monthp_reqs + ", " + g_tbl_month_reqs + ", " + g_tbl_date_reqs + ", \
                        " + g_tbl_weekday_reqs + ", " + g_tbl_hour_reqs + ", " + g_tbl_timetaken + ", " + g_tbl_client_error + ", " + g_tbl_os_info + ", " + g_tbl_browser_info + ", " + g_tbl_host_info + ""
                myconn.execute(query)

            # analysis start
            # analysis download filetypes
            dfe_reqs, dfe_ttakens = logdataObj.downloaded_filetypes()
            totaltime = sum(dfe_ttakens.values())
            
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_dfe_req + " (\
                        extension VARCHAR(255), \
                        reqs TINYINT NOT NULL, \
                        tpercent FLOAT NOT NULL \
                    )"
            myconn.execute(query)
            for exten in dfe_reqs.keys():
                query = "INSERT INTO " + g_tbl_dfe_req + " \
                    (extension, reqs, tpercent) VALUES \
                        ('" + str(exten) + "','" + str(dfe_reqs[exten]) + "','" + str(dfe_ttakens[exten]/totaltime) + "')"
                myconn.execute(query)

            # analysis number of users per number of visits
            userspervisits = logdataObj.getUsersPerVisits()

            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_users_per_visits + " (\
                        visits VARCHAR(255), \
                        users TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for visits in userspervisits.keys():
                query = "INSERT INTO " + g_tbl_users_per_visits + " \
                    (visits, users) VALUES \
                        ('" + str(visits) + "','" + str(userspervisits[visits]) + "')"
                myconn.execute(query)
            
            # focused pages
            cnt_fpages, cnt_fpages_404 = logdataObj.focused_url_analysis()

            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_focus_url + " (\
                        url VARCHAR(255), \
                        reqs TINYINT NOT NULL, \
                        req404 TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for page in cnt_fpages.keys():
                query = "INSERT INTO " + g_tbl_focus_url + " \
                    (url, reqs, req404) VALUES \
                        ('" + str(page) + "','" + str(cnt_fpages[page]) + "','" + str(cnt_fpages_404[page]) + "')"
                myconn.execute(query)

            # active countries
            cnt_active_countries = logdataObj.getActiveCountries()

            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_active_countries + " (\
                        country VARCHAR(255), \
                        reqs TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for country in cnt_active_countries.keys():
                query = "INSERT INTO " + g_tbl_active_countries + " \
                    (country, reqs) VALUES \
                        ('" + str(country) + "','" + str(cnt_active_countries[country]) + "')"
                myconn.execute(query)
                
            # active cities
            cnt_active_cities = logdataObj.getActiveCities()

            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_active_cities + " (\
                        city VARCHAR(255), \
                        reqs TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for page in cnt_active_cities.keys():
                query = "INSERT INTO " + g_tbl_active_cities + " \
                    (city, reqs) VALUES \
                        ('" + str(page) + "','" + str(cnt_active_cities[page]) + "')"
                myconn.execute(query)

            # requests of year and month
            yfrom, yto = logdataObj.get_year()
            yearrequests = {} 
            yearpages = {}
            monthrequests = {}
            monthpages = {}
            for i in range(yto - yfrom + 1):
                cnt_oneyrequest, cnt_oneypages = logdataObj.get_req_pages_year_month(i + yfrom)
                yearrequests[str(i+yfrom)] = (cnt_oneyrequest)
                yearpages[str(i+yfrom)] = (cnt_oneyrequest)
                    
                months = [*range(0,11)]
                for j in months:
                    cnt_onemrequest, cnt_onempages = logdataObj.get_req_pages_year_month(i + yfrom, j + 1, j + 2)
                    monthrequests[str(i + yfrom) + '/' + str(j+1)] = cnt_onemrequest
                    monthpages[str(i + yfrom) + '/' + str(j+1)] = cnt_onempages

            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_year_reqs + " (\
                        year VARCHAR(255), \
                        reqs TINYINT NOT NULL, \
                        pages TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for year in yearrequests.keys():
                query = "INSERT INTO " + g_tbl_year_reqs + " \
                    (year, reqs, pages) VALUES \
                        ('" + str(year) + "','" + str(yearrequests[year]) + "','" + str(yearpages[year]) + "')"
                myconn.execute(query)
                
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_month_reqs + " (\
                        month VARCHAR(255), \
                        reqs TINYINT NOT NULL, \
                        pages TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for month in monthrequests.keys():
                query = "INSERT INTO " + g_tbl_month_reqs + " \
                    (month, reqs, pages) VALUES \
                        ('" + str(month) + "','" + str(monthrequests[month]) + "','" + str(monthpages[month]) + "')"
                myconn.execute(query)

            # get request of dates
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_date_reqs + " (\
                        date VARCHAR(255), \
                        reqs TINYINT NOT NULL, \
                        pages TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for mdate in logdataObj.dates.keys():
                query = "INSERT INTO " + g_tbl_date_reqs + " \
                    (date, reqs, pages) VALUES \
                        ('" + str(mdate) + "','" + str(logdataObj.dates[mdate]) + "','" + str(logdataObj.dates_pages[mdate]) + "')"
                myconn.execute(query)
            
            # get activities of weekday
            weekdays = logdataObj.getActivitiesWeekday()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_weekday_reqs + " (\
                        weekday TINYINT NOT NULL, \
                        users TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for weekday in range(0,7):
                query = "INSERT INTO " + g_tbl_weekday_reqs + " \
                    (weekday, users) VALUES \
                        ('" + str(weekday) + "','" + str(weekdays[weekday]) + "')"
                myconn.execute(query)

            # get activities of hours
            activities_hours = logdataObj.getActivitiesOfHour()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_hour_reqs + " (\
                        hour TINYINT NOT NULL, \
                        users TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for hour in range(0,24):
                query = "INSERT INTO " + g_tbl_hour_reqs + " \
                    (hour, users) VALUES \
                        ('" + str(hour + 1) + "','" + str(activities_hours[hour]) + "')"
                myconn.execute(query)

            # get timetaken
            timetakens = logdataObj.getTimeTaken()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_timetaken + " (\
                        timestep VARCHAR(255), \
                        reqs TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for step in range(0,len(g_timesteps)):
                query = "INSERT INTO " + g_tbl_timetaken + " \
                    (timestep, reqs) VALUES \
                        ('" + str(g_timesteps[step]) + "~" + "','" + str(timetakens[step]) + "')"
                myconn.execute(query)

            # get client errors
            cnt_errors = logdataObj.getClientErrors()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_client_error + " (\
                        errorcode VARCHAR(255), \
                        counts TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for errorcode in cnt_errors.keys():
                query = "INSERT INTO " + g_tbl_client_error + " \
                    (errorcode, counts) VALUES \
                        ('" + str(errorcode) + "~" + "','" + str(cnt_errors[errorcode]) + "')"
                myconn.execute(query)

            # get os info
            osinfo = logdataObj.getOsInfo()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_os_info + " (\
                        os VARCHAR(255), \
                        reqs TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for osi in osinfo.keys():
                query = "INSERT INTO " + g_tbl_os_info + " \
                    (os, reqs) VALUES \
                        ('" + str(osi) + "~" + "','" + str(osinfo[osi]) + "')"
                myconn.execute(query)

            # get browser info
            browserinfo = logdataObj.getBrowserInfo()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_browser_info + " (\
                        browser VARCHAR(255), \
                        reqs TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for browser in browserinfo.keys():
                query = "INSERT INTO " + g_tbl_browser_info + " \
                    (browser, reqs) VALUES \
                        ('" + str(browser) + "~" + "','" + str(browserinfo[browser]) + "')"
                myconn.execute(query)

            # get browser info
            hostinfo = logdataObj.getHostInfo()
            query = "CREATE TABLE IF NOT EXISTS " + g_tbl_host_info + " (\
                        host VARCHAR(255), \
                        reqs TINYINT NOT NULL \
                    )"
            myconn.execute(query)
            for host in hostinfo.keys():
                query = "INSERT INTO " + g_tbl_host_info + " \
                    (host, reqs) VALUES \
                        ('" + str(host) + "~" + "','" + str(hostinfo[host]) + "')"
                myconn.execute(query)
    
            myconn.disconnect()

    except Error as e:
        print(e)
    
    print("Finished")
    return
    

if __name__ == '__main__':
    main()
    