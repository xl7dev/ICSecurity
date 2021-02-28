#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 xl7dev <xl7dev@xl7dev-2.local>
#
# Distributed under terms of the MIT license.

"""
spider ics.cnvd.org.cn
"""

import requests
import re
from lxml import etree
import MySQLdb

def spider():
    conn=MySQLdb.connect(host="127.0.0.1",user="root",passwd="123456",port=8889,db="ICSecurity",charset="utf8")
    cursor = conn.cursor()
    for x in range(10):
    	url = 'http://ics.cnvd.org.cn/?max=100&offset=%d' % (x * 100)
    	response =  requests.get(url)
        print response.status_code,url
    	if response.status_code == 200:
            page = etree.HTML(response.content)
            hrefs = page.xpath('//td/a')
            spans = page.xpath('//td/span')
            times = page.xpath('//tr/td[last()]')
            values = zip(hrefs,spans,times)
            for href,span,time in values:
                #print href.attrib['href']+","+href.attrib['title']+","+span.attrib['class'].replace('red','high').replace('yellow','medium').replace('green','low')+","+(time.text).strip()
                sql = 'insert into ics_cnvd(title,href,level,time) values("%s","%s","%s","%s")' % (href.attrib['title'],href.attrib['href'],span.attrib['class'].replace('red','high').replace('yellow','medium').replace('green','low'),(time.text).strip())
                print sql
                try:
                    cursor.execute(sql)
                    conn.commit()
                except MySQLdb.Error,e:
                    print "Mysql Error %d: %s" % (e.args[0], e.args[1])
    	else:
    	    response =  requests.get(url)
            page = etree.HTML(response.content)
            hrefs = page.xpath('//td/a')
            spans = page.xpath('//td/span')
            times = page.xpath('//tr/td[last()]')
            values = zip(hrefs,spans,times)
            for href,span,time in values:
                #print href.attrib['href']+","+href.attrib['title']+","+span.attrib['class']+","+time.text
                sql = 'insert into ics_cnvd(title,href,level,time) values("%s","%s","%s","%s")' % (href.attrib['title'],href.attrib['href'],span.attrib['class'].replace('red','high').replace('yellow','medium').replace('green','low'),(time.text).strip())
                try:
                    cursor.execute(sql)
                    conn.commit()
                except MySQLdb.Error,e:
                    print "Mysql Error %d: %s" % (e.args[0], e.args[1])
if __name__ == "__main__":
    spider()
