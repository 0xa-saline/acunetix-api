#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import requests
from xml.dom import minidom
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()


filter = {
    "level_white_list": ["high", "medium","low","informational"],  # high,medium,low,informational四种级别.
    "bug_black_list": [                     # 漏洞黑名单，过滤掉一些危害等级高，但没什么卵用的洞
        "User credentials are sent in clear text",
        "HTML form without CSRF protection",
        "Broken links"
    ]
}



def details_parse_xml(file_name):
    bug_list = {}
    try:
        root = minidom.parse(file_name).documentElement
        ReportItem_list = root.getElementsByTagName('ReportItem')
        Crawler_list = root.getElementsByTagName('SiteFile')
        bug_list['time'] = root.getElementsByTagName('ScanTime')[0].firstChild.data.encode('utf-8')
        bug_list['url'] = []
        bug_list['bug'] = []

        if Crawler_list:
            for crawl in Crawler_list:
                spider = {}
                URL = crawl.getElementsByTagName("URL")[0].firstChild.data.encode('utf-8')
                fURL = crawl.getElementsByTagName("FullURL")[0].firstChild.data.encode('utf-8')
                spider['path'] = URL
                spider['furl'] = fURL
                bug_list['url'].append(spider)

        
        if ReportItem_list:
            for node in ReportItem_list:
                level = node.getElementsByTagName("Severity")[0].firstChild.data.encode('utf-8')
                name = node.getElementsByTagName("Name")[0].firstChild.data.encode('utf-8')
                if level in filter['level_white_list'] and name not in filter['bug_black_list']:

                    try:
                        Request = node.getElementsByTagName("Request")[0].firstChild.data.encode('utf-8')
                    except:
                        Request = ""

                    try:
                        details = node.getElementsByTagName("Details")[0].firstChild.data.encode('utf-8')
                    except:
                        details = ""

                    temp = {}
                    temp['name'] = name
                    temp['level'] = level.encode('utf-8')
                    temp['request'] = Request
                    temp['details'] = details
                    temp['path'] = node.getElementsByTagName("Affects")[0].firstChild.data.encode('utf-8')

                    bug_list['bug'].append(temp)
                 
    except Exception as e:
        print "Error in parse_xml: %s" % str(e)

    return bug_list

def deal_url(scan_id,url):
    filename = "/tmp/wvsreports/"+scan_id+".xml"
    try:
        resp = requests.get(url,timeout=120,verify=False)
        content = resp.content
        xmlf = file(filename,"w+")
        xmlf.write(content)
        xmlf.close()

        results = details_parse_xml(filename)
        #读出来，删除
        os.remove(filename)
        return results

    except Exception as e:
        print "Error in get report: %s " % str(e)

if __name__ == '__main__':
    target_id = "target_id"
    reporturl = "https://127.0.0.1:3443/reports/download/hash.xml"
    results = deal_url(target_id,reporturl)

    for result in results['bug']:
        print result    
