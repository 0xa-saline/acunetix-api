#!/usr/bin/env python
# -*- coding: utf-8 -*-
from xml.dom import minidom

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
        #遍历爬虫获取文件
        if Crawler_list:
            for crawl in Crawler_list:
                spider = {}
                URL = crawl.getElementsByTagName("URL")[0].firstChild.data.encode('utf-8')
                fURL = crawl.getElementsByTagName("FullURL")[0].firstChild.data.encode('utf-8')
                spider['path'] = URL
                spider['furl'] = fURL
                bug_list['url'].append(spider)

        #遍历漏洞信息
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
                    #漏洞名称
                    temp['name'] = name
                    #漏洞等级
                    temp['level'] = level.encode('utf-8')
                    #请求包
                    temp['request'] = Request
                    temp['details'] = details
                    temp['path'] = node.getElementsByTagName("Affects")[0].firstChild.data.encode('utf-8')

                    bug_list['bug'].append(temp)
                 
    except Exception as e:
        print "Error in parse_xml: %s" % str(e)

    return bug_list

if __name__ == '__main__':
    results = details_parse_xml('XML1.xml')
    for result in results['bug']:
        print result
    
