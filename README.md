# acunetix-api
利用https://github.com/jenkinsci/acunetix-plugin/blob/master/src/main/java/com/acunetix/Engine.java

里面所提供的api改写而来

全局依赖于获取到的api-key
```
headers = {"X-Auth":apikey,"content-type": "application/json"}
```
1.添加任务
```
post  /api/v1/targets

data = {"address":url,"description":url,"criticality":"10"}
```
2.扫描任务
```
post /api/v1/scans

data = {"target_id":target_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
```
target_id 为第一步添加任务返回的结果


3.获取任务概要
```
get /api/v1/scans
```
4.获取任务详情
```
get /api/v1/scans/+scan_id
```
5.生成报告
```
post /api/v1/reports

data = {"template_id":"11111111-1111-1111-1111-111111111111","source":{"list_type":"scans","id_list":[scan_id]}}
```
6.停止扫描
```
POST /scans/" + scanId + "/abort
```
7.删除扫描
```
DELETE /api/v1/scans/+scan_id
```
详情参考

http://0cx.cc/about_awvs11_api.jspx
