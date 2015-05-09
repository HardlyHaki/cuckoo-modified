# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

try:
    import re2 as re
except ImportError:
    import re

import os
import json

from django.conf import settings
from django.template import RequestContext
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied
from gridfs import GridFS
from urllib import quote
sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
import modules.processing.network as network

from django.http import StreamingHttpResponse
from django.core.servers.basehttp import FileWrapper

results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]
fs = GridFS(results_db)

TASK_LIMIT = 25
repconf = Config("reporting")

global_settings=dict()
if settings.MOLOCH_ENABLED:
    global_settings["moloch_enabled"] = True
else:
    global_settings["moloch_enabled"] = False

if settings.DISPLAY_IE_MARTIANS:
    global_settings["display_ie_martians"] = True 
else:
    global_settings["display_ie_martians"] = False 

if settings.DISPLAY_SHRIKE:
    global_settings["display_shrike"] = True
else:
    global_settings["display_shrike"] = False

@require_safe
def index(request, page=1):
    page = int(page)
    db = Database()
    if page == 0:
        page = 1
    off = (page - 1) * TASK_LIMIT

    tasks_files = db.list_tasks(limit=TASK_LIMIT, offset=off, category="file", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=TASK_LIMIT, offset=off, category="url", not_status=TASK_PENDING)
    analyses_files = []
    analyses_urls = []

    # Vars to define when to show Next/Previous buttons
    paging = dict()
    paging["show_file_next"] = "show"
    paging["show_url_next"] = "show"
    paging["next_page"] = str(page + 1)
    paging["prev_page"] = str(page - 1)

    # On a fresh install, we need handle where there are 0 tasks.
    buf = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by="added_on asc")
    if len(buf) == 1:
        first_file = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by="added_on asc")[0].to_dict()["id"]
        paging["show_file_prev"] = "show"
    else:
        paging["show_file_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by="added_on asc")
    if len(buf) == 1:
        first_url = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by="added_on asc")[0].to_dict()["id"]
        paging["show_url_prev"] = "show"
    else:
        paging["show_url_prev"] = "hide"

    if tasks_files:
        for task in tasks_files:
            new = task.to_dict()
            if new["id"] == first_file:
                paging["show_file_next"] = "hide"
            if page <= 1:
                paging["show_file_prev"] = "hide"
            new["sample"] = db.view_sample(new["sample_id"]).to_dict()

            filename = os.path.basename(new["target"])
            new.update({"filename": filename})

            if db.view_errors(task.id):
                new["errors"] = True

            rtmp = results_db.analysis.find_one({"info.id": int(new["id"])},{"virustotal_summary": 1,"network.pcap_id":1, "info.custom":1, "info.shrike_msg":1},sort=[("_id", pymongo.DESCENDING)])
            stmp = results_db.suricata.find_one({"info.id": int(new["id"])},{"tls_cnt": 1, "alert_cnt": 1, "http_cnt": 1, "file_cnt": 1, "http_log_id": 1, "tls_log_id": 1, "alert_log_id": 1, "file_log_id": 1},sort=[("_id", pymongo.DESCENDING)])
            if rtmp:
                if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
                    new["virustotal_summary"] = rtmp["virustotal_summary"]
                if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
                    new["mlist_cnt"] = rtmp["mlist_cnt"]
                if rtmp.has_key("network") and rtmp["network"].has_key("pcap_id") and rtmp["network"]["pcap_id"]:
                    new["pcap_id"] = rtmp["network"]["pcap_id"]
                if rtmp.has_key("info") and rtmp["info"].has_key("custom") and rtmp["info"]["custom"]:
                    new["custom"] = rtmp["info"]["custom"]
                if settings.DISPLAY_SHRIKE and rtmp.has_key("info") and rtmp["info"].has_key("shrike_msg") and rtmp["info"]["shrike_msg"]:
                    new["shrike_msg"] = rtmp["info"]["shrike_msg"]

            if settings.MOLOCH_ENABLED:
                if settings.MOLOCH_BASE[-1] != "/":
                    settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
                new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')
                new["moloch_base"] = settings.MOLOCH_BASE
            if stmp:
                if stmp.has_key("tls_cnt") and stmp["tls_cnt"]:
                    new["suri_tls_cnt"] = stmp["tls_cnt"]
                if stmp.has_key("alert_cnt") and stmp["alert_cnt"]:
                    new["suri_alert_cnt"] = stmp["alert_cnt"]
                if stmp.has_key("file_cnt") and stmp["file_cnt"]:
                    new["suri_file_cnt"] = stmp["file_cnt"]
                if stmp.has_key("http_cnt") and stmp["http_cnt"]:
                    new["suri_http_cnt"] = stmp["http_cnt"]
                if stmp.has_key("http_log_id") and stmp["http_log_id"]:
                    new["suricata_http_log_id"] = stmp["http_log_id"]
                if stmp.has_key("tls_log_id") and stmp["tls_log_id"]:
                    new["suricata_tls_log_id"] = stmp["tls_log_id"]
                if stmp.has_key("alert_log_id") and stmp["alert_log_id"]:
                    new["suricata_alert_log_id"] = stmp["alert_log_id"]
                if  stmp.has_key("file_log_id") and stmp["file_log_id"]:
                    new["suricata_file_log_id"] = stmp["file_log_id"]
            analyses_files.append(new)
    else:
        paging["show_file_next"] = "hide"

    if tasks_urls:
        for task in tasks_urls:
            new = task.to_dict()
            if new["id"] == first_url:
                paging["show_url_next"] = "hide"
            if page <= 1:
                paging["show_url_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            rtmp = results_db.analysis.find_one({"info.id": int(new["id"])},{"virustotal_summary": 1, "network.pcap_id":1, "info.custom":1, "info.shrike_msg":1,"signatures":1},sort=[("_id", pymongo.DESCENDING)])
            stmp = results_db.suricata.find_one({"info.id": int(new["id"])},{"tls_cnt": 1, "alert_cnt": 1, "http_cnt": 1, "file_cnt": 1, "http_log_id": 1, "tls_log_id": 1, "alert_log_id": 1, "file_log_id": 1},sort=[("_id", pymongo.DESCENDING)])
            if rtmp:
                if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
                    new["virustotal_summary"] = rtmp["virustotal_summary"]
                if rtmp.has_key("network") and rtmp["network"].has_key("pcap_id") and rtmp["network"]["pcap_id"]:
                    new["pcap_id"] = rtmp["network"]["pcap_id"]
                if rtmp.has_key("info") and rtmp["info"].has_key("custom") and rtmp["info"]["custom"]:
                    new["custom"] = rtmp["info"]["custom"]
                if settings.DISPLAY_SHRIKE and rtmp.has_key("info") and rtmp["info"].has_key("shrike_msg") and rtmp["info"]["shrike_msg"]:
                    new["shrike_msg"] = rtmp["info"]["shrike_msg"]
                if settings.DISPLAY_IE_MARTIANS and rtmp.has_key("signatures"):
                    for entry in rtmp["signatures"]:
                        if entry["name"] == "ie_martian_children":
                            new["mlist_cnt"] = len(entry["data"])                        
            if settings.MOLOCH_ENABLED:
                if settings.MOLOCH_BASE[-1] != "/":
                    settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
                new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')
                new["moloch_base"] = settings.MOLOCH_BASE
            if stmp:
                if stmp.has_key("tls_cnt") and stmp["tls_cnt"]:
                    new["suri_tls_cnt"] = stmp["tls_cnt"]
                if stmp.has_key("alert_cnt") and stmp["alert_cnt"]:
                    new["suri_alert_cnt"] = stmp["alert_cnt"]
                if stmp.has_key("file_cnt") and stmp["file_cnt"]:
                    new["suri_file_cnt"] = stmp["file_cnt"]
                if stmp.has_key("http_cnt") and stmp["http_cnt"]:
                    new["suri_http_cnt"] = stmp["http_cnt"]
                if stmp.has_key("http_log_id") and stmp["http_log_id"]:
                    new["suricata_http_log_id"] = stmp["http_log_id"]
                if stmp.has_key("tls_log_id") and stmp["tls_log_id"]:
                    new["suricata_tls_log_id"] = stmp["tls_log_id"]
                if stmp.has_key("alert_log_id") and stmp["alert_log_id"]:
                    new["suricata_alert_log_id"] = stmp["alert_log_id"]
                if  stmp.has_key("file_log_id") and stmp["file_log_id"]:
                    new["suricata_file_log_id"] = stmp["file_log_id"]
            analyses_urls.append(new)
    else:
        paging["show_url_next"] = "hide"
    return render_to_response("analysis/index.html",
            {"files": analyses_files, "urls": analyses_urls,
             "paging": paging, "global_settings":global_settings}, context_instance=RequestContext(request))

@require_safe
def pending(request):
    db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render_to_response("analysis/pending.html",
                              {"tasks": pending},
                              context_instance=RequestContext(request))

@require_safe
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum)-1
    except:
        raise PermissionDenied

    if request.is_ajax():
        record = results_db.analysis.find_one(
            {
                "info.id": int(task_id),
                "behavior.processes.process_id": pid
            },
            {
                "behavior.processes.process_id": 1,
                "behavior.processes.calls": 1
            }
        )

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict

        if not process:
            raise PermissionDenied

        try:
            objectid = process["calls"][pagenum]
        except:
            raise PermissionDenied
        chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": chunk},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied


@require_safe
def filtered_chunk(request, task_id, pid, category, apilist):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    @param apilist: comma-separated list of APIs to include, if preceded by ! specifies to exclude the list
    """
    if request.is_ajax():
        # Search calls related to your PID.
        record = results_db.analysis.find_one(
            {"info.id": int(task_id), "behavior.processes.process_id": int(pid)},
            {"behavior.processes.process_id": 1, "behavior.processes.calls": 1}
        )

        if not record:
            raise PermissionDenied

        # Extract embedded document related to your process from response collection.
        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == int(pid):
                process = pdict

        if not process:
            raise PermissionDenied

        # Create empty process dict for AJAX view.
        filtered_process = {"process_id": pid, "calls": []}

        exclude = False
        apilist = apilist.strip()
        if len(apilist) and apilist[0] == '!':
            exclude = True
        apilist = apilist.lstrip('!')
        apis = apilist.split(',')
        apis[:] = [s.strip().lower() for s in apis if len(s.strip())]

        # Populate dict, fetching data from all calls and selecting only appropriate category/APIs.
        for call in process["calls"]:
            chunk = results_db.calls.find_one({"_id": call})
            for call in chunk["calls"]:
                if category == "all" or call["category"] == category:
                    if len(apis) > 0:
                        add_call = -1
                        for api in apis:
                            if call["api"].lower() == api:
                                if exclude == True:
                                    add_call = 0
                                else:
                                    add_call = 1
                                break
                        if (exclude == True and add_call != 0) or (exclude == False and add_call == 1):
                            filtered_process["calls"].append(call)
                    else:
                        filtered_process["calls"].append(call)

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": filtered_process},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied

def gen_moloch_from_suri_http(suricata):
    if suricata.has_key("http") and suricata["http_cnt"] > 0:
        for e in suricata["http"]:
            try:
                if e.has_key("src_ip") and e["src_ip"]:
                    e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["src_ip"])),safe='')
                if e.has_key("dest_ip") and e["dest_ip"]:
                    e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dest_ip"])),safe='')
                if e.has_key("dest_port") and e["dest_port"]:
                    e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["dest_port"])),safe='')
                if e.has_key("src_port") and e["src_port"]:
                    e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["src_port"])),safe='')
                if e.has_key("http"):
                    if e["http"].has_key("hostname") and e["http"]["hostname"]:
                        e["moloch_http_host_url"] = settings.MOLOCH_BASE + "?date=-1&expression=host.http" + quote("\x3d\x3d\x22%s\x22" % (e["http"]["hostname"]),safe='')
                    if e["http"].has_key("url") and e["http"]["url"]:
                        e["moloch_http_uri_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["http"]["url"]),safe='')
                    if e["http"].has_key("http_user_agent") and e["http"]["http_user_agent"]:
                        e["moloch_http_ua_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.user-agent" + quote("\x3d\x3d\x22%s\x22" % (e["http"]["http_user_agent"]),safe='')
                    if e["http"].has_key("http_method") and e["http"]["http_method"]:
                        e["moloch_http_method_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.method" + quote("\x3d\x3d\x22%s\x22" % (e["http"]["http_method"]),safe='')
                    if e["http"].has_key("http_method") and e["http"]["http_method"]:
                        e["moloch_http_method_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.method" + quote("\x3d\x3d\x22%s\x22" % (e["http"]["http_method"]),safe='')
            except:
                continue
    return suricata

def gen_moloch_from_suri_alerts(suricata):
    if suricata.has_key("alerts") and suricata["alert_cnt"] > 0:
        for e in suricata["alerts"]:
            if e.has_key("src_ip") and e["src_ip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["src_ip"])),safe='')
            if e.has_key("dest_ip") and e["dest_ip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dest_ip"])),safe='')
            if e.has_key("dest_port") and e["dest_port"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dest_port"]),e["proto"].lower()),safe='')
            if e.has_key("src_port") and e["src_port"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["src_port"]),e["proto"].lower()),safe='')
            if e.has_key("alert"):
                if e["alert"].has_key("signature_id") and e["alert"]["signature_id"]:
                    e["moloch_sid_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22suri_sid\x3a%s\x22" % (e["alert"]["signature_id"]),safe='')
                if e["alert"].has_key("signature") and e["alert"]["signature"]:
                    e["moloch_msg_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22suri_msg\x3a%s\x22" % (re.sub(r"[\W]","_",e["alert"]["signature"])),safe='')
    return suricata

def gen_moloch_from_suri_file_info(suricata):
    if suricata.has_key("files") and suricata["file_cnt"] > 0:
        for e in suricata["files"]:
            if e.has_key("srcip") and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])),safe='')
            if e.has_key("dstip") and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])),safe='')
            if e.has_key("dp") and e["dp"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dp"]),"tcp"),safe='')
            if e.has_key("sp") and e["sp"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["sp"]),"tcp"),safe='')
            if e.has_key("http_uri") and e["http_uri"]:
                e["moloch_uri_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["http_uri"]),safe='')
            if e.has_key("http_host") and e["http_host"]:
                e["moloch_host_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.host" + quote("\x3d\x3d\x22%s\x22" % (e["http_host"]),safe='')
            if e.has_key("file_info"):
                if e["file_info"].has_key("clamav") and e["file_info"]["clamav"]:
                    e["moloch_clamav_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22clamav\x3a%s\x22" % (re.sub(r"[\W]","_",e["file_info"]["clamav"])),safe='')
                if e["file_info"].has_key("md5") and e["file_info"]["md5"]:
                    e["moloch_md5_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22md5\x3a%s\x22" % (e["file_info"]["md5"]),safe='')
                if e["file_info"].has_key("sha1") and e["file_info"]["sha1"]:
                    e["moloch_sha1_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22sha1\x3a%s\x22" % (e["file_info"]["sha1"]),safe='')
                if e["file_info"].has_key("sha256") and e["file_info"]["sha256"]:
                    e["moloch_sha256_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22sha256\x3a%s\x22" % (e["file_info"]["sha256"]),safe='')
                if e["file_info"].has_key("crc32") and e["file_info"]["crc32"]:
                    e["moloch_crc32_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22crc32\x3a%s\x22" % (e["file_info"]["crc32"]),safe='')
                if e["file_info"].has_key("ssdeep") and e["file_info"]["ssdeep"]:
                    e["moloch_ssdeep_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22ssdeep\x3a%s\x22" % (e["file_info"]["ssdeep"]),safe='')
                if e["file_info"].has_key("yara") and e["file_info"]["yara"]:
                    for sign in e["file_info"]["yara"]:
                        if sign.has_key("name"):
                            sign["moloch_yara_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22yara\x3a%s\x22" % (sign["name"]),safe='')
    return suricata

def gen_moloch_from_suri_tls(suricata):
    if suricata.has_key("tls") and suricata["tls_cnt"] > 0:
        for e in suricata["tls"]:
            if e.has_key("src_ip") and e["src_ip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["src_ip"])),safe='')
            if e.has_key("dest_ip") and e["dest_ip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dest_ip"])),safe='')
            if e.has_key("dest_port") and e["dest_port"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dest_port"]),e["proto"].lower()),safe='')
            if e.has_key("src_port") and e["src_port"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["src_port"]),e["proto"].lower()),safe='')
    return suricata

def gen_moloch_from_antivirus(virustotal):
    if virustotal and virustotal.has_key("scans"):
        for key in virustotal["scans"]:
            if virustotal["scans"][key]["result"]:
                 virustotal["scans"][key]["moloch"] = settings.MOLOCH_BASE + "?date=-1&expression=" + quote("tags\x3d\x3d\x22VT:%s:%s\x22" % (key,virustotal["scans"][key]["result"]),safe='')
    return virustotal 

def surialert(request,task_id):
    suricata = results_db.suricata.find_one({"info.id": int(task_id)},{"alerts": 1,"alert_cnt": 1},sort=[("_id", pymongo.DESCENDING)])
    if not suricata:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        if suricata.has_key("alerts"):
            suricata=gen_moloch_from_suri_alerts(suricata)

    return render_to_response("analysis/surialert.html",
                              {"suricata": suricata},
                              context_instance=RequestContext(request))
def shrike(request,task_id):
    shrike = results_db.analysis.find_one({"info.id": int(task_id)},{"info.shrike_url": 1,"info.shrike_msg": 1,"info.shrike_sid":1, "info.shrike_refer":1},sort=[("_id", pymongo.DESCENDING)])
    if not shrike:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))

    return render_to_response("analysis/shrike.html",
                              {"shrike": shrike},
                              context_instance=RequestContext(request))

def surihttp(request,task_id):
    suricata = results_db.suricata.find_one({"info.id": int(task_id)},{"http": 1, "http_cnt": 1},sort=[("_id", pymongo.DESCENDING)])
    if not suricata:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        if suricata.has_key("http"):
            suricata=gen_moloch_from_suri_http(suricata)

    return render_to_response("analysis/surihttp.html",
                              {"suricata": suricata},
                              context_instance=RequestContext(request))

def suritls(request,task_id):
    suricata = results_db.suricata.find_one({"info.id": int(task_id)},{"tls": 1, "tls_cnt": 1},sort=[("_id", pymongo.DESCENDING)])
    if not suricata:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        if suricata.has_key("tls"):
            suricata=gen_moloch_from_suri_tls(suricata)
    return render_to_response("analysis/suritls.html",
                              {"suricata": suricata},
                              context_instance=RequestContext(request))
def surifiles(request,task_id):
    suricata = results_db.suricata.find_one({"info.id": int(task_id)},{"files": 1,"files_cnt": 1},sort=[("_id", pymongo.DESCENDING)])
    if not suricata:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        if suricata.has_key("files"):
            suricata=gen_moloch_from_suri_tls(suricata)
    return render_to_response("analysis/surifiles.html",
                              {"suricata": suricata},
                              context_instance=RequestContext(request))

def antivirus(request,task_id):
    rtmp = results_db.analysis.find_one({"info.id": int(task_id)},{"virustotal": 1,"info.category": 1},sort=[("_id", pymongo.DESCENDING)])
    if not rtmp:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        if rtmp.has_key("virustotal"):
            rtmp["virustotal"]=gen_moloch_from_antivirus(rtmp["virustotal"])

    return render_to_response("analysis/antivirus.html",
                              {"analysis": rtmp},
                              context_instance=RequestContext(request))


@csrf_exempt
def search_behavior(request, task_id):
    if request.method == 'POST':
        query = request.POST.get('search')
        results = []

        # Fetch anaylsis report
        record = results_db.analysis.find_one(
            {"info.id": int(task_id)}
        )

        # Loop through every process
        for process in record["behavior"]["processes"]:
            process_results = []

            chunks = results_db.calls.find({
                "_id": { "$in": process["calls"] }
            })
            for chunk in chunks:
                for call in chunk["calls"]:
                    query = re.compile(query)
                    if query.search(call['api']):
                        process_results.append(call)
                    else:
                        for argument in call['arguments']:
                            if query.search(argument['name']) or query.search(argument['value']):
                                process_results.append(call)
                                break

            if len(process_results) > 0:
                results.append({
                    'process': process,
                    'signs': process_results
                })

        return render_to_response("analysis/behavior/_search_results.html",
                                  {"results": results},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied

@require_safe
def report(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    suricata = results_db.suricata.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        report["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,task_id),safe='')
        if isinstance(suricata, dict):
            if suricata.has_key("http") and suricata["http_cnt"] > 0:
                suricata=gen_moloch_from_suri_http(suricata)
            if suricata.has_key("alerts") and suricata["alert_cnt"] > 0:
                suricata=gen_moloch_from_suri_alerts(suricata)
            if suricata.has_key("files") and suricata["file_cnt"] > 0:
                suricata=gen_moloch_from_suri_file_info(suricata)
            if suricata.has_key("tls") and suricata["tls_cnt"] > 0:
                suricata=gen_moloch_from_suri_tls(suricata)

        if report.has_key("virustotal"):
            report["virustotal"]=gen_moloch_from_antivirus(report["virustotal"])
        
    # Creating dns information dicts by domain and ip.
    if "network" in report and "domains" in report["network"]:
        domainlookups = dict((i["domain"], i["ip"]) for i in report["network"]["domains"])
        iplookups = dict((i["ip"], i["domain"]) for i in report["network"]["domains"])
        for i in report["network"]["dns"]:
            for a in i["answers"]:
                iplookups[a["data"]] = i["request"]
    else:
        domainlookups = dict()
        iplookups = dict()

    conf = repconf.get_config()
    enabledconf = dict()
    for item in conf:
        if conf[item]["enabled"] == "yes":
            enabledconf[item] = True
        else:
            enabledconf[item] = False

    return render_to_response("analysis/report.html",
                             {"analysis": report,
                              "domainlookups": domainlookups,
                              "iplookups": iplookups,
                              "config": enabledconf,
                              "suricata": suricata},
                             context_instance=RequestContext(request))
@require_safe
def file(request, category, object_id):
    file_item = fs.get(ObjectId(object_id))

    if file_item:
        file_name = file_item.sha256
        if category == "pcap":
            file_name += ".pcap"
        elif category == "zip":
            file_name += ".zip"
        elif category == "screenshot":
            file_name += ".jpg"
        elif category == 'memdump':
            file_name += ".dmp"
        else:
            file_name += ".bin"

        # Managing gridfs error if field contentType is missing.
        try:
            content_type = file_item.contentType
        except AttributeError:
            content_type = "application/octet-stream"

        response = HttpResponse(file_item.read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))

@require_safe
def procdump(request, object_id, task_id, process_id, start, end):
    analysis = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])

    file_item = fs.get(ObjectId(object_id))
    file_name = "{0}_{1:x}.dmp".format(process_id, int(start, 16))

    if file_item and analysis and "procmemory" in analysis:
        for proc in analysis["procmemory"]:
            if proc["pid"] == int(process_id):
                data = ""
                for memmap in proc["address_space"]:
                    for chunk in memmap["chunks"]:
                        if int(chunk["start"], 16) >= int(start, 16) and int(chunk["end"], 16) <= int(end, 16):
                            file_item.seek(chunk["offset"])
                            data += file_item.read(int(chunk["size"], 16))
                if len(data):
                    content_type = "application/octet-stream"
                    response = HttpResponse(data, content_type=content_type)
                    response["Content-Disposition"] = "attachment; filename={0}".format(file_name)
                    return response

    return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))

@require_safe
def filereport(request, task_id, category):
    formats = {
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-1.1.xml",
        "metadata": "report.metadata.xml",
    }

    if category in formats:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", formats[category])
        file_name = str(task_id) + "_" + formats[category]
        content_type = "application/octet-stream"

        if os.path.exists(file_path):
            response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
            response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

            return response

    return render_to_response("error.html",
                              {"error": "File not found"},
                              context_instance=RequestContext(request))

@require_safe
def full_memory_dump_file(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp")
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    else:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    if filename:
        content_type = "application/octet-stream"
        chunk_size = 8192
        response = StreamingHttpResponse(FileWrapper(open(file_path), chunk_size),
                                   content_type=content_type)
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))
@require_safe
def full_memory_dump_strings(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.strings")
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    else:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.strings.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    if filename:
        content_type = "application/octet-stream"
        chunk_size = 8192
        response = StreamingHttpResponse(FileWrapper(open(file_path), chunk_size),
                                   content_type=content_type)
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))

def search(request):
    if "search" in request.POST:
        error = None

        try:
            term, value = request.POST["search"].strip().split(":", 1)
        except ValueError:
            term = ""
            value = request.POST["search"].strip()

        if term:
            # Check on search size.
            if len(value) < 3:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Search term too short, minimum 3 characters required"},
                                          context_instance=RequestContext(request))
            # name:foo or name: foo
            value = value.lstrip()

            # Search logic.
            if term == "name":
                records = results_db.analysis.find({"target.file.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "type":
                records = results_db.analysis.find({"target.file.type": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "string":
                records = results_db.analysis.find({"strings" : {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "ssdeep":
                records = results_db.analysis.find({"target.file.ssdeep": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "crc32":
                records = results_db.analysis.find({"target.file.crc32": value}).sort([["_id", -1]])
            elif term == "file":
                records = results_db.analysis.find({"behavior.summary.files": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "command":
                records = results_db.analysis.find({"behavior.summary.executed_commands": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "key":
                records = results_db.analysis.find({"behavior.summary.keys": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "mutex":
                records = results_db.analysis.find({"behavior.summary.mutexes": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "domain":
                records = results_db.analysis.find({"network.domains.domain": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "ip":
                records = results_db.analysis.find({"network.hosts.ip": value}).sort([["_id", -1]])
            elif term == "signature":
                records = results_db.analysis.find({"signatures.description": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "signame":
                records = results_db.analysis.find({"signatures.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "url":
                records = results_db.analysis.find({"target.url": value}).sort([["_id", -1]])
            elif term == "imphash":
                records = results_db.analysis.find({"static.pe_imphash": value}).sort([["_id", -1]])
            elif term == "surisid":
                records = results_db.suricata.find({"alerts.alert.signature_id": int(value)}).sort([["_id", -1]])
            elif term == "surimsg":
                records = results_db.suricata.find({"alerts.alert.signature": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "suriurl":
                records = results_db.suricata.find({"http.http.url": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "suriua":
                records = results_db.suricata.find({"http.http.http_user_agent": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "surireferer":
                records = results_db.suricata.find({"http.http.http_refer": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "surihhost":
                records = results_db.suricata.find({"http.http.hostname": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "suritlssubject":
                records = results_db.suricata.find({"tls.tls.subject": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "suritlsissuerdn":
                records = results_db.suricata.find({"tls.tls.issuerdn": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "suritlsfingerprint":
                records = results_db.suricata.find({"tls.tls.fingerprint": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "clamav":
                records = results_db.analysis.find({"target.file.clamav": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "yaraname":
                records = results_db.analysis.find({"target.file.yara.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "strings":
                records = results_db.analysis.find({"strings": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "virustotal":
                records = results_db.analysis.find({"virustotal.results.sig": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "machinename":
                records = results_db.analysis.find({"info.machine.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "machinelabel":
                records = results_db.analysis.find({"info.machine.label": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "custom":
                records = results_db.analysis.find({"info.custom": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "shrikemsg":
                records = results_db.analysis.find({"info.shrike_msg": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "shrikeurl":
                records = results_db.analysis.find({"info.shrike_url": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "shrikerefer":
                records = results_db.analysis.find({"info.shrike_refer": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "shrikesid":
                records = results_db.analysis.find({"info.shrike_sid": int(value)}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "global_settings": global_settings,
                                           "error": "Invalid search term: %s" % term},
                                          context_instance=RequestContext(request))
        else:
            # hash matching is lowercase and case sensitive
            value = value.lower()
            if re.match(r"^([a-fA-F\d]{32})$", value):
                records = results_db.analysis.find({"target.file.md5": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{40})$", value):
                records = results_db.analysis.find({"target.file.sha1": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{64})$", value):
                records = results_db.analysis.find({"target.file.sha256": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                records = results_db.analysis.find({"target.file.sha512": value}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": None,
                                           "global_settings": global_settings,
                                           "error": "Unable to recognize the search syntax"},
                                          context_instance=RequestContext(request))

        # Get data from cuckoo db.
        db = Database()
        analyses = []
        for result in records:
            new = db.view_task(result["info"]["id"])

            if not new:
                continue

            new = new.to_dict()

            if new["category"] == "file":
                if new["sample_id"]:
                    sample = db.view_sample(new["sample_id"])
                    if sample:
                        new["sample"] = sample.to_dict()
                filename = os.path.basename(new["target"])
                new.update({"filename": filename})
            rtmp = results_db.analysis.find_one({"info.id": int(new["id"])},{"virustotal_summary": 1, "network.pcap_id":1, "info.custom":1, "info.shrike_msg":1,"signatures":1},sort=[("_id", pymongo.DESCENDING)])
            stmp = results_db.suricata.find_one({"info.id": int(new["id"])},{"tls_cnt": 1, "alert_cnt": 1, "http_cnt": 1, "file_cnt": 1, "http_log_id": 1, "tls_log_id": 1, "alert_log_id": 1, "file_log_id": 1},sort=[("_id", pymongo.DESCENDING)])

            if rtmp:
                if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
                    new["virustotal_summary"] = rtmp["virustotal_summary"]
                if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
                    new["mlist_cnt"] = rtmp["mlist_cnt"]
                if rtmp.has_key("network") and rtmp["network"].has_key("pcap_id") and rtmp["network"]["pcap_id"]:
                    new["pcap_id"] = rtmp["network"]["pcap_id"]
                if rtmp.has_key("info") and rtmp["info"].has_key("custom") and rtmp["info"]["custom"]:
                    new["custom"] = rtmp["info"]["custom"]
                if settings.DISPLAY_SHRIKE and rtmp.has_key("info") and rtmp["info"].has_key("shrike_msg") and rtmp["info"]["shrike_msg"]:
                    new["shrike_msg"] = rtmp["info"]["shrike_msg"]
                if settings.DISPLAY_IE_MARTIANS and rtmp.has_key("signatures"):
                    for entry in rtmp["signatures"]:
                        if entry["name"] == "ie_martian_children":
                            new["mlist_cnt"] = len(entry["data"])
            if settings.MOLOCH_ENABLED:
                if settings.MOLOCH_BASE[-1] != "/":
                    settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
                new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')
                new["moloch_base"] = settings.MOLOCH_BASE
            if stmp:
                if stmp.has_key("tls_cnt") and stmp["tls_cnt"]:
                    new["suri_tls_cnt"] = stmp["tls_cnt"]
                if stmp.has_key("alert_cnt") and stmp["alert_cnt"]:
                    new["suri_alert_cnt"] = stmp["alert_cnt"]
                if stmp.has_key("file_cnt") and stmp["file_cnt"]:
                    new["suri_file_cnt"] = stmp["file_cnt"]
                if stmp.has_key("http_cnt") and stmp["http_cnt"]:
                    new["suri_http_cnt"] = stmp["http_cnt"]
                if stmp.has_key("http_log_id") and stmp["http_log_id"]:
                    new["suricata_http_log_id"] = stmp["http_log_id"]
                if stmp.has_key("tls_log_id") and stmp["tls_log_id"]:
                    new["suricata_tls_log_id"] = stmp["tls_log_id"]
                if stmp.has_key("alert_log_id") and stmp["alert_log_id"]:
                    new["suricata_alert_log_id"] = stmp["alert_log_id"]
                if  stmp.has_key("file_log_id") and stmp["file_log_id"]:
                    new["suricata_file_log_id"] = stmp["file_log_id"]
            analyses.append(new)
        return render_to_response("analysis/search.html",
                                  {"analyses": analyses,
                                   "term": request.POST["search"],
                                   "global_settings": global_settings,
                                   "error": None},
                                  context_instance=RequestContext(request))
    else:
        return render_to_response("analysis/search.html",
                                  {"analyses": None,
                                   "term": None,
                                   "global_settings": global_settings,
                                   "error": None},
                                  context_instance=RequestContext(request))

@require_safe
def remove(request, task_id):
    """Remove an analysis.
    @todo: remove folder from storage.
    """
    analyses = results_db.analysis.find({"info.id": int(task_id)})
    suri = results_db.suricata.find({"info.id": int(task_id)})
    # Checks if more analysis found with the same ID, like if process.py was run manually.
    if analyses.count() > 1:
        message = "Multiple tasks with this ID deleted."
    elif analyses.count() == 1:
        message = "Task deleted."

    if analyses.count() > 0:
        # Delete dups too.
        for analysis in analyses:
            # Delete sample if not used.
            if "file_id" in analysis["target"]:
                if results_db.analysis.find({"target.file_id": ObjectId(analysis["target"]["file_id"])}).count() == 1:
                    fs.delete(ObjectId(analysis["target"]["file_id"]))
            # Delete screenshots.
            for shot in analysis["shots"]:
                if results_db.analysis.find({"shots": ObjectId(shot)}).count() == 1:
                    fs.delete(ObjectId(shot))
            # Delete network pcap.
            if "pcap_id" in analysis["network"] and results_db.analysis.find({"network.pcap_id": ObjectId(analysis["network"]["pcap_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["network"]["pcap_id"]))
            # Delete dropped.
            for drop in analysis["dropped"]:
                if "object_id" in drop and results_db.analysis.find({"dropped.object_id": ObjectId(drop["object_id"])}).count() == 1:
                    fs.delete(ObjectId(drop["object_id"]))
            # Delete calls.
            for process in analysis["behavior"]["processes"]:
                for call in process["calls"]:
                    results_db.calls.remove({"_id": ObjectId(call)})
            # Delete analysis data.
            results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})

    # we may not have any suri entries
    if suri.count() == 1:
        for suricata in suri:
            results_db.suricata.remove({"_id": ObjectId(suricata["_id"])})

    # More analysis found with the same ID, like if process.py was run manually.
    else:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))
    # we may not have any suri entries
    if suri.count() > 0:
        for suricata in suri:
            results_db.suricata.remove({"_id": ObjectId(suricata["_id"])})

    # Delete from SQL db.
    db = Database()
    db.delete_task(task_id)

    return render_to_response("success_simple.html",
                              {"message": message},
                              context_instance=RequestContext(request))

@require_safe
def pcapstream(request, task_id, conntuple):
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    conndata = results_db.analysis.find_one({ "info.id": int(task_id) },
        { "network.tcp": 1, "network.udp": 1, "network.sorted_pcap_id": 1 },
        sort=[("_id", pymongo.DESCENDING)])

    if not conndata:
        return render_to_response("standalone_error.html",
            {"error": "The specified analysis does not exist"},
            context_instance=RequestContext(request))

    try:
        if proto == "udp": connlist = conndata["network"]["udp"]
        else: connlist = conndata["network"]["tcp"]

        conns = filter(lambda i: (i["sport"],i["dport"],i["src"],i["dst"]) == (sport,dport,src,dst),
            connlist)
        stream = conns[0]
        offset = stream["offset"]
    except:
        return render_to_response("standalone_error.html",
            {"error": "Could not find the requested stream"},
            context_instance=RequestContext(request))

    try:
        fobj = fs.get(conndata["network"]["sorted_pcap_id"])
        # gridfs gridout has no fileno(), which is needed by dpkt pcap reader for NOTHING
        setattr(fobj, "fileno", lambda: -1)
    except:
        return render_to_response("standalone_error.html",
            {"error": "The required sorted PCAP does not exist"},
            context_instance=RequestContext(request))

    packets = list(network.packets_for_stream(fobj, offset))
    return HttpResponse(json.dumps(packets), content_type="application/json")
