# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import re
import os
import sys
import requests
import tempfile
import random
from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.utils import store_temp_file

def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value

def index(request):
    if request.method == "POST":
        package = request.POST.get("package", "")
        timeout = min(force_int(request.POST.get("timeout")), 60 * 60 * 24)
        options = request.POST.get("options", "")
        priority = force_int(request.POST.get("priority"))
        machine = request.POST.get("machine", "")
        gateway = request.POST.get("gateway",None)
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))

        tags = request.POST.get("tags", None)

        if request.POST.get("free"):
            if options:
                options += ","
            options += "free=yes"

        if request.POST.get("nohuman"):
            if options:
                options += ","
            options += "nohuman=yes"

        if request.POST.get("tor"):
            if options:
                options += ","
            options += "tor=yes"

        if request.POST.get("process_memory"):
            if options:
                options += ","
            options += "procmemdump=yes"
        if request.POST.get("kernel_analysis"):
            if options:
                options += ","
            options += "kernel_analysis=yes"
        if gateway:
            if "," in settings.GATEWAYS[gateway]:
                tgateway = random.choice(settings.GATEWAYS[gateway].split(","))
                ngateway = settings.GATEWAYS[tgateway]
            else:
                ngateway = settings.GATEWAYS[gateway]
            if options:
                options += ","
            options += "setgw=%s" % (ngateway)
        db = Database()
        task_ids = []
        task_machines = []

        if machine.lower() == "all":
            for entry in db.list_machines():
                task_machines.append(entry.label)
        else:
            task_machines.append(machine)

        if "sample" in request.FILES:
            for sample in request.FILES.getlist("sample"):
                if sample.size == 0:
                    return render_to_response("error.html",
                                              {"error": "You uploaded an empty file."},
                                              context_instance=RequestContext(request))
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render_to_response("error.html",
                                              {"error": "You uploaded a file that exceeds that maximum allowed upload size."},
                                              context_instance=RequestContext(request))
    
                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(),
                                       sample.name)
                os.chmod(path, 0664) 
                for entry in task_machines:
                    task_id = db.add_path(file_path=path,
                                          package=package,
                                          timeout=timeout,
                                          options=options,
                                          priority=priority,
                                          machine=entry,
                                          custom=custom,
                                          memory=memory,
                                          enforce_timeout=enforce_timeout,
                                          tags=tags)
                    if task_id:
                        task_ids.append(task_id)
        elif "url" in request.POST and request.POST.get("url").strip():
            url = request.POST.get("url").strip()
            
#        elif "url" in request.POST:
#            url = request.POST.get("url").strip()
            if not url:
                return render_to_response("error.html",
                                          {"error": "You specified an invalid URL!"},
                                          context_instance=RequestContext(request))

            if re.match(r"https?\:\/\/[^\x2f]+$",url,re.I):
                url = url + "/"

            for entry in task_machines:
                task_id = db.add_url(url=url,
                                     package=package,
                                     timeout=timeout,
                                     options=options,
                                     priority=priority,
                                     machine=entry,
                                     custom=custom,
                                     memory=memory,
                                     enforce_timeout=enforce_timeout,
                                     tags=tags)
                if task_id:
                    task_ids.append(task_id)
        elif settings.VTDL_ENABLED and "vtdl" in request.POST:
                vtdl = request.POST.get("vtdl").strip()
                if settings.VTDL_KEY == None or settings.VTDL_PATH == None:
                    return render_to_response("error.html",
                                              {"error": "You specified VirusTotal but must edit the file and specify your VTDL_KEY variable and VTDL_PATH base directory"},
                                              context_instance=RequestContext(request))
                else:
                    base_dir = tempfile.mkdtemp(prefix='cuckoovtdl',dir=settings.VTDL_PATH)
                    os.chmod(base_dir, 0774)
                    hashlist = []
                    if "," in vtdl:
                        hashlist=vtdl.split(",")
                    else:
                        hashlist.append(vtdl)

                    for h in hashlist:
                        filename = base_dir + "/" + h
                        url = 'http://www.virustotal.com/vtapi/v2/file/download'
                        params = {'apikey': settings.VTDL_KEY, 'hash': h}

                        r = requests.get(url, params=params)
                        if r.status_code == 200:
                            f = open(filename, 'wb')
                            f.write(r.content)
                            f.close()
                            os.chmod(filename, 0664)
                            for entry in task_machines:
                                task_id = db.add_path(file_path=filename,
                                          package=package,
                                          timeout=timeout,
                                          options=options,
                                          priority=priority,
                                          machine=entry,
                                          custom=custom,
                                          memory=memory,
                                          enforce_timeout=enforce_timeout,
                                          tags=tags)
                                if task_id:
                                    task_ids.append(task_id)

        tasks_count = len(task_ids)
        if tasks_count > 0:
            return render_to_response("submission/complete.html",
                                      {"tasks" : task_ids,
                                       "tasks_count" : tasks_count},
                                      context_instance=RequestContext(request))
        else:
            return render_to_response("error.html",
                                      {"error": "Error adding task to Cuckoo's database."},
                                      context_instance=RequestContext(request))
    else:
        files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

        packages = []
        for name in files:
            name = os.path.splitext(name)[0]
            if name == "__init__":
                continue

            packages.append(name)

        # Prepare a list of VM names, description label based on tags.
        machines = []
        for machine in Database().list_machines():
            tags = []
            for tag in machine.tags:
                tags.append(tag.name)

            if tags:
                label = machine.label + ": " + ", ".join(tags)
            else:
                label = machine.label

            machines.append((machine.label, label))

        # Prepend ALL/ANY options.
        machines.insert(0, ("", "First available"))
        machines.insert(1, ("all", "All"))

        return render_to_response("submission/index.html",
                                  {"packages": sorted(packages),
                                   "machines": machines,
                                   "gateways": settings.GATEWAYS,
                                   "vtdlenabled": settings.VTDL_ENABLED,
                                   "torenabled": settings.TOR_ENABLED,
                                   "zmonenabled": settings.DISPLAY_ZMON},
                                  context_instance=RequestContext(request))

def status(request, task_id):
    task = Database().view_task(task_id)
    if not task:
        return render_to_response("error.html",
                                  {"error": "The specified task doesn't seem to exist."},
                                  context_instance=RequestContext(request))

    completed = False
    if task.status == "reported":
        completed = True

    return render_to_response("submission/status.html",
                              {"completed" : completed,
                               "status" : task.status,
                               "task_id" : task_id},
                              context_instance=RequestContext(request))
