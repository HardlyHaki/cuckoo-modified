# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys
import copy
import json
import urllib
import urllib2
import logging
import logging.handlers
import datetime

import modules.auxiliary
import modules.processing
import modules.signatures
import modules.reporting
import modules.feeds

from lib.cuckoo.common.colors import red, green, yellow, cyan
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.utils import create_folders, store_temp_file, delete_folder
from lib.cuckoo.core.database import Database, Task, TASK_RUNNING, TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING, TASK_RECOVERED
from lib.cuckoo.core.plugins import import_plugin, import_package, list_plugins
from bson.objectid import ObjectId

log = logging.getLogger()

def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    if sys.version_info[:2] != (2, 7):
        raise CuckooStartupError("You are running an incompatible version "
                                 "of Python, please use 2.7")


def check_working_directory():
    """Checks if working directories are ready.
    @raise CuckooStartupError: if directories are not properly configured.
    """
    if not os.path.exists(CUCKOO_ROOT):
        raise CuckooStartupError("You specified a non-existing root "
                                 "directory: {0}".format(CUCKOO_ROOT))

    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's "
                                 "root directory")


def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"),
               os.path.join(CUCKOO_ROOT, "conf", "reporting.conf"),
               os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf")]

    for config in configs:
        if not os.path.exists(config):
            raise CuckooStartupError("Config file does not exist at "
                                     "path: {0}".format(config))

    return True

def check_signatures():
    """Checks if user pulled in community signature modules
    @raise CuckooStartupError: if community signature modules not installed.
    """

    sigpath = os.path.join(CUCKOO_ROOT, "modules", "signatures")
    bad = False

    if os.path.exists(sigpath):
        path, dirs, files = os.walk(sigpath).next()
        if len(files) < 20:
            bad = True
    else:
        bad = True

    if bad:
        raise CuckooStartupError("Signature modules are not installed.  Please run: utils/community.py --force --rewrite --all")

def create_structure():
    """Creates Cuckoo directories."""
    folders = [
        "log",
        "storage",
        os.path.join("storage", "analyses"),
        os.path.join("storage", "binaries"),
        os.path.join("data", "feeds"),
    ]

    try:
        create_folders(root=CUCKOO_ROOT, folders=folders)
    except CuckooOperationalError as e:
        raise CuckooStartupError(e)

class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        if hasattr(record, "task_id"):
            db = Database()
            db.add_error(record.msg, int(record.task_id))

class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)
        elif record.levelname == "ERROR" or record.levelname == "CRITICAL":
            colored.msg = red(record.msg)
        else:
            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)

def init_logging():
    """Initializes logging."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "cuckoo.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    dh = DatabaseHandler()
    dh.setLevel(logging.ERROR)
    log.addHandler(dh)

    log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)

def init_console_logging():
    """Initializes logging only to console."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(logging.INFO)

def init_tasks():
    """Check tasks and reschedule uncompleted ones."""
    db = Database()
    cfg = Config()

    log.debug("Checking for locked tasks...")
    tasks = db.list_tasks(status=TASK_RUNNING)

    for task in tasks:
        if cfg.cuckoo.reschedule:
            db.reschedule(task.id)
            log.info("Rescheduled task with ID {0} and "
                     "target {1}".format(task.id, task.target))
        else:
            db.set_status(task.id, TASK_FAILED_ANALYSIS)
            log.info("Updated running task ID {0} status to failed_analysis".format(task.id))

def init_modules():
    """Initializes plugins."""
    log.debug("Importing modules...")

    # Import all auxiliary modules.
    import_package(modules.auxiliary)
    # Import all processing modules.
    import_package(modules.processing)
    # Import all signatures.
    import_package(modules.signatures)
    # Import all reporting modules.
    import_package(modules.reporting)
    # Import all feeds modules.
    import_package(modules.feeds)

    # Import machine manager.
    import_plugin("modules.machinery." + Config().cuckoo.machinery)

    for category, entries in list_plugins().items():
        log.debug("Imported \"%s\" modules:", category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)

def init_yara():
    """Generates index for yara signatures."""

    def find_signatures(root):
        signatures = []
        for entry in os.listdir(root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(root, entry))

        return signatures

    log.debug("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # We divide yara rules in three categories.
    categories = ["binaries", "urls", "memory"]
    generated = []
    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not os.path.exists(category_root):
            continue

        # Check if the directory contains any rules.
        signatures = []
        for entry in os.listdir(category_root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(category_root, entry))

        if not signatures:
            continue

        # Generate path for the category's index file.
        index_name = "index_{0}.yar".format(category)
        index_path = os.path.join(yara_root, index_name)

        # Create index file and populate it.
        with open(index_path, "w") as index_handle:
            for signature in signatures:
                index_handle.write("include \"{0}\"\n".format(signature))

        generated.append(index_name)

    for entry in generated:
        if entry == generated[-1]:
            log.debug("\t `-- %s", entry)
        else:
            log.debug("\t |-- %s", entry)


def cuckoo_clean():
    """Clean up cuckoo setup.
    It deletes logs, all stored data from file system and configured databases (SQL
    and MongoDB.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Initialize the database connection.
    db = Database()

    # Drop all tables.
    db.drop()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            conn = MongoClient(host, port)
            conn.drop_database(mdb)
            conn.close()
        except:
            log.warning("Unable to drop MongoDB database: %s", mdb)

    # Check if ElasticSearch is enabled and delete that data if it is.
    if cfg.elasticsearchdb and cfg.elasticsearchdb.enabled:
        from elasticsearch import Elasticsearch
        delidx = cfg.elasticsearchdb.index + "-*"
        try:
            es = Elasticsearch(
                     hosts = [{
                         "host": cfg.elasticsearchdb.host,
                         "port": cfg.elasticsearchdb.port,
                     }],
                     timeout = 60
                 )
        except:
            log.warning("Unable to connect to ElasticSearch")

        if es:
            analyses = es.search(
                           index=delidx,
                           doc_type="analysis",
                           q="*"
                       )["hits"]["hits"]
        if analyses:
            for analysis in analyses:
                esidx = analysis["_index"]
                esid = analysis["_id"]
                # Check if behavior exists
                if analysis["_source"]["behavior"]:
                    for process in analysis["_source"]["behavior"]["processes"]:
                        for call in process["calls"]:
                            es.delete(
                                index=esidx,
                                doc_type="calls",
                                id=call,
                            )
                # Delete the analysis results
                es.delete(
                    index=esidx,
                    doc_type="analysis",
                    id=esid,
                )

    # Paths to clean.
    paths = [
        os.path.join(CUCKOO_ROOT, "db"),
        os.path.join(CUCKOO_ROOT, "log"),
        os.path.join(CUCKOO_ROOT, "storage"),
    ]

    # Delete various directories.
    for path in paths:
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
            except (IOError, OSError) as e:
                log.warning("Error removing directory %s: %s", path, e)

    # Delete all compiled Python objects ("*.pyc").
    for dirpath, dirnames, filenames in os.walk(CUCKOO_ROOT):
        for fname in filenames:
            if not fname.endswith(".pyc"):
                continue

            path = os.path.join(CUCKOO_ROOT, dirpath, fname)

            try:
                os.unlink(path)
            except (IOError, OSError) as e:
                log.warning("Error removing file %s: %s", path, e)


def remove_task(task_id):
    #for this not to take eternity you need to create the following indexes
    #mongo
    #use cuckoo
    #db.analysis.createIndex({"shots":1},{"background":1})
    #db.analysis.createIndex({"network.pcap_id":1},{"background":1})
    #db.analysis.createIndex({"network.sorted_pcap_id":1},{"background":1})
    #db.analysis.createIndex({"dropped.object_id":1},{"background":1})
    #db.suricata.createIndex({"files.object_id":1},{"background":1})
    #db.analysis.createIndex({"info.custom":1},{"background":1})

    # Initialize the database connection.
    db = Database()
    
    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        from gridfs import GridFS
        try:
            results_db = MongoClient(host, port)[mdb]
        except:
            log.warning("Unable to connect to MongoDB database: %s", mdb)
            return
        
        analyses = results_db.analysis.find({"info.id": int(task_id)})
        suri = results_db.suricata.find({"info.id": int(task_id)})
        fs = GridFS(results_db)

        print "going to delete task id %s" % (task_id)
        # Checks if more analysis found with the same ID, like if process.py was run manually.
        if analyses.count() > 1:
            message = "Multiple tasks with this ID deleted."
        elif analyses.count() == 1:
            message = "Task deleted."

        if analyses.count() > 0:
            # Delete dups too.
            for analysis in analyses:
                print "deleting target"
                # Delete sample if not used.
                if "file_id" in analysis["target"]:
                    if results_db.analysis.find({"target.file_id": ObjectId(analysis["target"]["file_id"])}).count() == 1:
                        fs.delete(ObjectId(analysis["target"]["file_id"]))
                print "deleting screenshots"
                # Delete screenshots.
                for shot in analysis["shots"]:
                    if results_db.analysis.find({"shots": ObjectId(shot)}).count() == 1:
                        fs.delete(ObjectId(shot))
                print "deleting pcap"
                # Delete network pcap.
                if "pcap_id" in analysis["network"] and results_db.analysis.find({"network.pcap_id": ObjectId(analysis["network"]["pcap_id"])}).count() == 1:
                    fs.delete(ObjectId(analysis["network"]["pcap_id"]))

                print "deleting sorted_pcap"
                # Delete sorted pcap
                if "sorted_pcap_id" in analysis["network"] and results_db.analysis.find({"network.sorted_pcap_id": ObjectId(analysis["network"]["sorted_pcap_id"])}).count() == 1:
                    fs.delete(ObjectId(analysis["network"]["sorted_pcap_id"]))

                print "deleting dropped"
                # Delete dropped.
                for drop in analysis["dropped"]:
                    if "object_id" in drop and results_db.analysis.find({"dropped.object_id": ObjectId(drop["object_id"])}).count() == 1:
                        fs.delete(ObjectId(drop["object_id"]))               
                print "deleting calls"
                # Delete calls.
                for process in analysis.get("behavior", {}).get("processes", []):
                    for call in process["calls"]:
                        results_db.calls.remove({"_id": ObjectId(call)})
                print "remove analysis data"
                # Delete analysis data.
                results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
                # we may not have any suri entries
                if suri.count() > 0:
                    for suricata in suri:
                        if "files" in suricata.keys():
                            print "removing suri files"
                            for entry in suricata["files"]:
                                if "object_id" in entry and results_db.suricata.find({"files.object_id": ObjectId(entry["object_id"])}).count() == 1:
                                    fs.delete(ObjectId(entry["object_id"]))

                        results_db.suricata.remove({"_id": ObjectId(suricata["_id"])})
        print "remove task from db"
        result = db.delete_task(task_id)
        if not result:
            print "failed to remove from db"
        print "removing file structure"
        delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses",
                      "%s" % int(task_id)))

def cuckoo_clean_failed_tasks():
    """Clean up failed tasks 
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Initialize the database connection.
    db = Database()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            results_db = MongoClient(host, port)[mdb]
        except:
            log.warning("Unable to connect to MongoDB database: %s", mdb)
            return 

        failed_tasks_a = db.list_tasks(status=TASK_FAILED_ANALYSIS)
        failed_tasks_p = db.list_tasks(status=TASK_FAILED_PROCESSING)
        failed_tasks_r = db.list_tasks(status=TASK_FAILED_REPORTING)
        failed_tasks_rc = db.list_tasks(status=TASK_RECOVERED)
        for e in failed_tasks_a,failed_tasks_p,failed_tasks_r,failed_tasks_rc:
            for el2 in e:
                new = el2.to_dict()
                remove_task(new["id"])


def cuckoo_clean_failed_url_tasks():
    """Clean up failed tasks 
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Initialize the database connection.
    db = Database()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            results_db = MongoClient(host, port)[mdb]
        except:
            log.warning("Unable to connect MongoDB database: %s", mdb)
            return

        done = False
        while not done:
            rtmp = results_db.analysis.find({"info.category": "url", "network.http.0": {"$exists": False}},{"info.id": 1},sort=[("_id", -1)]).limit( 100 )
            if rtmp and rtmp.count() > 0:
                for e in rtmp:
                    if e["info"]["id"]:
                        print e["info"]["id"]
                        remove_task(e["info"]["id"])
                    else:
                        done = True
            else:
                done = True 

def cuckoo_clean_before_day(args):
    """Clean up failed tasks 
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for tasks completed before now - days.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    print args
    if not args.delete_older_than_days:
        print "No days argument provided bailing"
        return
    else:
        days = args.delete_older_than_days
    create_structure()
    init_console_logging()
    id_arr = []

    # Initialize the database connection.
    db = Database()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            results_db = MongoClient(host, port)[mdb]
        except:
            log.warning("Unable to connect to MongoDB database: %s", mdb)
            return
        added_before = datetime.datetime.now() - datetime.timedelta(days=int(days))
        if args.files_only_filter:
            print("file filter applied")
            old_tasks = db.list_tasks(added_before=added_before,category="file")
        elif args.urls_only_filter:
            print("url filter applied")
            old_tasks = db.list_tasks(added_before=added_before,category="url")
        else:
            old_tasks = db.list_tasks(added_before=added_before)

        for e in old_tasks:
            new = e.to_dict()
            print int(new["id"])
            id_arr.append({"info.id":(int(new["id"]))})
        print "number of matching records %s before suri/custom filter " % len(id_arr)
        for e in id_arr:
            if args.suricata_zero_alert_filter:
                result = results_db.suricata.find_one({"info.id":e["info.id"],"alerts.alert": {"$exists": False}},{"info.id":1})
                if not result:
                    continue
            if args.custom_include_filter:
                result = results_db.analysis.find_one({"info.id":e["info.id"],"info.custom": {"$regex": args.custom_include_filter}},{"info.id":1})
                if not result:
                    continue
            try:
                print "removing %s matches all filters" % (e["info.id"])
                remove_task(e["info.id"])
            except Exception as er:
                print "failed to remove task %s %s" % (e["info.id"],er)

def cuckoo_clean_sorted_pcap_dump():
    """Clean up failed tasks 
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Initialize the database connection.
    db = Database()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            results_db = MongoClient(host, port)[mdb]
        except:
            log.warning("Unable to connect MongoDB database: %s", mdb)
            return

        done = False
        while not done:
            rtmp = results_db.analysis.find({"network.sorted_pcap_id": {"$exists": True}},{"info.id": 1},sort=[("_id", -1)]).limit( 100 )
            if rtmp and rtmp.count() > 0:
                for e in rtmp:
                    if e["info"]["id"]:
                        print e["info"]["id"]
                        try:
                            results_db.analysis.update({"info.id": int(e["info"]["id"])},{ "$unset": { "network.sorted_pcap_id": ""}})
                        except:
                            print "failed to remove sorted pcap from db for id %s" % (e["info"]["id"])
                        try:      
                            path = os.path.join(CUCKOO_ROOT, "storage", "analyses","%s" % (e["info"]["id"]), "dump_sorted.pcap")
                            os.remove(path)
                        except Exception as e:
                            print "failed to remove sorted_pcap from disk %s" % (e)
                    else:
                        done = True
            else:
                done = True

def cuckoo_clean_suricata_files_zip():
    """Clean up failed tasks 
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Initialize the database connection.
    db = Database()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            results_db = MongoClient(host, port)[mdb]
        except:
            log.warning("Unable to connect MongoDB database: %s", mdb)
            return

        done = False
        while not done:
            rtmp = results_db.suricata.find({"suri_extracted_zip": {"$exists": True}},{"info.id": 1},sort=[("_id", -1)]).limit( 100 )
            if rtmp and rtmp.count() > 0:
                print rtmp.count()
                for e in rtmp:
                    if e["info"]["id"]:
                        print e["info"]["id"]
                        try:
                            results_db.suricata.update({"info.id": int(e["info"]["id"])},{ "$unset": { "suri_extracted_zip": ""}})
                        except:
                            print "failed to remove sorted pcap from db for id %s" % (e["info"]["id"])
                        try:
                            path = os.path.join(CUCKOO_ROOT, "storage", "analyses","%s" % (e["info"]["id"]), "logs","files.zip")
                            if os.path.exists(path):
                                os.remove(path)
                        except Exception as e:
                            print "failed to remove suricata zip from disk %s" % (e)
                    else:
                        done = True
            else:
                done = True
