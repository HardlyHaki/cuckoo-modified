# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import zipfile

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooProcessingError

class ProcessMemory(Processing):
    """Analyze process memory dumps."""

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []
        zipdump = self.options.get("zipdump", False)
        zipstrings = self.options.get("zipstrings", False)
        do_strings = self.options.get("strings", False)

        if os.path.exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                dmp_path = os.path.join(self.pmemory_path, dmp)
                dmp_file = File(dmp_path)

                proc = dict(
                    file=dmp_path,
                    pid=os.path.splitext(os.path.basename(dmp_path))[0],
                    yara=dmp_file.get_yara(os.path.join(CUCKOO_ROOT, "data", "yara", "index_memory.yar")),
                    zipdump=zipdump,
                    zipstrings=zipstrings
                )
                    
                if do_strings:
                    try:
                        data = open(dmp_path, "r").read()
                    except (IOError, OSError) as e:
                        raise CuckooProcessingError("Error opening file %s" % e)

                    nulltermonly = self.options.get("nullterminated_only", True)
                    minchars = self.options.get("minchars", 5)

                    if nulltermonly:
                        apat = "([\x20-\x7e]{" + str(minchars) + ",})\x00"
                        strings = re.findall(apat, data)
                        upat = "((?:[\x20-\x7e][\x00]){" + str(minchars) + ",})\x00\x00"
                        strings += [str(ws.decode("utf-16le")) for ws in re.findall(upat, data)]
                        f=open(dmp_path + ".strings", "w")
                        f.write("\n".join(strings))
                        f.close()
                        proc["strings_path"] = dmp_path + ".strings"
                    else:
                        apat = "([\x20-\x7e]{" + str(minchars) + ",})\x00"
                        strings = re.findall(apat, data)
                        upat = "(?:[\x20-\x7e][\x00]){" + str(minchars) + ",}"
                        strings += [str(ws.decode("utf-16le")) for ws in re.findall(upat, data)]
                        f=open(dmp_path + ".strings", "w")
                        f.write("\n".join(strings))
                        f.close()
                        proc["strings_path"] = dmp_path + ".strings"
                    zipstrings = self.options.get("zipstrings", False)
                    if zipstrings:
                        try:
                            f = zipfile.ZipFile("%s.zip" % (proc["strings_path"]), "w")
                            f.write(proc["strings_path"], os.path.basename(proc["strings_path"]), zipfile.ZIP_DEFLATED)
                            f.close()
                            os.remove(proc["strings_path"])
                            proc["strings_path"] = "%s.zip" % (proc["strings_path"]) 
                        except:
                            raise CuckooProcessingError("Error creating Process Memory Strings Zip File %s" % e)

                if zipdump:
                    try:
                        f = zipfile.ZipFile("%s.zip" % (dmp_path), "w")
                        f.write(dmp_path, os.path.basename(dmp_path), zipfile.ZIP_DEFLATED)
                        f.close()
                        os.remove(dmp_path)
                        proc["file"]="%s.zip" % (dmp_path)
                    except:
                        raise CuckooProcessingError("Error creating Process Memory Zip File %s" % e)
                results.append(proc)
        return results
