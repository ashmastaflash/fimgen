# This will accept an RPM file as an argument, and write out a json representing all files in the RPM

import os
import re
import sys
import json
import magic
import rpmfile
import getopt
from deb_pkg_tools.package import inspect_package_fields
from deb_pkg_tools.package import inspect_package_contents



def main(argv):
    infile = ''
    drop_dir = './'
    usagetext = "Usage: fimgen.py -p PATH_TO_PACKAGE \n Supports rpm and dpkg!"
    try:
        opts, args = getopt.getopt(argv, "hp:",["packagefile="])
    except getopt.GetoptError:
        print config["usagetext"]
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print usagetext
            sys.exit()
        elif opt in ("-p","--packagefile"):
            infile = arg
    if os.path.isfile(infile):
        pass
    else:
        print "File does not exist!"
        sys.exit(2)
    pkg_type = determine_pkg_type(infile)
    rulecoll = []
    attr = {"pkg_name": '',
            "pkg_type": '',
            "file_name": str(os.path.split(infile)[1]),
            "distro": '',
            "pkg_ver": '',
            "pkg_desc": '',
            "pkg_type": determine_pkg_type(infile)
            }
    if pkg_type == "RPM":
        attr, filelist = handle_rpm(infile, attr)
    elif pkg_type == "DPKG":
        attr, filelist = handle_dpkg(infile, attr)
    else:
        print "Unidentified package! \n" + pkg_type + "\nPlease try another."
        sys.exit()

    outfile = drop_dir + attr["file_name"] +  '--fim-policy.json'
    policyname = str(attr['pkg_name']) + " version " + str(attr['pkg_ver']) + " for " + str(attr['pkg_type']) + " distributions"
    poldesc = "Package Description: \n" + attr['pkg_desc'] + "\n\n" \
            "This policy was auto-generated from the " + attr['pkg_name'] + " package by fimgen (https://github.com/ashmastaflash/fimgen)\n" \
            "Original file: " + attr['file_name'] + "\n" \
            "Distribution: " + attr['distro'] + "\n" \
            "Version: " + attr['pkg_ver'] + "\n"
    #print "File name: ", outfile
    #print "Policy Name: \n", policyname, "\n\n"
    #print "Policy Description: ", poldesc, "\n\n"
    #print "File List:\n"
    for f in filelist:
        rulecoll.append(create_fim_rule(f))

    policyout = {"fim_policy": {
                   "name": policyname,
                   "description": poldesc,
                   "platform": "linux",
                   "rules": rulecoll
                   }}
    print "Resulting Policy: \n", json.dumps(policyout)
    print "Creating file: ", outfile
    with open(outfile, 'w') as o:
        o.write(json.dumps(policyout))
    sys.exit()


def create_fim_rule(f):
    fimrule = {"target": f,
               "description": "",
               "recurse": False,
               "critical": True,
               "alert": False,
               }
    return fimrule

def handle_rpm(f, attr):
    filelist = []
    with rpmfile.open(f) as rpm:
        #for l in  rpm.headers.keys():
        #    print l ,'=====',rpm.headers.get(l),'\n'
        attr['pkg_name'] = rpm.headers.get('name')
        attr['pkg_desc'] = rpm.headers.get('description')
        attr['distro'] = rpm.headers.get('distribution')
        attr['pkg_ver'] = rpm.headers.get('version')
    for member in rpm.getmembers():
        filelist.append(member.name.lstrip('.'))
    return(attr, filelist)

def handle_dpkg(f, attr):
    filematch = '/$'
    filelist = []
    attr['pkg_name'] = inspect_package_fields(f)['Package']
    attr['pkg_desc'] = inspect_package_fields(f)['Description']
    attr['distro'] = 'none'
    attr['pkg_ver'] = inspect_package_fields(f)['Version']
    for k in inspect_package_contents(f):
        if re.search(filematch, k):
            pass
        else:
            filelist.append(str(k))
    return(attr, filelist)

def determine_pkg_type(f):
    rpm_match = '^RPM\s'
    dpkg_match = '^Debian\sbinary\spackage\s'
    magical = magic.from_file(f)
    if re.search(rpm_match, magical):
        return 'RPM'
    elif re.search(dpkg_match, magical):
        return 'DPKG'
    return magical


if __name__ == "__main__":
    main(sys.argv[1:])
