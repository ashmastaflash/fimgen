"""Create a FIM policy based on the contents of a package."""
import getopt
import json
import os
import re
import sys

import magic
import rpmfile

from deb_pkg_tools.package import inspect_package_fields
from deb_pkg_tools.package import inspect_package_contents


def main(argv):
    infile = ''
    drop_dir = './'
    usagetext = "Usage: fimgen.py -p PATH_TO_PACKAGE \n Supports rpm and dpkg!"
    try:
        opts, args = getopt.getopt(argv, "hp:", ["packagefile="])
    except getopt.GetoptError:
        print(usagetext)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print usagetext
            sys.exit()
        elif opt in ("-p", "--packagefile"):
            infile = arg
    if os.path.isfile(infile):
        pass
    else:
        print "File does not exist!"
        sys.exit(2)
    pkg_type = determine_pkg_type(infile)
    rulecoll = []
    attr = {"pkg_name": ' ',
            "file_name": str(os.path.split(infile)[1]),
            "distro": ' ',
            "pkg_ver": ' ',
            "pkg_desc": ' ',
            "pkg_type": determine_pkg_type(infile)
            }
    if pkg_type == "RPM":
        attr, filelist = handle_rpm(infile, attr)
    elif pkg_type == "DPKG":
        attr, filelist = handle_dpkg(infile, attr)
    else:
        print "Unidentified package! \n" + pkg_type + "\nPlease try another."
        sys.exit()
    outfile_name = "{}--fim-policy.json".format(attr["file_name"])
    outfile_path = os.path.join(drop_dir, outfile_name)
    policyname = "{} version {} for {} distributions".format(attr['pkg_name'],
                                                             attr['pkg_ver'],
                                                             attr['pkg_type'])
    poldesc = ("Package description:\n {}\n\nThis policy was automatically "
               "generated from the {} package by fimgen.\nOriginal file: {}\n"
               "Distribution: {}\nVersion: {}".format(attr['pkg_desc'],
                                                      attr['pkg_name'],
                                                      attr['file_name'],
                                                      attr['distro'],
                                                      attr['pkg_ver']))
    for f in filelist:
        rulecoll.append(create_fim_rule(f))

    policyout = {"fim_policy": {
                   "name": policyname,
                   "description": poldesc,
                   "platform": "linux",
                   "rules": rulecoll
                   }}
    print "Creating file: ", outfile_path
    with open(outfile_path, 'w') as o:
        o.write(json.dumps(policyout))
    sys.exit()


def create_fim_rule(f):
    # The suppress list contains regex matches for documentation and other
    # files you won't want any sort of high-alert attention directed to
    # in the event they change.
    suppress = ['^/usr/share/doc',
                '^/usr/share/man']
    fimrule = {"target": f,
               "description": "",
               "recurse": False,
               "critical": True,
               "alert": False,
               }
    for s in suppress:
        if re.search(s, f):
            fimrule["critical"] = False
            return fimrule
        else:
            pass
    return fimrule


def handle_rpm(f, attr):
    filelist = []
    with rpmfile.open(f) as rpm:
        attr['pkg_name'] = rpm.headers.get('name')
        attr['pkg_desc'] = rpm.headers.get('description')
        attr['distro'] = rpm.headers.get('distribution')
        attr['pkg_ver'] = rpm.headers.get('version')
    for member in rpm.getmembers():
        if not validate_path(member.name):
            print "Invalid character(s) in path, excluding: ", member.name
            pass
        else:
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
        if not validate_path(k):
            print "Invalid character(s) in path, excluding: ",  k
            pass
        elif re.search(filematch, k):
            pass
        else:
            filelist.append(str(k))
    return(attr, filelist)


def determine_pkg_type(f):
    rpm_match = r"^RPM\s"
    dpkg_match = r"^Debian\sbinary\spackage\s"
    magical = magic.from_file(f)
    if re.search(rpm_match, magical):
        return 'RPM'
    elif re.search(dpkg_match, magical):
        return 'DPKG'
    return magical


def validate_path(p):
    # Halo doesn't support every character that you might find in a unix file
    # path. This ensures that your policies are importable, excluding objects
    # that will fail validation.
    ill_chars = ["+", "@", "%", "~", "#", "!"]
    for c in ill_chars:
        if c in str(p):
            return False
        else:
            pass
    return True


if __name__ == "__main__":
    main(sys.argv[1:])
