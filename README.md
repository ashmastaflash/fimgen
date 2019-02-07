This script creates FIM policies for CloudPassage Halo, using rpm or deb packages for file lists.  This requires dpkg to be installed (Mac can get it using homebrew) and a couple of other dependencies.

The Dockerfile shows how to parse an RPM file and generate a json policy. Requirements are in requirements.txt.

Known issue with parsing some RPM files using the rpmfile module: https://github.com/srossross/rpmfile/issues/3
