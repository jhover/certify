#!/bin/bash

python setup.py bdist_rpm
scp2 dist/`ls dist | grep -v src | grep rpm` grid.racf.bnl.gov:/var/www/html/rpms/certify
