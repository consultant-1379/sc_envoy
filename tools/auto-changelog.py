#!/bin/env python3
# Devan Nair
# Thu Jun 2 2022
# Automatically adapt Changelog between two tags
# Use expandtabs(<num-chars>) to have aligned usage of tabs

import argparse
import os
import re
import yaml

def listOneLinesBetweenTags(head,prev):
    op = os.popen('git log \''+head+'\''+'...'+'\''+prev+'\''+' --oneline').read()
    res = []

    for line in op.split('\n'):
        if 'Merge branch' in line:
            pass
        else :
            res.append(line)
    return res

def getEnvoyBuilderVersion():
    with open('../../../../ruleset2.0-eric-envoy.yaml', 'r') as fopen:
        try:
            data = yaml.safe_load(fopen)
            prop = data['properties']
            for dicts in prop:
                if 'ENVOY_BUILDER_VERSION' in dicts:
                    return dicts.get('ENVOY_BUILDER_VERSION')
        except yaml.YAMLError as exc:
            print(exc)


def getGitCommitId(head):
#    op = os.popen('git show-ref \''+head+'\'').read()
    op = os.popen('git log --decorate=short').read()
    for line in op.split('\n'):
        if head in line:
            match = re.search(r'commit ([0-9a-fA-F]+)',line)
            if match:
                return match.group(1)[:10]

def getGitTags():
    op = os.popen('git log --decorate=short').read()
    result = []
    count = 2
    for line in op.split('\n'):
        if count == 0:
            return result
        if 'tag' in line:
            match = re.search(r'tag: ([^),]+),', line)
            if match and count != 0:
                result.append(match.group(1))
                count = count - 1

    return result

def getGitBranch():
    op = os.popen('git rev-parse --abbrev-ref HEAD').read()
    return op[:-1]

def constructUpdate(head,prev):
    builderVersion = getEnvoyBuilderVersion()
    branchName= getGitBranch()
    fl = head[7:] + ' ('+builderVersion+') '+ 'Built from "sc_envoy" repository ('+branchName+') (commit: '+ getGitCommitId(head) +')'
    #commits = '\t\t'+listOneLinesBetweenTags(head,prev)
    for commit in listOneLinesBetweenTags(head,prev):
        fl = fl + '\n\t\t\t\t   '.expandtabs(4) + commit.lstrip()
    return fl

def writeChangelog(head,prev):
    preamble = 'This file contains local changes of Envoy performed by the development team.\nThe purpose is to take track of these changes and map them to the corresponding internal version numbers.\nFrom 1.15.2-2 on, the builder version is also specified.\n\n'
    filename = '../../Changelog-Envoy'
    try:
        with open(filename,'r') as contents:
            for i in range(1,4):
                contents.readline()
            save = contents.read()
        with open(filename,'w') as contents:
            update = constructUpdate(head,prev)
            contents.write(preamble)
            contents.write(update)
        with open(filename,'a') as contents:
            contents.write(save)
    except Exception as e:
        print(e)

if __name__=="__main__":
    print("Auto updating Changelog")
    parser= argparse.ArgumentParser(description='Update Changelog based on git Tag')
    parser.add_argument('-t','--top',help='Tag closest to head')
    parser.add_argument('-b','--bottom',help='Tag previous to current')

    args=parser.parse_args()
    if args.top is not None and args.bottom is not None:
        print('From Commandline Arguments...')
        print('Head Tag:'+args.top)
        print('Tail Tag:'+args.bottom)
        writeChangelog(args.top,args.bottom)
    else :
        print('From git logs...')
        tags = getGitTags()
        print('Head Tag:'+tags[0])
        print('Tail Tag:'+tags[1])
        writeChangelog(tags[0],tags[1])

