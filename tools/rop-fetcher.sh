#! /usr/bin/sh
# Author : Devan Nair

set -e

command -v sshpass >/dev/null 2>&1 || { echo >&2 "Requires sshpass, do module avail sshpass.  Aborting..."; exit 1; }

if [[ -z "${NS}" ]]; then 
    echo No namespace set in  environment variable NS
    echo Using default namespace 5g-bsf-${USER}
    export NS=5g-bsf-${USER}
fi
export PMBR_POD=$(kubectl -n $NS get pods -o=jsonpath='{.items[?(@.metadata.labels.app=="eric-pm-bulk-reporter")].metadata.name}') 
mkdir -p rop
echo Fetching ROP files with counter $1 from namespace $NS
export PMBR_PORT=$(kubectl get -n $NS svc eric-pm-bulk-reporter -o jsonpath="{.spec.ports[0].nodePort}")
export PMBR_NODE=$(kubectl get -n $NS pods -l app=eric-pm-bulk-reporter -o jsonpath="{.items[0].status.hostIP}")
echo PMBR Node IP $PMBR_NODE
echo PMBR Port $PMBR_PORT

if [ $# -eq 0 ]
    then 
    myarray=($(kubectl -n $NS exec -it $PMBR_POD -c eric-pm-bulk-reporter -- /bin/sh -c "ls -d /PerformanceManagementReportFiles/*"))      
else
    myarray=($(kubectl -n $NS exec -it $PMBR_POD -c eric-pm-bulk-reporter -- /bin/sh -c "grep -Rl $1 /PerformanceManagementReportFiles"))
fi
for el in "${myarray[@]}"                                                                                                                    
do
   # echo "${el}"
    sshpass -p rootroot sftp -P $PMBR_PORT expert@$PMBR_NODE:${el} ./rop/
done

echo PM-ROP XML files fetched in ./rop
