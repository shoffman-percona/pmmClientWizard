#!/usr/bin/env bash
#
# This script will perform all needed steps to install pmm's latest client, connect 
# to a PMM server, create a monitoring DB user and start monitoring
#
#

set -Eeuo pipefail 
trap cleanup SIGINT SIGTERM ERR EXIT

# Set defaults
default_db_username="pmm_monitor"
default_db_password="S0meWh@tSafe?"

#######################################
# Show Script Usage Information
#######################################


#######################################
# Defines colours for output messages.
#######################################
setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m'
    BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' YELLOW='\033[1;33m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE='' BLUE='' PURPLE='' CYAN='' YELLOW=''
  fi
}

#######################################
# Prints message to stderr with new line at the end.
#######################################
msg() {
  echo >&2 -e "${1-}"
}

#######################################
# Prints message and exit with code.
# Arguments:
#   message string;
#   exit code.
# Outputs:
#   writes message to stderr.
#######################################
die() {
  local msg=$1
  local code=${2-1} # default exit status 1
  msg "$msg"
  exit "$code"
}

#######################################
# Clean up setup if interrupt.
#######################################
cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
}

######################################
# Check if command exists
######################################
check_command() {
	command -v "$@" 1>/dev/null
}

#######################################
# Runs command as root.
#######################################
run_root() {
  sh='sh -c'
  if [ "$(id -un)" != 'root' ]; then
    if check_command sudo; then
      sh='sudo -E sh -c'
    elif check_command su; then
      sh='su -c'
    else
      die "${RED}ERROR: root rights needed to run "$*" command${NOFORMAT}"
    fi
  fi
  ${sh} "$@"
}

#######################################
# What is the OS (to know what packages to get)
#######################################

check_os() {
	case "$(uname -s)" in
   	*darwin* | *Darwin* ) OS=mac ;;
	*Linux* | *linux* ) 
 	   case "$(awk -F= '/^ID_LIKE/{print $2}' /etc/os-release)" in 
		*rhel* ) OS=redhat ;;
		*debian* ) OS=debian ;;
  	   esac	  
	;;
   esac
}



##############################################
# Check if  pmm client installed and the latest version
##############################################
if ! check_command pmm-admin; then
	echo "PMM Client not installed, downloading and installing"
	check_os
	echo "OS is $OS"
	if [ $OS == "mac" ]; then
		echo "Mac is not supported for this installer yet"
		exit
	elif [ $OS == "debian" ]; then
		run_root 'apt install -y wget gnupg2 lsb-release'
		wget https://repo.percona.com/apt/percona-release_latest.generic_all.deb
		run_root 'dpkg -i percona-release_latest.generic_all.deb'
		run_root 'apt update'
		run_root 'apt install pmm2-client'
		rm -f percona-release_latest.generic_all.deb
	elif [ $OS == "redhat" ]; then 
		echo "installing for redhat"
	else
		echo "could not detect os properly"
	fi
else
	echo "PMM Client installed, moving to configuration"	
fi






# test connectivity to PMM Server





# Connect to PMM server
############################################
# Gather Data to setup monitoring user
############################################
collect_params() {
	echo -n "Please provide a monitoring username [$default_db_username]:"; read db_username 
	: ${db_username:="$default_db_username"}
	proceed="false"

	until [ $proceed == "true" ]
	do
		echo -n "Please provide a password for the monitoring user [$default_db_password]" ; read -s db_password 
		: ${db_password:="$default_db_password"}
		echo
		if [ $db_password != $default_db_password ]; then
			echo -n "Please re-enter password to confirm:" ; read -s db_password2
			if [ $db_password == $db_password2 ] ; then 
				proceed="true"
			else
				echo
				echo -n "Passwords do not match, try again"
			fi
		else 
			proceed="true"
		fi
	done
}

###############################################
# set up database user
###############################################
setup_mongo() {
	if ! check_command mongo; then
		echo "mongo command not detected...is mongodb installed on this server?"
#		exit
	fi
#	mongo <<EOF
cat <<EOF
db.getSiblingDB("admin").createRole({
    role: "explainRole",
    privileges: [{
        resource: {
            db: "",
            collection: ""
            },
        actions: [
            "listIndexes",
            "listCollections",
            "dbStats",
            "dbHash",
            "collStats",
            "find"
            ]
        }],
    roles:[]
})

db.getSiblingDB("admin").createUser({
   user: "$db_username",
   pwd: "$db_password",
   roles: [
      { role: "explainRole", db: "admin" },
      { role: "clusterMonitor", db: "admin" },
      { role: "read", db: "local" }
   ]
})

EOF

}

setup_postgres() {
        if ! check_command psql; then
                echo "psql command not detected...is Postgres installed on this server?"
#               exit
        fi
        psql <<EOF
CREATE USER $db_username WITH SUPERUSER ENCRYPTED PASSWORD '$db_password'
ALTER USER $db_username CONNECTION LIMIT 10;
EOF

#need to find the location of the pg_hba.conf file to add access for the PMM user
hba_location=run_root "psql -t -P format=unaligned -c 'show hba_file';"


echo "local   all             pmm                                md5" >> $hba_location 


}

setup_mysql() {
	if ! check_command mysql; then
		echo "mysql command not detected...is MySQL client installed on this server?"
		exit
	fi
	echo -n "Please provide a username that has the CREATE USER privilege: "; read monitor_username
	echo -n "Please provide the password for the user $monitor_username: "; read -s monitor_password
	echo
	echo -n "Please provide the hostname/IP of your MySQL server: "; read monitor_hostname
	echo -n "Please provide the port that your mysql server is running on (default 3306): " ; read monitor_port
	: ${monitor_port:="3306"}

mysql -u $monitor_username -p $monitor_password -h $monitor_hostname -P $monitor_port << MYSQL_SCRIPT
CREATE USER '$db_username'@'localhost' IDENTIFIED BY '$db_password' WITH MAX_USER_CONNECTIONS 10;
GRANT SELECT, PROCESS, REPLICATION CLIENT, RELOAD ON *.* TO '$db_username'@'localhost';
MYSQL_SCRIPT
	if [ $? -eq 0 ] ; then
		echo "Successfully added a monitoring user"
	else 
		echo "There was a problem creating a monitoring user, check your logs, fix and try again"
	fi

}

###############################################
# register with PMM
################################################
register_pmm_node() {

	#Register server to PMM
	echo -n "Please provide an admin account to register with your PMM server [admin]: "; read pmm_username
	: ${pmm_username:="admin"}
	
	echo -n "Please provide the password for the "$pmm_username" account: "; read -s pmm_password
	echo 

	echo -n "Please provide the hostname or IP address of your PMM server: "; read pmm_hostname
#logic needed so can't be blank...probably password too

	echo -n "Please provide a secure port for your pmm server [443]: "; read pmm_port
	: ${pmm_port:="443"}

	echo -n "Please provide a friendly name for this system [`hostname -s`]: "; read pmm_node_name
	: ${pmm_node_name:="`hostname -s`"}


	pmm-admin config --server-insecure-tls --server-url=https://$pmm_username:$pmm_password@$pmm_hostname:$pmm_port $pmm_hostname generic $pmm_node_name
	#register_command="pmm-admin config --server-insecure-tls --server-url=https://$pmm_username:$pmm_password@$pmm_hostname:$pmm_port" $pmm_hostname generic $pmm_node_nam
	#echo $register_command
	#run_root '$register_command'
	

#connect client with sane defaults
	#mysql
	echo -n "Please choose either 'perfschema' or 'slowlog' for detailed Query Analytics [perfschema]: "; read pmm_qan
	: ${pmm_qan:="perfschema"}

	pmm-admin add $database --username=$db_username --password=$db_password --query-source=$pmm_qan
	#monitor_command="pmm-admin add $database --username=$db_username --password=$db_password --query-source=$pmm_qan"
	#echo $monitor_command
	#run_root '$register_command'





}




################################################
# manually specify DB options
# FUTURE: auto-detect before failing to prompt
###############################################
select database in mysql postgresql mongodb exit; do  
	case $database in 
		mysql ) echo "Gathering info for MySQL"
		collect_params
		setup_mysql
		register_pmm_node
		break ;;
		postgresql ) echo "Gathering info for PostgreSQL"
		collect_params
		setup_postgres
		break ;;
		mongodb ) echo "Gathering info for MongoDB"
		collect_params
		setup_mongo
		break ;;
		exit) echo "exiting"
		break ;;
	esac
done






# enable services (pg_stat_monitor, other)








# gather inputs




#locally execute or remote execute


