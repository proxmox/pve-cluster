#!/bin/sh
#
### BEGIN INIT INFO
# Provides:          pve-cluster
# Required-Start:    $remote_fs $network $syslog $time fuse
# Required-Stop:     $remote_fs $network $syslog $time fuse
# X-Start-Before:    apache2
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Starts the pve cluster filesystem
# Description:       Starts and stops the pve cluster filesystem
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

DAEMON=/usr/bin/pmxcfs        # Introduce the server's location here
NAME=pve-cluster              # Introduce the short server's name here
DESC="pve cluster filesystem" # Introduce a short description here

PIDFILE=/var/run/$NAME.pid

test -x $DAEMON || exit 0

. /lib/lsb/init-functions

# Default options, these can be overriden by the information
# at /etc/default/$NAME
DAEMON_OPTS="-q"          # Additional options given to the server
                        
# Include defaults if available
if [ -f /etc/default/$NAME ] ; then
	. /etc/default/$NAME
fi

set -e

running_pid() {
# Check if a given process pid's cmdline matches a given name
    pid=$1
    name=$2
    [ -z "$pid" ] && return 1
    [ ! -d /proc/$pid ] &&  return 1
    cmd=`cat /proc/$pid/cmdline | tr "\000" "\n"|head -n 1 |cut -d : -f 1`
    # Is this the expected server
    [ "${cmd##*/}" != "${name##*/}" ] &&  return 1
    return 0
}

running() {
# Check if the process is running looking at /proc
# (works for all users)

    # No pidfile, probably no daemon present
    [ ! -f "$PIDFILE" ] && return 1
    pid=`cat $PIDFILE`
    running_pid $pid $DAEMON || return 1
    return 0
}

start_server() {

    start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- -q $DAEMON_OPTS
    errcode=$?
    return $errcode
}

stop_server() {
    start-stop-daemon --stop --quiet --retry TERM/2/TERM/10/KILL/2 --pidfile $PIDFILE
    errcode=$?
    return $errcode
}

case "$1" in
    start)
	log_daemon_msg "Starting $DESC " "$NAME"

        # Check if it's running first
        if running ;  then
            log_progress_msg "apparently already running"
            log_end_msg 0
            exit 0
        fi
	errcode=0
        start_server || errcode=$?
	# try to create required directories. This only works
	# for a single node setup, because we have no quorum
	# in a cluster setup. But this doesn't matter, because the 
	# cluster manager creates all needed files (pvecm)
	if [ $errcode -eq 0 ] ; then
	    /usr/bin/pvecm updatecerts --silent || true
	fi
        log_end_msg $errcode
	;;
    stop)
        log_daemon_msg "Stopping $DESC" "$NAME"
        if running ; then
            # Only stop the server if we see it running
	    errcode=0
  	    stop_server || errcode=$?		
	    log_end_msg $errcode
        else
            # If it's not running don't do anything
	    log_progress_msg "apparently not running"
	    log_end_msg 0
	    exit 0
        fi
        ;;
    restart|force-reload)
        log_daemon_msg "Restarting $DESC" "$NAME"
 	errcode=0
        stop_server || errcode=$?
 	errcode=0
        start_server || errcode=$?
	log_end_msg $errcode
 	;;
    status)
        log_daemon_msg "Checking status of $DESC" "$NAME"
        if running ;  then
            log_progress_msg "running"
            log_end_msg 0
        else
            log_progress_msg "apparently not running"
            log_end_msg 1
            exit 1
        fi
        ;;
    reload)
        log_warning_msg "Reloading $NAME daemon: not implemented, as the daemon"
        log_warning_msg "cannot re-read the config file (use restart)."
        ;;

    *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|force-reload|status}" >&2
	exit 1
	;;
esac

exit 0
