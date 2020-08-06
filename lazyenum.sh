#!/bin/bash

VERSION="v0.0.1"
ADVISORY="Enumeration script for given set of ip.Use responsibly! Designed for lazy people by a lazy guy :)"

#####################################
#--------)Configurations(-----------#
#####################################
VHOSTS_TYPE="htb"       #Change accordingly for OSCP exam
TMPDIR=$TARGET\\tmp
OUTPUT=$TARGET
WEB_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
VHOST_WORDLIST="/usr/share/wordlists/Subdomain.txt"
WEB_EXT_1="php,html,txt"
WEB_EXT_2="swp,,pdf"
WEB_EXT_3="tar.gz,bak,zip,sh"

#####################################
#-----------)Colours(---------------#
#####################################
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
Y="${C}[1;33m"
B="${C}[1;34m"
LG="${C}[1;37m" #LightGray
DG="${C}[1;90m" #DarkGray
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"


#####################################
#------)Parsing input arguemnts(----#
#####################################
CHECKS="nmap,directory,vhosts,linkfinders,exploitdb"
NMAP=0
DIRECTORY=0
VHOST=0
LINKFINDER=0
EXPLOITDB=0

HELP=$GREEN"Enumeration made easy.
     $B This tool enumerates the given ip with user defined controls.
     $Y-h$B To show this message.
     $Y-t <IP addr> $B Target ip address.
     $Y-a$B Enumerate everything.
     $Y-n$B Only enumerate namp.
     $Y-d <URL> $B Only perform directory bruteforcing.
     $Y-v <URL> $B Perform virtual host discovery.
     $Y-l <URL> $B Crawls all the links present in the source code of server.
     $Y-e <URL> $B Checks the server for known vulnerable bugs like outdated version of CMS.\n"

while getopts "h?n:t:d:v:l:e" c
do
    case $c in 
        h|\?)   print "$HELP";exit 0;;
        t)      TARGET=$OPTARG;;
        a)      NMAP=1;EXPLOITDB=1;DIRECTORY=1;LINKFINDER=1;VHOST=1;;
        n)      NMAP=1;;
        d)      DIRECTRY_WORDLIST=$OPTARG;DIRECTORY=1;;
        v)      VHOST_URL=$OPTARG;VHOST=1;;
        l)      LINKFINDER_URL=$OPTARG;LINKFINDER=1;;
        e)      EXPLOITDB=1;EXPLOITDB_URL=$OPTARG;;
    esac
done    

#########################################
#---------------)Lists(-----------------#
#########################################
vulnerable_softwares="Gym Management System"

#########################################
#---------)Utility Functions(-----------#
#########################################
clean_dir(){
    echo $DG"[INFO]Cleaning temporay directory"
    rm -rf $TMPDIR
    echo $DG"[INFO]Done"
}

is_down(){
#check if target is down
    ping -c 2 -W 3 $TARGET -q 1>/dev/null
    if [ $? -eq 0 ]
    then
        return 0
    fi
    return 1
}

is_webserver(){
#Returns 0 if port is running webservice
    nc -z $TARGET $1 2>$TMPDIR_$TARGET_$1
    cat $TMPDIR_$TARGET_$1 | grep 'http\|tcp\|https'
    if [ $? -eq 0]
    then
        return 0
    fi
    return 1
}

##########################################
#-----------)Entry functions(------------#
##########################################
nmap_scan(){
    touch $TMPDIR/webservers.txt
    if [ is_down -eq 1 ]
    then
        echo $RED"[-] Target Down!"
        exit 1
    fi
    echo $LG"[INFO] Starting nmap scan for top 1000 ports!"
    nmap -sC -sV -A -o $TMPDIR/nmap_top_1000.txt $TARGET 1>/dev/null
    cp $TMPDIR/nmap_top_1000 $OUTPUT/nmap_top_1000.txt

    echo $LG"[INFO] Analyzing the nmap scan!"
    echo $LG"[INFO] Found `cat $TMPDIR/nmap_top_1000.txt | grep 'open' | wc -l` open ports"
    echo -e $GREEN"[+] Open ports :\n`cat $TMPDIR/nmap_top_1000.txt | grep 'open' | awk '{print $1}'`"
    
    ports_top_1000=`cat $TMPDIR/nmap_top_1000.txt | grep 'open' | awk '{print $1}' | cut -d '/' -f 1`
    for port in ports_top_1000
    do
        if [ is_webserver $port -eq 0 ]
        then
            echo $LG"[INFO] Webserver found at $port!"
            echo $port >> $TMPDIR/webservers.txt
        fi
    done

    echo $LG"[INFO] Running full port scan now!"
    nmap -p- -sC -sV -A -o $TMPDIR/nmap_full.txt $TARGET 1>/dev/null
    cp $TMPDIR/nmap_full.txt $OUTPUT/nmap_full.txt

    echo $LG"[INFO] Analyzing the nmap scan!"
    ports_full=`cat $TMPDIR/nmap_full.txt | grep 'open' | awk '{print $1}' | cut -d '/' -f 1`

    if [ $ports_full -eq $ports_top_1000 ]
    then
        echo $DG"[-] No extra ports found!"
    elif [ $ports_full -lt $ports_top_1000 ]
    then
        echo $RED"[-] Unknown error encountered! Perform manual nmap scan again!"
    else
        echo $LG"[INFO] Found `$(($ports_full-$ports_top_1000))` extra open ports"
        for p in `echo $ports_full`
        do
            echo $p >> $TMPDIR/tmp1.txt
        done

        for p in `echo $ports_top_1000`
        do
            echo $p >> $TMPDIR/tmp2.txt
        done
    
        uniq_ports=`diff -u $TMPDIR/tmp1.txt $TMPDIR/tmp2.txt | grep -E '^\+' | sed -E 's/^\+//' | grep -v '+'`
        rm $TMPDIR/tmp2.txt $TMPDIR/tmp1.txt

        echo -e $GREEN"[+] New ports found using full scan:\n`cat $uniq_ports`"
        for uport in `echo $uniq_ports`
        do
            if [ is_webserver $uport -eq 0 ]
            then   
                echo $LG"[INFO] Webserver found at port $uport!"
                echo $port >> $TMPDIR/webservers.txt
            fi
        done
    fi
}

vhosts_enum(){
    echo $LG"[INFO] Starting vhosts enumeration"
    vhost=`cat $TMPDIR/nmap_full.txt | grep -o "\w*.$VHOSTS_TYPE\b" | uniq -c`

    if [[ -z "$vhost" && -z "$VHOST_URL" ]]
    then
        echo $DG"[-] No vhosts found! Not running the vhosts scan"
    elif [[ ! -z "$vhost" && -z "$VHOST_URL" ]]
    then
        #Run vhosts enum on $vhost
        gobuster vhost -w $VHOST_WORDLIST -u $vhost -q 1>$TMPDIR/vhost_$vhost.txt
        for v in `cat $TMPDIR/vhost_$vhost.txt`
        do
            host=`echo $v | grep "\w*.$VHOSTS_TYPE"`
            if [ $? -eq 0 ]
            then
                echo $host >> $OUTPUT/vhost.txt
            fi
        done

        echo $LG"[INFO] Done with virtual hosts enunmeration!"
    elif [[ -z "$vhost" && ! -z "$VHOST_URL" ]]
    then
        #Run vhosts enum on $VHOSTS_URL
        gobuster vhost -w $VHOST_WORDLIST -u $VHOST_URL -q 1>$TMPDIR/vhost_$VHOST_URL.txt
        for v in `cat $TMPDIR/vhost_$VHOST_URL.txt`
        do
            host=`echo $v | grep "\w*.$VHOSTS_TYPE"`
            if [ $? -eq 0 ]
            then
                echo $host >> $OUTPUT/vhost.txt
            fi
        done

        echo $LG"[INFO] Done with virtual hosts enunmeration!"
    else
        # Run vhosts enum on $VHOSTS_URL and $vhosts
        gobuster vhost -w $VHOST_WORDLIST -u $vhost -q 1>$TMPDIR/vhost_$vhost.txt
        for v in `cat $TMPDIR/vhost_$VHOST_URL.txt`
        do
            host=`echo $v | grep "\w*.$VHOSTS_TYPE"`
            if [ $? -eq 0 ]
            then
                echo $host >> $OUTPUT/vhost.txt
            fi
        done

        gobuster vhost -w $VHOST_WORDLIST -u $VHOST_URL -q 1>$TMPDIR/vhost_$VHOST_URL.txt
        for v in `cat $TMPDIR/vhost_$vhost.txt`
        do
            host=`echo $v | grep "\w*.$VHOSTS_TYPE"`
            if [ $? -eq 0 ]
            then
                echo $host >> $OUTPUT/vhost.txt
            fi
        done

        echo $LG"[INFO] Done with virtual hosts enunmeration!"
    fi
}

web_enum(){
    echo -e $LG"[INFO] Starting website enumeration\n[INFO] Stage 1 enumeration initiated!"

    #Stage 1 enumeration
    for urls in `cat $OUTPUT/vhost.txt`
    do
        gobuster -w $WEB_WORDLIST dir -u $urls -x $WEB_EXT_1 -q 1>$TMPDIR/gobuster_stage_1.txt
    done

    for links in `cat $TMPDIR/gobuster_stage_1.txt`
    do
        l=`echo $links | grep -E ' /\w*.\w*'`
        if [ -$? -eq 0 ]
        then
            echo $l >> $OUTPUT/gobuster.txt
        fi
    done

    echo $LG"[INFO] Starting stage 2 enumeration!"
    #Stage 2 enumeration
    for urls in `cat $OUTPUT/vhost.txt`
    do
        gobuster -w $WEB_WORDLIST dir -u $urls -x $WEB_EXT_2 -q 1>$TMPDIR/gobuster_stage_2.txt
    done

    for links in `cat $TMPDIR/gobuster_stage_2.txt`
    do
        l=`echo $links | grep -E ' /\w*.\w*'`
        if [ -$? -eq 0 ]
        then
            echo $l >> $OUTPUT/gobuster.txt
        fi
    done

    echo $LG"[INFO] Starting stage 3 enumeration!"
    #Stage 3 enumeration
    for urls in `cat $OUTPUT/vhost.txt`
    do
        gobuster -w $WEB_WORDLIST dir -u $urls -x $WEB_EXT_3 -q 1>$TMPDIR/gobuster_stage_3.txt
    done

    for links in `cat $TMPDIR/gobuster_stage_3.txt`
    do
        l=`echo $links | grep -E ' /\w*.\w*'`
        if [ -$? -eq 0 ]
        then
            echo $l >> $OUTPUT/gobuster.txt
        fi
    done

    echo $LG"[INFO] Done with web based enumeration"
}

linkfinder_enum(){
    echo $LG"[INFO] Starting static analysis of web pages"


}

exploitdb_enum(){

}
