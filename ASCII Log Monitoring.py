##################################################################################################
## Author       ::  Softility.Inc
## Description  ::  This Script used for Remote Log Files Monitoring based on LogMessage Patterns
## Version      ::  v2
## Created on   ::  09/19/2018
## Modified on  ::  01/15/2019
##################################################################################################

# Importing Required Modules to be used in the Script
import paramiko
import time
import logging
import re
import collections
from silo_common import snippets as em7_snippets

logger=em7_snippets.logger(filename='/data/logs/SFTYRemoteLogFileMonitoring.log')

"""
Note :: If you want to monitor LogFile from firstline number provide "0". Example :: linux_files={'filename':'0'}
Note :: If you want to monitor LogFile from lastline number provide "1". Example  :: linux_files={'filename':'1'} """

linux_files={'/var/log/messages':'1'}
solaris_files={'/var/adm/messages':'1','/apps/netiq/HCMPRD/logs':'1'}


""" Provide FilesNames which needs to be monitored along with Log Message Patterns
Search Inputs :: Provide "Files to be monitored as keys with fullpath of file" and "Log Message patterns as List of Values" """

linux={'/var/log/messages':['CPU_FAN.*FAILED','V_BAT has exceeded low','SC.*Alert.*Chassis.*major','file system full','nscd.*libsldap.*no available conn','link has gone down','NFS write failed','needs maintenance','fault.chassis.env.power.loss with probability=100','power supply AC input voltage failure has occurred','Drive failure imminent','Physical drive failure','Smart Error Reported','NFS server.*not responding','NFS file operation','NFS write error','NFS  file operation failed','nfs_mount: cannot mount','nfs_mount: Permission denied','.+dataguard replication of CARESRPD.*failed','TimeFinder Clone script failed for CARESPRD DB','ASM diskgroups failed to unmount','database CARESTG failed to shutdown','ASM diskgroups failed to mount','database failed','.+snmpdx:.*daemon.error','.+NFS .*failed','authentication failure'],}

solaris={'/var/adm/messages':['CPU_FAN.*FAILED','V_BAT has exceeded low','SC.*Alert.*Chassis.*major','file system full','nscd.*libsldap.*no available conn','link has gone down','NFS write failed','needs maintenance','fault.chassis.env.power.loss with probability=100','power supply AC input voltage failure has occurred','Drive failure imminent','Physical drive failure','Smart Error Reported','NFS server.*not responding','NFS file operation','NFS write error','NFS  file operation failed','nfs_mount: cannot mount','nfs_mount: Permission denied','.+Command Timeout on path','.+snmpdx:.*daemon.error','.+NFS .*failed','authentication failure'],}

osnames={'Linux':linux,'SunOS':solaris}

# Maximum Lines to read for every data polling
Maximum_Number_of_Lines_to_read = 100000;

# Path to which AWKscript is to be pushed
AWK_path="/tmp/awkscript2"

# Number of Patterns to be pushed to AWKscript
Maximum_patterns_to_AWKscript = 34 ;

# Provide time period in mins for AWKscript to be updated
Update_AWKScript_in_days= 1 ;

# Recovery file which stores log_file_name,last_linenumber and LastLineMessage on the Target server.
recovery_file_name = '/tmp/SL_log_mon.rec'

# Dictionaries to store the LogMessages and RollOverFilesNames
RESULTS = {}
single_alerts = []
Rolloverlogfiles = {}
startTime = time.time()

try:
    # Connection Parameters used for connecting to Target Device Box
    host= self.cred_details['cred_host']
    port=22
    username=self.cred_details['cred_user']
    password=self.cred_details['cred_pwd']
    # Recovery file which stores log_file_name,last_linenumber and LastLineMessage on the Target server.
    logger.info("*********** Starting Remote Log File Snippet Dynamic Application ***********")
    # Making SSH Connection to Target Server.
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, username, password)
    # Executing 'uname' command on Target Server to get OS PlatformName.
    command = "uname"
    stdin, stdout, stderr = ssh.exec_command(command)
    result = stdout.readlines()
    # The Output will be 'Linux' for Linux Servers & 'SunOS' for Solaris Servers
    # Based on the PlatformName we will take SearchInputs
    platformname = str(result[0].replace('\n', ''))
    logger.info("SSH is connected successfully to Target Server :: {0}".format(host))
    logger.info("Target Server :: {1} Operating System type :: {0}".format(platformname, host))
    logmonpolicy = {}
    if platformname in osnames:
           logmonpolicy = osnames[platformname]
    # Storing RollOverFile Names in Rolloverlogfiles dictionary
    for log_file_name in logmonpolicy:
        log_files = []
        logfilepath_list = log_file_name.split('/')
        rollover_files = 'ls {1} | grep "{0}*"'.format(logfilepath_list[-1], ('/'.join(logfilepath_list[:-1])))
        stdin1, stdout1, stderr1 = ssh.exec_command(rollover_files)
        total_rollover_files = stdout1.readlines()
        for roll_file in total_rollover_files:
            log_files.append(str(('/'.join(logfilepath_list[:-1])) + '/' + roll_file))
            log_files.reverse()
        log_files = sorted(log_files)[::-1]
        if len(log_files) != 0:
            log_files.pop()
            if platformname == "SunOS":
                log_files.reverse()
        Rolloverlogfiles[log_file_name] = log_files
    def push_awk_script(patterns):
        """
                    This Function is used to create AWK Script on the Target Server in '/tmp/' folder based on maximum count of Patterns
                    :param patterns: Maximum number of Patterns
        """
        pattern_string = ''
        pattern_string1 = ''
        pattern_string2 = ''
        for pattern_count in range(1, patterns + 1):
            pattern_string += "p" + str(pattern_count) + "=0;"
            # pattern_string1 += 'NR>=startline && pattern' + str(pattern_count) + ' && $0 ~ pattern' + str(pattern_count) + '{ ++p' + str(pattern_count) + '; print "pattern' + str(pattern_count) + '::",$0 }\n'
            pattern_string1 += 'NR<=stopline && NR>=startline && pattern' + str(pattern_count) + ' && $0 ~ pattern' + str(pattern_count) + '{ ++p' + str(pattern_count) + '; print "pattern' + str(pattern_count) + '::",$0 }\n'
            # pattern_string2 += 'print "Matched' + str(pattern_count) + '::' + '",pattern' + str(pattern_count) + ',"::has occured::" p' + str(pattern_count) + ';\n'
            pattern_string2 += 'print "Matched' + str(pattern_count) + '::' + '",pattern' + str(pattern_count) + ',"::has occured::" p' + str(pattern_count) + ';\n'
        awk_code = """
            #!/usr/bin/awk -f
            BEGIN {%s stopline = startline + %d }
            NR==1 Firstline{ print "Firstline::",$0}
            NR<startline {next}
            NR>stopline { exit;}
            %s
            END { %s
            if (NR > stopline) { print "TotalLines::",stopline;} else { print "TotalLines::",NR;} }
            """ % (pattern_string, int(Maximum_Number_of_Lines_to_read), pattern_string1, pattern_string2)
        command = "echo '{0}' >{1}".format(str(awk_code), str(AWK_path))
        stdin, stdout, stderr = ssh.exec_command(command)

    def check_lastline_pattern(last_linenumber, log_filename, recovery_file_name, first_linepattern, patterns):

        """
                This Function Checks if FirstLinePattern from Recoveryfile matches with Present Starting Line and Process the LogFile
                If FirstLinePattern is not found in Present LogFile. It will check in the RollOverLogFiles
                :param last_linenumber: It is the previous lastlinenumber of logfile
                :param log_filename: It is the logfilename which is being processed
                :param recovery_file_name: It is the file which stores lastlinenumber,firstlinepattern and logfilename
                :param first_linepattern: It the previous firstlinepattern of logfile
                :param patterns: These are log message patterns which needs to be checked while reading logfile
                :return: It will return the log_messages
        """

        log_messages = []

        if last_linenumber != 0:

            command = '''head -1 {1}'''.format(last_linenumber, log_filename)
            stdin, stdout, stderr = ssh.exec_command(command)
            firstline_existence = stdout.readlines()
            ssh_data = (firstline_existence[0].replace("'","").replace('"','').replace("\n",""))
            file_data = (first_linepattern.replace("'","").replace('"','').replace("\n",""))

            if len(firstline_existence) != 0 and ssh_data == file_data:
                log_messages=process_data(last_linenumber, log_filename, recovery_file_name, patterns, firstline_existence)
                return log_messages

            else:
                index = 0
                while index < len(Rolloverlogfiles[log_filename]):
                    RollOverlogfilename = str(Rolloverlogfiles[log_filename][index]).replace('\n','')
                    #command = "sed '{0}!d' {1}| fgrep '{2}'".format(last_linenumber, RollOverlogfilename, first_linepattern.replace('\n',''))
                    #command = """sed '1!d' {1}| fgrep '{2}'""".format(last_linenumber, RollOverlogfilename, first_linepattern)
                    #command = """head -1 {1}| fgrep '{2}'""".format(last_linenumber, log_filename, first_linepattern)
                    ## 03/19/2019
                    command = '''head -1 {1}'''.format(last_linenumber, RollOverlogfilename)
                    stdin, stdout, stderr = ssh.exec_command(command)
                    firstline_existence = stdout.readlines()
                    ssh_data = (firstline_existence[0].replace("'","").replace('"','').replace("\n",""))
                    file_data = (first_linepattern.replace("'","").replace('"','').replace("\n",""))
                    if len(firstline_existence) != 0 and ssh_data == file_data:
                        matched_messages=process_data(last_linenumber=last_linenumber, log_filename=RollOverlogfilename, recovery_file_name=recovery_file_name, patterns=patterns, firstline_existence=firstline_existence)
                        log_messages.extend(matched_messages)
                        rolloverfiles_list = sorted(Rolloverlogfiles[log_filename][:index])
                        rolloverfiles_list = ['var/log/messages.1', 'var/log/messages.2']
                        if len(rolloverfiles_list)!=0:
                            filtered_messages=[]
                            for rollfile in rolloverfiles_list:
                                rolllogfilename = rollfile.replace('\n', '')
                                match_messages = process_data(last_linenumber=0, log_filename=rolllogfilename,recovery_file_name=recovery_file_name, patterns=patterns,firstline_existence=firstline_existence)
                                filtered_messages.extend(match_messages)
                            matched_messages = process_data(last_linenumber=0, log_filename=log_filename,recovery_file_name=recovery_file_name, patterns=patterns, firstline_existence=firstline_existence)
                            log_messages.extend(matched_messages)
                            log_messages.extend(filtered_messages)
                            break
                        else:
                            matched_messages = process_data(last_linenumber=0, log_filename=log_file_name,recovery_file_name=recovery_file_name, patterns=patterns,firstline_existence=firstline_existence)
                            log_messages.extend(matched_messages)
                        return log_messages
                    else:
                        index=index+1

                if len(log_messages) == 0:
                    log_messages = check_lastline_pattern(last_linenumber=0, log_filename=log_file_name, first_linepattern='',patterns=logmonpolicy[log_file_name], recovery_file_name=recovery_file_name)
                    #print("M",log_messages)
                    truncate="\tTarget file {0} has been truncated".format(log_filename)
                    logger.info("Target file {0} has been truncated on Target Server :: {0}".format(log_filename,host))
                    log_messages.append(truncate)
                    return log_messages
                else:
                    return log_messages
        else:
            firstline_existence=''
            matched_messages=process_data(last_linenumber=last_linenumber, log_filename=log_filename, recovery_file_name=recovery_file_name,patterns=patterns,firstline_existence = firstline_existence)
            log_messages.extend(matched_messages)
            return log_messages
    def process_data(last_linenumber, log_filename, recovery_file_name, patterns, firstline_existence):
        """
                   This Function Processes Data in a logfile from where it is Matched
                   :param last_linenumber: It is the previous lastlinenumber of logfile
                   :param log_filename: It is the logfilename which is being processed
                   :param recovery_file_name: It is the file which stores lastlinenumber,firstlinepattern and logfilename
                   :param patterns: These are log message patterns which needs to be checked while reading logfile
                   :param firstline_existence: It the previously lastpattern pattern which matches in present logfile
                   :return: It will return the matched_messages
           """
        pattern_string3 = ''
        for pattern_count in range(1, len(patterns)+ 1):
            #pattern_string3 += ' -vpattern' + str(pattern_count) + '="' + str(patterns[pattern_count - 1]) + '" '
            pattern_string3 += ' -v ' + '"pattern'+ str(pattern_count)+'='+str(patterns[pattern_count - 1])+'"'
        if firstline_existence is not None:
            if platformname =='Linux':
                command = 'awk -v "startline=%d" %s  -v "IGNORECASE=1" -f %s %s'%(int(last_linenumber)+1,pattern_string3,str(AWK_path),log_filename)
            elif platformname =='SunOS':
                command = 'nawk -v "startline=%d" %s -f %s %s'%(int(last_linenumber)+1,pattern_string3,str(AWK_path),log_filename)
            logger.info("Executing {0} on Target Server :: {1}".format(command,host))
            stdin, stdout, stderr = ssh.exec_command(command)
            records_retrieved = stdout.readlines()
            if firstline_existence is not None and len(records_retrieved)!=0:
                matched_messages=parsing_data(records_retrieved, last_linenumber, recovery_file_name,patterns,log_filename)
                return matched_messages
            else:
                matched_messages = parsing_data(records_retrieved, last_linenumber, recovery_file_name, patterns, log_filename)
                return matched_messages
        else:
            ##command = 'awk -v startline=%d%s-f /tmp/awkscript3 %s' % (0, pattern_string3, log_filename)
            stdin, stdout, stderr = ssh.exec_command('awk -v startline=%d %s-f %s %s' % (0, pattern_string3,str(AWK_path),log_filename))
            outlines_empty = stdout.readlines()
            if len(outlines_empty) == 0:
                recovery_file_update(total_lines=0, first_line_message="", log_file_name=log_filename, recovery_file_name=recovery_file_name)
                #print("N",log_messages)
                truncate = "\tTarget file {0} has been truncated".format(log_filename)
                return ["empty records available"]
            else:
                return ["No records available"]

    def parsing_data(records_retrieved, last_linenumber, recovery_file_name, patterns, log_filename):
        """ This Function Parses the LogMessages, last_linenumber and FirstLinePattern """
        """
                   This Function Parses the LogMessages, LastLinenumber and FirstLinePattern
                   :param last_linenumber: It is the previous lastlinenumber of logfile
                   :param log_filename: It is the logfilename which is being processed
                   :param recovery_file_name: It is the file which stores lastlinenumber,firstlinepattern and logfilename
                   :param first_linepattern: It the previous firstlinepattern of logfile
                   :param patterns: These are log message patterns which needs to be checked while reading logfile
                   :return: It will return the filtered_values
           """
        matched_messages=[]
        first_line_message = ''
        total_lines = 0
        ## Updated ##
        time_list =[]
        stdin, stdout, stderr = ssh.exec_command("hostname")
        HOSTNAME_SPLIT = stdout.readlines()[0]
        HOSTNAME = str(HOSTNAME_SPLIT.split('.')[0].replace("\n", ""))
        ##
        try:
            for msg in records_retrieved:
                if msg.startswith("pattern"):

                    a = msg.split("::")[1]
                    time_list.append(a.split(HOSTNAME)[0].strip())
                    logmsg=str("\tLogMonAlert-"+msg.split("::")[1])
                    single_alerts.append(msg.split("::")[1].replace("\n","").strip())
                    #matched_messages.append(logmsg)
                elif msg.startswith("Lastline"):
                    last_line_message=msg.split("::")[1].strip(" ").replace("\n","")
                elif msg.startswith("Firstline"):
                    first_line_message=msg.split("::")[1].strip(" ").replace("\n","")
                elif msg.startswith("TotalLines"):
                    total_lines+=int(msg.split("::")[1].strip(" "))
                elif msg.startswith("Matched"):
                    if (int(msg.split("::")[3]))!=0:
                        macthedpatternscnt=("\t"+"Pattern: "+msg.split("::")[1].strip() +"; Matches found: "+ msg.split("::")[3].strip("\n") +"; File: "+ log_file_name  +"; Starttime: "+time_list[0]+ ";  Endtime: "+time_list[-1]+";--MATCHES--")
                        #macthedpatternscnt=("\t"+"UNIX_APP-Pattern: "+msg.split("::")[1].strip() +"; Matches found: "+ msg.split("::")[3].strip("\n") +"; File: "+ log_file_name  +"; Starttime: "+time_list[0]+ ";  Endtime: "+time_list[-1]+";--MATCHES--")
                        matched_messages.append(macthedpatternscnt)
            print("Total",total_lines)
            recovery_file_update(total_lines, first_line_message, log_file_name, recovery_file_name)
            return matched_messages
        except Exception as e:
            pass
    def recovery_file_update(total_lines, first_line_message, log_file_name, recovery_file_name):
        """
                       This Function used to update the last_linenumber and FirstLinePattern in RecoveryFile
                       :param total_lines: It is the lastlinenumber to be updated in the Recoveryfile
                       :param first_line_message: It is the firstlinepattern to be updated in the Recoveryfile
                       :param log_file_name: It is the logfilename for which lastlinenumber and lastpattern to be updated in the Recoveryfile
                       :param recovery_file_name: It is the file which stores lastlinenumber,firstlinepattern and logfilename
        """
        file_namee=''
        for file_name in recovery_file_data:
            if (file_name == log_file_name) :
                recovery_file_data[log_file_name] = (total_lines, first_line_message)
        for file_nam in recovery_file_data:
            if file_nam != "filename":
                line1 = str(recovery_file_data[file_nam][1]).replace('"','\\"')
                file_namee += str(file_nam) + "," + str(recovery_file_data[file_nam][0]) + "," + str(line1)+str("\n")
        #command = "echo '{0}' >{1}".format(str(file_namee), recovery_file_name)
        ## 03/19/2019
        command = 'echo "{0}" >{1}'.format(str(file_namee), recovery_file_name)
        stdin, stdout, stderr = ssh.exec_command(command)

    ################################################
    ############# Main Function ####################
    ################################################

    """ Checks Whether AWKScript Exists on Target Server or Not by excuting below command on Target Server.
    If AWKScript doesnt exists it will create it in '/tmp/' Folder """
    stdin, stdout, stderr = ssh.exec_command("[ -f {0} ] && echo AWKScriptExists || echo AWKDoesNotExists".format(str(AWK_path)))
    check_awk_script=stdout.readlines()
    # Checks if AWKScript Exists or not; If not it will creates it on Target Server
    logger.info("Checking for AWKscript on the Target Server :: {0}".format(host))
    if check_awk_script[0].strip("\n") == "AWKScriptExists":
        command = "find {0} -mtime +{1}".format(AWK_path,Update_AWKScript_in_days)
        #print(command)
        stdin, stdout, stderr = ssh.exec_command(command)
        awk_script_age = stdout.readlines()
        if len(awk_script_age)!=0:
            #print("Test",awk_script_age)
            push_awk_script(patterns=int(Maximum_patterns_to_AWKscript))
            logger.info("AWKscript is updated as it existing for past {1} days on the Target Server :: {0}".format(Update_AWKScript_in_days,host))
        logger.info("AWKScript already existed on the Target Server :: {0}".format(host))
    else:
        # If AWKSript DoesNOTExists Creates it on Target Server using 'push_awk_script()' function
        logger.info("AWKScript doesn't exists on Target Server :: {0}".format(host))
        logger.info("Creating AWKScript on Target Server :: {0}".format(host))
        push_awk_script(patterns=Maximum_patterns_to_AWKscript)

    """ Checks Whether RecoveryFile Exists on Target Server or Not by excuting below command on Target Server.
    If RecoveryFile doesnt exists it will create in '/tmp/' Folder """
    stdin1, stdout1, stderr1 = ssh.exec_command("[ -f {0} ] && echo RecoveryFileExists || echo RecoveryFileDoesNotExists".format(recovery_file_name))
    check_recovery_file = stdout1.readlines()
    # Checks if Recovery File Exists or not; If not it will create it on Target Server
    logger.info("Checking for RecoveryFile on the Target Server :: {0}".format(host))
    if check_recovery_file[0].strip("\n")== "RecoveryFileExists":
        logger.info("RecoveryFile already existed on the Target Server :: {0}".format(host))
    else:
        # If RecoveryFile DoesNOTExists Creates it on Target Server using below code
        logger.info("RecoveryFile doesn't exists on Target Server :: {0}".format(host))
        logger.info("Creating RecoveryFile on Target Server :: {0}".format(host))
        file_create = 'filename,lastlinenumber,firstlinepattern\n'
        firstlinepattern = ''
        recovery_file_data = {}
        for filename in logmonpolicy:
                if platformname == "Linux":
                    for file in linux_files:
                        if file == filename:
                            if linux_files[filename]=="1":
                                cmd = "wc -l {0}".format(filename)
                                stdin, stdout, stderr = ssh.exec_command(cmd)
                                lastline = stdout.readlines()
                                if len(lastline)!=0:
                                    lastlinenumber = str(lastline[0].strip().split(" ")[0])
                                    recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                    file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(recovery_file_data[filename][1]) + str("\n")
                                else:
                                    lastlinenumber='0'
                                    recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                    file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(recovery_file_data[filename][1]) + str("\n")
                            else:
                                lastlinenumber='0'
                                recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(recovery_file_data[filename][1]) + str("\n")
                elif platformname == "SunOS":
                    for file in solaris_files:
                        if file == filename:
                            if solaris_files[filename]=="1":
                                cmd = "wc -l {0}".format(filename)
                                stdin, stdout, stderr = ssh.exec_command(cmd)
                                lastline = stdout.readlines()
                                if len(lastline)!=0:
                                    lastlinenumber = str(lastline[0].strip().split(" ")[0])
                                    recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                    file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(recovery_file_data[filename][1]) + str("\n")
                                else:
                                    lastlinenumber='0'
                                    recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                    file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(recovery_file_data[filename][1]) + str("\n")
                            else:
                                lastlinenumber='0'
                                recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(recovery_file_data[filename][1]) + str("\n")
        command = "echo '{0}' >{1}".format(str(file_create), recovery_file_name)
        stdin, stdout, stderr = ssh.exec_command(command)
        recovery_file_data = {}
        file_cmd = 'cat {0}'.format(recovery_file_name)
        stdin, stdout, stderr = ssh.exec_command(file_cmd)
        reader = stdout.readlines()
        for record in reader:
            if len(record.strip("\n")) != 0:
                recovery_file_data[(record.strip("\n").split(",")[0])] = [record.strip("\n").split(",")[1],record.strip("\n").split(",")[2]]

    # Retrieving data from RecoveryFile like FileName, last_linenumber Count and FirstLinepattern
    recovery_file_data = {}
    file_cmd = 'cat {0}'.format(recovery_file_name)
    stdin, stdout, stderr = ssh.exec_command(file_cmd)
    reader = stdout.readlines()
    for record in reader:
        if len(record.strip("\n")) != 0:
            recovery_file_data[(record.strip("\n").split(",")[0])] = [record.strip("\n").split(",")[1], record.strip("\n").split(",")[2]]
    # Updating the Recovery File when NewLogFile is added for Monitoring
    for log_filename in logmonpolicy:
        if log_filename not in recovery_file_data.keys():
            logger.info("Added New logfilename for monitoring :: {0}".format(str(log_filename)))
            file_cmd = 'cat {0}'.format(recovery_file_name)
            stdin, stdout, stderr = ssh.exec_command(file_cmd)
            reader = stdout.readlines()
            for record in reader:
                if len(record.strip("\n")) != 0:
                    recovery_file_data[(record.strip("\n").split(",")[0])] = [record.strip("\n").split(",")[1],record.strip("\n").split(",")[2]]
            recovery_file_data[log_filename]=('0',"")


    log_messages1 = []
    # Processing of each Logfile
    for log_file_name in logmonpolicy:
        log_messages = []
        ## Check Directory permissions
        stdin9, stdout9, stderr9 = ssh.exec_command("tail -1 {0}".format(log_file_name))
        filedir  = stdout9.readlines()
        filedir_nopermission  = stderr9.readlines()
        if len(filedir_nopermission)!=0 and re.match(".*Permission denied.*", str(filedir_nopermission[0])):
            logger.info("Logfile {0} doesn't have required Permissions on the Target server :: {1}".format(log_file_name, host))
            file_doesnt_have_permissions = ("\tTarget file {0} does not have required permissions".format(log_file_name))
            log_messages1.append(file_doesnt_have_permissions)
        else:
            """ Checks if LogFile which needs to be Monitored exists on the Target Server or Not. 
            By Executing below command on Target Server we can Check LogFile Exists or Not """
            stdin2, stdout2, stderr2 = ssh.exec_command("[ -f {0} ] &&  echo LogFileExists   || echo LogFileDoesnotExists  ".format(log_file_name))
            check_file_existence = stdout2.readlines()
            # If LogFile Exists Continues processing #
            if str(str(check_file_existence[0]).split('\n')[0]) == 'LogFileExists':
                logger.info("Logfile {0} exists on the Target server :: {1}".format(log_file_name,host))
                # Checks if LogFile has permissions to read using executing below command on Target Server
                stdin, stdout, stderr = ssh.exec_command("tail -1 {0}".format(log_file_name))
                check_file_permissions = stderr.readlines()
                # If LogFile has Required Permissions are Present then Continues Processing
                if (len(check_file_permissions) == 0):
                    logger.info("Logfile {0} have required Permissions on the Target server :: {1}".format(log_file_name,host))
                    logger.info("Processing of LogFile :: {0} is started".format(log_file_name))
                    log_messages=check_lastline_pattern(last_linenumber=int(recovery_file_data[log_file_name][0]),first_linepattern=recovery_file_data[log_file_name][1],patterns=logmonpolicy[log_file_name], log_filename=log_file_name,recovery_file_name=recovery_file_name)
                    logger.info("Processing of LogFile :: {0} is Completed".format(log_file_name))
                    logger.info("{0} matched messages are retrieved from logfile :: {1}".format(len(log_messages),log_file_name))
                # If LogFile doesn't have required Permissions throws Permission denied
                if re.match(".* cannot open .* for reading", str(check_file_permissions)):
                    logger.info("Logfile {0} doesn't have required Permissions on the Target server :: {1}".format(log_file_name,host))
                    file_doesnt_have_permissions = ("\tTarget file {0} does not have required read permissions".format(log_file_name))
                    #log_messages.append(file_doesnt_have_permissions)
            else:
                    # If LogFile doesn't Exists on Target
                    logger.info("Logfile {0} doesn't exists on the Target server :: {1}".format(log_file_name, host))
                    file_doesnt_exists = ("\tTarget file {0} does not exist".format(log_file_name))
                    log_messages.append(file_doesnt_exists)
            log_messages1.extend(log_messages)
    # Storing the Collected Log Messages to Science Logic
    log_message3 = []
    log_message4 = []
    if len(log_messages1) != 0:
        for index in range(len((log_messages1))):
            pattern_cnt = log_messages1[index]
            if re.search("Target.*file.*truncated".strip(),pattern_cnt):
                log_message4.append(pattern_cnt)
            else:
                alert_index = 1
                if alert_index <= 5:
                    for i in range(0, len(single_alerts)):
                        alert_msgs = ""
                        match_pt = log_messages1[index].split(":")[1]
                        if re.search(match_pt.lower().split(";")[0].replace("\n","").strip(),single_alerts[i].lower()):
                            alert_msgs+= " "+str(single_alerts[i]+";")
                            alert_index += 1
                            if alert_index == 7:
                                break
                        pattern_cnt += alert_msgs
                    log_message4.append(pattern_cnt)
    #### Config ###
    if len(log_message4) != 0:
        for index in range(len((log_message4))):
            em7_snippets.generate_alert(log_message4[index].lstrip("\t"), self.did, '1')
            log_touple = (index, log_message4[index].lstrip("\t"))
            log_message3.append(log_touple)
    RESULTS['log'] = log_message3
    print(RESULTS)
    logger.info("RESULTS" + str(RESULTS))
    ssh.close()
    logger.info("***********  Remote Log File Snippet Executed Successfully *********** ")
except Exception as ee:
    logger.error("Snippet execution failed due to error :: {0}".format(ee))
    logger.info("***********  Remote Log File Snippet Execution Failed *********** ")
end = time.time()
duration = abs(startTime - end)
logger.info("Total time taken for execution of script :: {0} seconds on Target Server :: {1}".format(duration,host))
RESULTS['duration'] = [(0, duration)]
result_handler.update(RESULTS)