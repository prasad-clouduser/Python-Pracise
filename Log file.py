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

# Logging

do_debug_output = False
logfile = '/data/logs/unix_sfty_ecbackup_ascii_logfile_monitoring.log'

if do_debug_output is True:
    logger = em7_snippets.logger(filename=logfile)
else:
    logger = em7_snippets.logger(filename='/dev/null')

"""
Note :: If you want to monitor LogFile from firstline number provide "0". Example :: linux_files={'filename':'0'}
Note :: If you want to monitor LogFile from lastline number provide "1". Example  :: linux_files={'filename':'1'} """

linux_files = {'/opspool/backup/sat-backup-remedy.log': '1'}
solaris_files = {'/opspool/backup/sat-backup-remedy.log': '1'}

""" Provide FilesNames which needs to be monitored along with Log Message Patterns
Search Inputs :: Provide "Files to be monitored as keys with fullpath of file" and "Log Message patterns as List of Values" """

linux = {'/opspool/backup/sat-backup-remedy.log': ['EC Backup FAILURE'], }

solaris = {'/opspool/backup/sat-backup-remedy.log': ['EC Backup FAILURE'], }

osnames = {'Linux': linux, 'SunOS': solaris}

# Maximum Lines to read for every data polling
Maximum_Number_of_Lines_to_read = 100000;

# Path to which AWKscript is to be pushed
AWK_path = "~/awkscript_ecbackup"

# Number of Patterns to be pushed to AWKscript
Maximum_patterns_to_AWKscript = 3;

# Provide time period in mins for AWKscript to be updated
Update_AWKScript_in_days = 1;

# Recovery file which stores log_file_name,last_linenumber and LastLineMessage on the Target server.
recovery_file_name = '~/SL_log_mon_ecbackup.rec'

# Dictionaries to store the LogMessages and RollOverFilesNames
RESULTS = {}
single_alerts = []
Rolloverlogfiles = {}
startTime = time.time()

did = self.did
try:
    # Connection Parameters used for connecting to Target Device Box
    host = self.cred_details['cred_host']
    port = 22
    username = self.cred_details['cred_user']
    password = self.cred_details['cred_pwd']
    logger.info(
        "[DID:{0}]: *********** Starting Remote Log File Snippet Dynamic Application ***********".format(str(did)))

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
    # platformname = "SunOS"
    logger.info("[DID:{0}]: SSH is connected successfully to Target Server".format(did))
    logger.info("[DID:{1}]: Target Server Operating System type : {0}".format(platformname, did))
    logmonpolicy = {}
    if platformname in osnames:
        logmonpolicy = osnames[platformname]

    ## Storing Roll Over Files in Dictionary
    for log_file_name in logmonpolicy:
        log_files = []
        logfilepath_list = log_file_name.split('/')
        rollover_files = 'ls -lt {0}*'.format(log_file_name)
        stdin1, stdout1, stderr1 = ssh.exec_command(rollover_files)
        total_rollover_files = stdout1.readlines()
        for roll_file in total_rollover_files:
            if str(log_file_name) != str(roll_file.split(" ")[-1].strip()):
                log_files.append(roll_file.split(" ")[-1])
        Rolloverlogfiles[log_file_name] = log_files
        logger.info("[DID:{1}]: RollOver Files on Target Server : {0}".format(Rolloverlogfiles, did))
        # print(Rolloverlogfiles)


    def push_awk_script(patterns):
        """
                    This Function is used to create AWK Script on the Target Server in '/tmp/' folder based on maximum count of Patterns
                    :param patterns: Maximum number of Patterns
        """
        pattern_string = ''
        pattern_string1 = ''
        pattern_string2 = ''
        pattern_string3 = ''
        pattern_string4 = ''
        for pattern_count in range(1, patterns + 1):
            pattern_string += "p" + str(pattern_count) + "=0;"
            # pattern_string1 += 'NR>=startline && pattern' + str(pattern_count) + ' && $0 ~ pattern' + str(pattern_count) + '{ ++p' + str(pattern_count) + '; print "pattern' + str(pattern_count) + '::",$0 }\n'
            pattern_string1 += 'NR<=stopline && NR>=startline && pattern' + str(pattern_count) + " && p" + str(
                pattern_count) + "<4 " + ' && $0 ~ pattern' + str(pattern_count) + '{ ' + 'print "pattern' + str(
                pattern_count) + '::",$0 }\n'
            pattern_string3 += 'NR<=stopline && NR>=startline && pattern' + str(
                pattern_count) + ' && $0 ~ pattern' + str(pattern_count) + '{ ++p' + str(
                pattern_count) + '; pattern' + str(pattern_count) + 'line=$0}\n'
            # pattern_string2 += 'print "Matched' + str(pattern_count) + '::' + '",pattern' + str(pattern_count) + ',"::has occured::" p' + str(pattern_count) + ';\n'
            pattern_string2 += 'print "Matched' + str(pattern_count) + '::' + '",pattern' + str(
                pattern_count) + ',"::has occured::" p' + str(pattern_count) + ';\n'
            pattern_string4 += 'print "pattern' + str(pattern_count) + '::",' + 'pattern' + str(
                pattern_count) + 'line;\n'
        awk_code = """
            #!/usr/bin/awk -f
            BEGIN {%s stopline = startline + %d }
            NR==1 Firstline{ print "Firstline::",$0}
            NR<startline {next}
            NR>stopline { exit;}
            %s
            %s
            END { %s
            %s
            if (NR > stopline) { print "TotalLines::",stopline;} else { print "TotalLines::",NR;} }
            """ % (
        pattern_string, int(Maximum_Number_of_Lines_to_read), pattern_string1, pattern_string3, pattern_string4,
        pattern_string2)
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
            # command = """'sed '{0}!d' {1}| fgrep '{2}'""".format(last_linenumber, log_filename, first_linepattern)
            # command = """sed '1!d' {1}| fgrep '{2}'""".format(last_linenumber, log_filename, first_linepattern)
            # command = """head -1 {1}| fgrep '{2}'""".format(last_linenumber, log_filename, first_linepattern)
            ## 03/19/2019
            command = '''head -1 {1}'''.format(last_linenumber, log_filename)
            stdin, stdout, stderr = ssh.exec_command(command)
            firstline_existence = stdout.readlines()
            ssh_data = (firstline_existence[0].replace("'", "").replace('"', '').replace("\n", ""))
            file_data = (first_linepattern.replace("'", "").replace('"', '').replace("\n", ""))
            if len(firstline_existence) != 0 and file_data in ssh_data:
                log_messages = process_data(last_linenumber, log_filename, recovery_file_name, patterns,
                                            firstline_existence)
                return log_messages
            else:
                index = 0
                while index < len(Rolloverlogfiles[log_filename]):
                    RollOverlogfilename = str(Rolloverlogfiles[log_filename][index]).replace('\n', '')
                    # command = "sed '{0}!d' {1}| fgrep '{2}'".format(last_linenumber, RollOverlogfilename, first_linepattern.replace('\n',''))
                    # command = """sed '1!d' {1}| fgrep '{2}'""".format(last_linenumber, RollOverlogfilename, first_linepattern)
                    # command = """head -1 {1}| fgrep '{2}'""".format(last_linenumber, log_filename, first_linepattern)
                    ## 03/19/2019
                    logger.info(
                        "[DID:{1}]: File got rolled over and checking Roll Over File on Target Server : {0}".format(
                            RollOverlogfilename, did))
                    command = '''head -1 {1}'''.format(last_linenumber, RollOverlogfilename)
                    stdin, stdout, stderr = ssh.exec_command(command)
                    firstline_existence = stdout.readlines()
                    ssh_data = (firstline_existence[0].replace("'", "").replace('"', '').replace("\n", ""))
                    file_data = (first_linepattern.replace("'", "").replace('"', '').replace("\n", ""))
                    if len(firstline_existence) != 0 and file_data in ssh_data:
                        matched_messages = process_data(last_linenumber=last_linenumber,
                                                        log_filename=RollOverlogfilename,
                                                        recovery_file_name=recovery_file_name, patterns=patterns,
                                                        firstline_existence=firstline_existence)
                        log_messages.extend(matched_messages)
                        rolloverfiles_list = sorted(Rolloverlogfiles[log_filename][:index])
                        if len(rolloverfiles_list) != 0:
                            filtered_messages = []
                            for rollfile in rolloverfiles_list:
                                # print("ROLLOVER NAME",rollfile)
                                logger.info(
                                    "[DID:{1}]: Processing Roll over File : {0} on Target Server".format(rollfile, did))
                                rolllogfilename = rollfile.replace('\n', '')
                                match_messages = process_data(last_linenumber=0, log_filename=rolllogfilename,
                                                              recovery_file_name=recovery_file_name, patterns=patterns,
                                                              firstline_existence=firstline_existence)
                                filtered_messages.extend(match_messages)
                            matched_messages = process_data(last_linenumber=0, log_filename=log_filename,
                                                            recovery_file_name=recovery_file_name, patterns=patterns,
                                                            firstline_existence=firstline_existence)
                            log_messages.extend(matched_messages)
                            log_messages.extend(filtered_messages)
                            break
                        else:
                            matched_messages = process_data(last_linenumber=0, log_filename=log_file_name,
                                                            recovery_file_name=recovery_file_name, patterns=patterns,
                                                            firstline_existence=firstline_existence)
                            log_messages.extend(matched_messages)
                        return log_messages
                    else:
                        index = index + 1
                if len(log_messages) == 0:
                    log_messages = check_lastline_pattern(last_linenumber=0, log_filename=log_file_name,
                                                          first_linepattern='', patterns=logmonpolicy[log_file_name],
                                                          recovery_file_name=recovery_file_name)
                    # print("M",log_messages)
                    truncate = "\tTarget file {0} has been truncated".format(log_filename)
                    logger.info(
                        "[DID:{1}]: Target file {0} has been truncated on Target Server".format(log_filename, did))
                    log_messages.append(truncate)
                    return log_messages
                else:
                    return log_messages
        else:
            firstline_existence = ''
            matched_messages = process_data(last_linenumber=last_linenumber, log_filename=log_filename,
                                            recovery_file_name=recovery_file_name, patterns=patterns,
                                            firstline_existence=firstline_existence)
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
        for pattern_count in range(1, len(patterns) + 1):
            # pattern_string3 += ' -vpattern' + str(pattern_count) + '="' + str(patterns[pattern_count - 1]) + '" '
            pattern_string3 += ' -v ' + '"pattern' + str(pattern_count) + '=' + str(patterns[pattern_count - 1]) + '"'
        if firstline_existence is not None:
            if platformname == 'Linux':
                command = 'awk -v "startline=%d" %s  -v "IGNORECASE=1" -f %s %s' % (
                int(last_linenumber) + 1, pattern_string3, str(AWK_path), log_filename)
            elif platformname == 'SunOS':
                command = 'nawk -v "startline=%d" %s -f %s %s' % (
                int(last_linenumber) + 1, pattern_string3, str(AWK_path), log_filename)
            logger.info("[DID:{1}]: Executing {0} on Target Server".format(command, did))
            stdin, stdout, stderr = ssh.exec_command(command)
            records_retrieved = stdout.readlines()
            if firstline_existence is not None and len(records_retrieved) != 0:
                matched_messages = parsing_data(records_retrieved, last_linenumber, recovery_file_name, patterns,
                                                log_filename)
                return matched_messages
            else:
                matched_messages = parsing_data(records_retrieved, last_linenumber, recovery_file_name, patterns,
                                                log_filename)
                return matched_messages
        else:
            ##command = 'awk -v startline=%d%s-f /tmp/awkscript3 %s' % (0, pattern_string3, log_filename)
            stdin, stdout, stderr = ssh.exec_command(
                'awk -v startline=%d %s-f %s %s' % (0, pattern_string3, str(AWK_path), log_filename))
            outlines_empty = stdout.readlines()
            if len(outlines_empty) == 0:
                recovery_file_update(total_lines=0, first_line_message="", log_file_name=log_filename,
                                     recovery_file_name=recovery_file_name)
                # print("N",log_messages)
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
        matched_messages = []
        first_line_message = ''
        total_lines = 0
        ## Updated ##
        time_list = []
        MATCHED = []
        print("dataaaa", time_list)
        stdin, stdout, stderr = ssh.exec_command("hostname")
        HOSTNAME_SPLIT = stdout.readlines()[0]
        HOSTNAME = str(HOSTNAME_SPLIT.split('.')[0].replace("\n", ""))
        ##
        try:
            for msg in records_retrieved:
                if msg.startswith("pattern"):
                    ##print("DATA"+str(msg))
                    a = msg.split("::")[1]
                    if len(a.replace("\n", "")) > 1:
                        time_list.append(a.split(HOSTNAME)[0].strip())
                        logmsg = str("\tLogMonAlert-" + msg.split("::")[1])
                        single_alerts.append(msg.split("::")[1].replace("\n", "").strip())
                    # matched_messages.append(logmsg)
                elif msg.startswith("Lastline"):
                    last_line_message = msg.split("::")[1].strip(" ").replace("\n", "")
                elif msg.startswith("Firstline"):
                    first_line_message = msg.split("::")[1].strip(" ").replace("\n", "")
                elif msg.startswith("TotalLines"):
                    total_lines += int(msg.split("::")[1].strip(" "))
                elif msg.startswith("Matched"):
                    if (int(msg.split("::")[3])) != 0:
                        macthedpatternscnt = ("\t" + "Pattern: " + msg.split("::")[1].strip() + "; Matches found: " +
                                              msg.split("::")[3].strip("\n") + "; File: " + log_file_name)
                        # macthedpatternscnt=("\t"+"{0}-Pattern: "+msg.split("::")[1].strip() +"; Matches found: "+ msg.split("::")[3].strip("\n") +"; File: "+ log_file_name ).format(prefix_string)
                        MATCHED.append(macthedpatternscnt)
            ##########Start Time and End Time ###
            MATCHED_TIME = {}
            print("LENGTH", len(MATCHED))
            if len(MATCHED) != 0 and platformname == "SunOS":
                single_alerts.pop()
                print("Solaris")

            if len(MATCHED) != 0 and platformname == "Linux":
                single_alerts.pop()
                print("Linux")
            if len(MATCHED) != 0:
                for macthedpattern1 in MATCHED:
                    time1_list = []
                    for data1 in single_alerts:
                        if re.search(macthedpattern1.split(":")[1].split(";")[0].strip().lower(), data1.lower()):
                            time1_list.append(data1.split(HOSTNAME)[0].strip())
                    matched_messages.append(
                        macthedpattern1 + "; Starttime: " + time1_list[0] + ";  Endtime: " + time1_list[
                            -1] + ";--MATCHES--")
                    # matched_messages.append(macthedpattern1+"; Starttime: "+time1_list[0]+ ";  Endtime: "+time1_list[-1]+";--MATCHES--")

            print("Total", total_lines)
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
        file_namee = ''
        for file_name in recovery_file_data:
            if (file_name == log_file_name):
                recovery_file_data[log_file_name] = (total_lines, first_line_message)
        for file_nam in recovery_file_data:
            if file_nam != "filename":
                line1 = str(recovery_file_data[file_nam][1]).replace('"', '\\"')
                file_namee += str(file_nam) + "," + str(recovery_file_data[file_nam][0]) + "," + str(line1) + str("\n")
        # command = "echo '{0}' >{1}".format(str(file_namee), recovery_file_name)
        ## 03/19/2019
        command = 'echo "{0}" >{1}'.format(str(file_namee), recovery_file_name)
        stdin, stdout, stderr = ssh.exec_command(command)


    ################################################
    ############# Main Function ####################
    ################################################

    """ Checks Whether AWKScript Exists on Target Server or Not by excuting below command on Target Server.
    If AWKScript doesnt exists it will create it in '/tmp/' Folder """
    stdin, stdout, stderr = ssh.exec_command(
        "[ -f {0} ] && echo AWKScriptExists || echo AWKDoesNotExists".format(str(AWK_path)))
    check_awk_script = stdout.readlines()
    # Checks if AWKScript Exists or not; If not it will creates it on Target Server
    logger.info("[DID:{0}]: Checking for AWKscript : {1} on the Target Server".format(did, AWK_path))
    if check_awk_script[0].strip("\n") == "AWKScriptExists":
        command = "find {0} -mtime +{1}".format(AWK_path, Update_AWKScript_in_days)
        # print(command)
        stdin, stdout, stderr = ssh.exec_command(command)
        awk_script_age = stdout.readlines()
        if len(awk_script_age) != 0:
            # print("Test",awk_script_age)
            push_awk_script(patterns=int(Maximum_patterns_to_AWKscript))
            logger.info("[DID:{1}]: AWKscript is updated as it existing for past {0} days on the Target Server".format(
                Update_AWKScript_in_days, did))
        logger.info("[DID:{0}]: AWKScript : {1} already existed on the Target Server".format(did, recovery_file_name))
    else:
        # If AWKSript DoesNOTExists Creates it on Target Server using 'push_awk_script()' function
        logger.info("[DID:{0}]: AWKScript doesn't exists on Target Server".format(did))
        logger.info("[DID:{0}]: Creating AWKScript : {1} on Target Server".format(did, AWK_path))
        push_awk_script(patterns=Maximum_patterns_to_AWKscript)
    """ Checks Whether RecoveryFile Exists on Target Server or Not by excuting below command on Target Server.
    If RecoveryFile doesnt exists it will create in '/tmp/' Folder """
    stdin1, stdout1, stderr1 = ssh.exec_command(
        "[ -f {0} ] && echo RecoveryFileExists || echo RecoveryFileDoesNotExists".format(recovery_file_name))
    check_recovery_file = stdout1.readlines()
    # Checks if Recovery File Exists or not; If not it will create it on Target Server
    logger.info("[DID:{0}]: Checking for RecoveryFile : {1} on the Target Server".format(did, recovery_file_name))
    if check_recovery_file[0].strip("\n") == "RecoveryFileExists":
        logger.info(
            "[DID:{0}]: RecoveryFile : {1} already existed on the Target Server".format(did, recovery_file_name))
    else:
        # If RecoveryFile DoesNOTExists Creates it on Target Server using below code
        logger.info("[DID:{0}]: RecoveryFile doesn't exists on Target Server".format(did))
        logger.info("[DID:{0}]: Creating RecoveryFile : {1} on Target Server".format(did, recovery_file_name))
        file_create = 'filename,lastlinenumber,firstlinepattern\n'
        firstlinepattern = ''
        recovery_file_data = {}
        for filename in logmonpolicy:
            if platformname == "Linux":
                for file in linux_files:
                    if file == filename:
                        if linux_files[filename] == "1":
                            cmd = "wc -l {0}".format(filename)
                            stdin, stdout, stderr = ssh.exec_command(cmd)
                            lastline = stdout.readlines()
                            if len(lastline) != 0:
                                lastlinenumber = str(lastline[0].strip().split(" ")[0])
                                recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(
                                    recovery_file_data[filename][1]) + str("\n")
                            else:
                                lastlinenumber = '0'
                                recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(
                                    recovery_file_data[filename][1]) + str("\n")
                        else:
                            lastlinenumber = '0'
                            recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                            file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(
                                recovery_file_data[filename][1]) + str("\n")
            elif platformname == "SunOS":
                for file in solaris_files:
                    if file == filename:
                        if solaris_files[filename] == "1":
                            cmd = "wc -l {0}".format(filename)
                            stdin, stdout, stderr = ssh.exec_command(cmd)
                            lastline = stdout.readlines()
                            if len(lastline) != 0:
                                lastlinenumber = str(lastline[0].strip().split(" ")[0])
                                recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(
                                    recovery_file_data[filename][1]) + str("\n")
                            else:
                                lastlinenumber = '0'
                                recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                                file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(
                                    recovery_file_data[filename][1]) + str("\n")
                        else:
                            lastlinenumber = '0'
                            recovery_file_data[filename] = [lastlinenumber, firstlinepattern]
                            file_create += str(filename) + "," + str(recovery_file_data[filename][0]) + "," + str(
                                recovery_file_data[filename][1]) + str("\n")
        command = "echo '{0}' >{1}".format(str(file_create), recovery_file_name)
        stdin, stdout, stderr = ssh.exec_command(command)
        recovery_file_data = {}
        file_cmd = 'cat {0}'.format(recovery_file_name)
        stdin, stdout, stderr = ssh.exec_command(file_cmd)
        reader = stdout.readlines()
        for record in reader:
            if len(record.strip("\n")) != 0:
                recovery_file_data[(record.strip("\n").split(",")[0])] = [record.strip("\n").split(",")[1],
                                                                          record.strip("\n").split(",")[2]]

    # Retrieving data from RecoveryFile like FileName, last_linenumber Count and FirstLinepattern
    recovery_file_data = {}
    file_cmd = 'cat {0}'.format(recovery_file_name)
    stdin, stdout, stderr = ssh.exec_command(file_cmd)
    reader = stdout.readlines()
    for record in reader:
        if len(record.strip("\n")) != 0:
            recovery_file_data[(record.strip("\n").split(",")[0])] = [record.strip("\n").split(",")[1],
                                                                      record.strip("\n").split(",")[2]]

    # Updating the Recovery File when NewLogFile is added for Monitoring
    for log_filename in logmonpolicy:
        if log_filename not in recovery_file_data.keys():
            logger.info("[DID:{1}]: Added New logfilename for monitoring :: {0} on Target Server".format(
                str(log_filename, str(did))))
            file_cmd = 'cat {0}'.format(recovery_file_name)
            stdin, stdout, stderr = ssh.exec_command(file_cmd)
            reader = stdout.readlines()
            for record in reader:
                if len(record.strip("\n")) != 0:
                    recovery_file_data[(record.strip("\n").split(",")[0])] = [record.strip("\n").split(",")[1],
                                                                              record.strip("\n").split(",")[2]]
            recovery_file_data[log_filename] = ('0', "")
    log_messages1 = []

    # Processing of each Logfile
    for log_file_name in logmonpolicy:
        log_messages = []
        ## Check Directory permissions
        stdin9, stdout9, stderr9 = ssh.exec_command("tail -1 {0}".format(log_file_name))
        filedir = stdout9.readlines()
        filedir_nopermission = stderr9.readlines()
        if len(filedir_nopermission) != 0 and re.match(".*Permission denied.*", str(filedir_nopermission[0])):
            logger.info("[DID:{1}]: Checking for File Permission : {0} on the Target server".format(log_file_name, did))
            logger.info(
                "[DID:{1}]: Logfile {0} doesn't have required Permissions on the Target server".format(log_file_name,
                                                                                                       did))
            file_doesnt_have_permissions = (
                "\tTarget file {0} does not have required permissions".format(log_file_name))
            log_messages1.append(file_doesnt_have_permissions)
        else:
            """ Checks if LogFile which needs to be Monitored exists on the Target Server or Not. 
            By Executing below command on Target Server we can Check LogFile Exists or Not """
            stdin2, stdout2, stderr2 = ssh.exec_command(
                "[ -f {0} ] &&  echo LogFileExists   || echo LogFileDoesnotExists  ".format(log_file_name))
            check_file_existence = stdout2.readlines()
            # If LogFile Exists Continues processing #
            if str(str(check_file_existence[0]).split('\n')[0]) == 'LogFileExists':
                logger.info(
                    "[DID:{1}]: Checking for File existence : {0} on the Target server".format(log_file_name, did))
                logger.info("[DID:{1}]: Logfile {0} exists on the Target server".format(log_file_name, did))
                # Checks if LogFile has permissions to read using executing below command on Target Server
                stdin, stdout, stderr = ssh.exec_command("tail -1 {0}".format(log_file_name))
                check_file_permissions = stderr.readlines()
                # If LogFile has Required Permissions are Present then Continues Processing
                if (len(check_file_permissions) == 0):
                    logger.info(
                        "[DID:{1}]: Checking for File Permission : {0} on the Target server".format(log_file_name, did))
                    logger.info(
                        "[DID:{1}]: Logfile {0} have required Permissions on the Target server".format(log_file_name,
                                                                                                       did))
                    logger.info(
                        "[DID:{1}]: Processing of LogFile :: {0} is started on Target server".format(log_file_name,
                                                                                                     str(did)))
                    log_messages = check_lastline_pattern(last_linenumber=int(recovery_file_data[log_file_name][0]),
                                                          first_linepattern=recovery_file_data[log_file_name][1],
                                                          patterns=logmonpolicy[log_file_name],
                                                          log_filename=log_file_name,
                                                          recovery_file_name=recovery_file_name)
                    logger.info(
                        "[DID:{1}]: Processing of LogFile :: {0} is Completed on Target server".format(log_file_name,
                                                                                                       did))
                    logger.info(
                        "[DID:{2}]: {0} matched messages are retrieved from logfile :: {1} on Target server".format(
                            len(log_messages), log_file_name, did))
                # If LogFile doesn't have required Permissions throws Permission denied
                if re.match(".* cannot open .* for reading", str(check_file_permissions)):
                    logger.info(
                        "[DID:{1}]: Checking for File Permission : {0} on the Target server".format(log_file_name, did))
                    logger.info("[DID:{1}]: Logfile {0} doesn't have required Permissions on the Target server".format(
                        log_file_name, did))
                    file_doesnt_have_permissions = (
                        "\tTarget file {0} does not have required read permissions on ".format(log_file_name))
                    # log_messages.append(file_doesnt_have_permissions)
            else:
                # If LogFile doesn't Exists on Target
                logger.info(
                    "[DID:{1}]: Checking for File existence : {0} on the Target server".format(log_file_name, did))
                logger.info("[DID:{1}]: Logfile {0} doesn't exists on the Target server".format(log_file_name, did))
                file_doesnt_exists = ("\tTarget file {0} does not exist".format(log_file_name))
                log_messages.append(file_doesnt_exists)
            log_messages1.extend(log_messages)

    # Storing the Collected Log Messages to Science Logic
    log_message3 = []
    log_message4 = []
    if len(log_messages1) != 0:
        for index in range(len((log_messages1))):
            pattern_cnt = log_messages1[index]
            if re.search("Target.*file.*truncated".strip(), pattern_cnt):
                log_message4.append(pattern_cnt)
            else:
                # stdin, stdout, stderr = ssh.exec_command("hostname")
                # HOSTNAME_SPLIT = stdout.readlines()[0]
                # HOSTNAME = str(HOSTNAME_SPLIT.split('.')[0].replace("\n", ""))
                alert_index = 1
                if alert_index <= 5:
                    for i in range(0, len(single_alerts)):
                        # ENDTIME = []
                        alert_msgs = ""
                        match_pt = log_messages1[index].split(":")[1]
                        if re.search(match_pt.lower().split(";")[0].replace("\n", "").strip(),
                                     single_alerts[i].lower()):
                            # ENDTIME.append(single_alerts[i])
                            # if len(ENDTIME) != 0:
                            # print("LAST",ENDTIME[0])
                            alert_msgs += " " + str(single_alerts[i] + ";")
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
    logger.info("[DID:" + str(did) + "]" + ": RESULTS" + str(RESULTS))
    ssh.close()
    logger.info("[DID:{0}]: ***********  Remote Log File Snippet Executed Successfully *********** ".format(str(did)))
except Exception as ee:
    print(ee)
    logger.error("[DID:{0}]: Snippet execution failed due to error :: {0}".format(ee, str(did)))
    logger.info("[DID:{0}]: ***********  Remote Log File Snippet Execution Failed *********** ".format(str(did)))
end = time.time()
duration = abs(startTime - end)
logger.info("[DID:{1}]: Total time taken for execution of script :: {0} seconds on Target Server".format(duration, did))
RESULTS['duration'] = [(0, duration)]
result_handler.update(RESULTS)