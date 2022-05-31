#!/usr/bin/env python3
from netmiko import ConnectHandler
from datetime import datetime
import json
import os
import re


today = datetime.now().strftime("%Y%m%d")
current_directory = os.getcwd()
log_dir = os.path.join(current_directory, f"logs_{today}")
os.makedirs(log_dir, exist_ok=True)


def cmd_global_wrapper(f):
    def _wrapper(*args, **kwargs):
        """
        Function to be applied on top of all decorated methods
        Prepends 'config global' to cmd
        """
        if not kwargs:
            raise ValueError("Missing isglobal keyword boolean argument")
        if kwargs["isglobal"]:
            newargs = "config global\n" + args[1]
            args = (args[0], newargs)
        return f(*args, **kwargs)

    return _wrapper


def cmd_vdom_wrapper(f):
    def _wrapper(*args, **kwargs):
        """
        Function to be applied on top of all decorated methods
        Prepends 'config vdom\nedit {vdom}' to cmd
        """
        if not kwargs:
            raise ValueError("Missing vdom keyword argument")
        if kwargs["vdom"]:
            vdom = kwargs["vdom"]
            newargs = "config vdom\nedit " + vdom + "\n" + args[1] + "\nend\n"
            args = (args[0], newargs)
        else:
            raise ValueError("Wrong kwarg. Should be vdom=<vdomName>")
        return f(*args, **kwargs)

    return _wrapper


def cmd_json_wrapper(f):
    def _wrapper(*args, **kwargs):
        """
        Function to be applied on top of all decorated methods
        Return output as JSON
        """
        return json.dumps(f(*args, **kwargs))

    return _wrapper


def grepper(f):
    def _wrapper(*args, **kwargs):
        """
        Function to be applied on top of all decorated methods
        Greps using regex findall
        """
        if not kwargs:
            return f(*args, **kwargs)
        try:
            grep = kwargs["grep"]
            rgrep = re.compile(f".+{grep}.+", re.M)
            grepped = re.findall(rgrep, f(*args, **kwargs))
        except:
            return f(*args, **kwargs)
        return grepped

    return _wrapper


class base_connection:
    """Netmiko functions"""

    def __init__(
        self,
        device_ip="",
        username="",
        password="",
        device_type="fortinet",
        expect_string="#",
        timeout=2,
    ) -> None:
        self.expect_string = expect_string
        self.device_ip = device_ip
        self.username = username
        self.password = password
        self.device_type = device_type
        self.timeout = timeout
        self.device = {
            "ip": self.device_ip,
            "device_type": self.device_type,
            "port": 22,
            "username": self.username,
            "password": self.password,
            "fast_cli": True,
            "session_log": f"{log_dir}/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.device_ip}_netmiko.log",
        }
        self.connection = ConnectHandler(**self.device, timeout=self.timeout)

    def __enter__(self):
        return self

    def __exit__(self, exctype, excinst, exctb):
        self.connection.disconnect()

    def send_single_cmd(self, command):
        return self.connection.send_command(
            command, expect_string=self.expect_string, cmd_verify=False
        )

    def send_set_of_cmds(self, command_set=None):
        return self.connection.send_config_set(command_set, cmd_verify=False)


class FGTRunSingleCmdInGlobal(base_connection):
    @cmd_global_wrapper
    def run_single_cmd_in_global(self, cmd, isglobal=True):
        return self.send_single_cmd(cmd)


class FGTRunSingleCmdInVdom(base_connection):
    @cmd_vdom_wrapper
    def run_single_cmd_in_vdom(self, cmd, vdom=None):
        return self.send_single_cmd(cmd)


class FGTRunConfigSetInVdom(base_connection):
    @cmd_vdom_wrapper
    @grepper
    def run_config_set_in_vdom(self, cmd, vdom=None, grep=""):
        return self.send_set_of_cmds(cmd)


class FGTRunConfigSetInGlobal(base_connection):
    @cmd_global_wrapper
    @grepper
    def run_config_set_in_global(self, cmd, isglobal=True, grep=""):
        return self.send_set_of_cmds(cmd)


class FGTRunConfigSetLoop(base_connection):
    def loop(f):
        def _wrapper(*args, **kwargs):
            """
            Function to be applied on top of all decorated methods
            loops a config set
            """
            while True:
                print("Press CTRL+C to quit")
                try:
                    print(f(*args, **kwargs))
                except KeyboardInterrupt:
                    print("\nExiting..\n")
                    return

        return _wrapper

    @loop
    @grepper
    def run_config_set(self, cmd, grep=""):
        return self.send_set_of_cmds(cmd)


class FGTGlobalStatusInfo(base_connection):
    """Parses 'get sys status' output"""

    def get_sys_status(self, cmd, isglobal=True):
        get_sys_status = self.send_single_cmd(command=cmd)
        _, *get_sys_status_val = get_sys_status.split(":")
        get_sys_status_val = " ".join(get_sys_status_val).strip()
        return get_sys_status_val

    @cmd_json_wrapper
    def get_fortigate_Version(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Version"', isglobal=isglobal
        )
        return {"Version": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Virus_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Virus-DB"', isglobal=isglobal
        )
        return {"Virus_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Extended_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Extended DB"', isglobal=isglobal
        )
        return {"Extended_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Extreme_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Extreme DB"', isglobal=isglobal
        )
        return {"Extreme_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_IPS_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "IPS-DB"', isglobal=isglobal
        )
        return {"IPS_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_IPS_ETDB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "IPS-ETDB"', isglobal=isglobal
        )
        return {"IPS_ETDB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_APP_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "APP-DB"', isglobal=isglobal
        )
        return {"APP_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_INDUSTRIAL_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "INDUSTRIAL-DB"', isglobal=isglobal
        )
        return {"INDUSTRIAL_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Serial_Number(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Serial-Number"', isglobal=isglobal
        )
        return {"Serial_Number": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_IPS_Malicious_URL_Database(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "IPS Malicious URL Database"', isglobal=isglobal
        )
        return {"IPS_Malicious_URL_Database": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Botnet_DB(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Botnet DB"', isglobal=isglobal
        )
        return {"Botnet_DB": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_License_Status(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "License Status"', isglobal=isglobal
        )
        return {"License_Status": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_License_Expiration_Date(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "License Expiration Date"', isglobal=isglobal
        )
        return {"License_Expiration_Date": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_VM_Resources(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "VM Resources"', isglobal=isglobal
        )
        return {"VM_Resources": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Log_hard_disk(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Log hard disk"', isglobal=isglobal
        )
        return {"Log_hard_disk": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Hostname(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Hostname"', isglobal=isglobal
        )
        return {"Hostname": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Private_Encryption(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Private Encryption"', isglobal=isglobal
        )
        return {"Private_Encryption": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Operation_Mode(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Operation Mode"', isglobal=isglobal
        )
        return {"Operation_Mode": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Current_virtual_domain(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Current virtual domain"', isglobal=isglobal
        )
        return {"Current_virtual_domain": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Max_number_of_virtual_domains(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Max number of virtual domains"', isglobal=isglobal
        )
        return {"Max_number_of_virtual_domains": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Virtual_domains_status(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Virtual domains status"', isglobal=isglobal
        )
        return {"Virtual_domains_status": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Virtual_domain_configuration(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Virtual domain configuration"', isglobal=isglobal
        )
        return {"Virtual_domain_configuration": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_FIPS_CC_mode(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "FIPS-CC mode"', isglobal=isglobal
        )
        return {"FIPS_CC_mode": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Current_HA_mode(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Current HA mode"', isglobal=isglobal
        )
        return {"Current_HA_mode": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Branch_point(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Branch point"', isglobal=isglobal
        )
        return {"Branch_point": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_Release_Version_Information(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "Release Version Information"', isglobal=isglobal
        )
        return {"Release_Version_Information": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_FortiOS_x86_64(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "FortiOS x86-64"', isglobal=isglobal
        )
        return {"FortiOS_x86_64": get_sys_status_val}

    @cmd_json_wrapper
    def get_fortigate_System_time(self, isglobal=None):
        get_sys_status_val = self.get_sys_status(
            'get sys status | grep "System time"', isglobal=isglobal
        )
        return {"System_time": get_sys_status_val}


class FGTGlobalPerfInfo(base_connection):
    """Parses 'get sys perf status' output"""

    @cmd_global_wrapper
    def get_sys_perf(self, cmd, isglobal=True):
        get_sys_perf_status = self.send_single_cmd(command=cmd)
        _, *get_sys_perf_status_val = get_sys_perf_status.split(":")
        get_sys_perf_status_val = " ".join(get_sys_perf_status_val).strip()
        return get_sys_perf_status_val

    @cmd_global_wrapper
    def get_sys_perf_cpu(self, cmd, isglobal=True):
        """Returns a dict of available CPU data
        returns: {"CPU_states": {"CPU": ["0% user", "0% system", "0% nice", "100% idle", "0% iowait", "0% irq", "0% softirq"], "CPU0": ["0% user", "0% system", "0% nice", "100% idle", "0% iowait", "0% irq", "0% softirq"]}}
        """
        cpu_regex = r"(CPU\d*)\sstates:\s(\d+\W\s\w+)\s(\d+\W\s\w+)\s(\d+\W\s\w+)\s(\d+\W\s\w+)\s(\d+\W\s\w+)\s(\d+\W\s\w+)\s(\d+\W\s\w+)"
        get_sys_perf_status = self.send_single_cmd(command=cmd)
        cpu_regex = re.compile(cpu_regex)
        cpus_found = re.findall(cpu_regex, get_sys_perf_status)
        cpus_dict = {}
        for i in list(cpus_found):
            cpus_dict[i[0]] = i[1:]
        return cpus_dict

    @cmd_json_wrapper
    def get_fortigate_CPU_states(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf_cpu(
            'get sys perf status | grep "CPU"', isglobal=isglobal
        )
        return {"CPU_states": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_Memory(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "Memory"', isglobal=isglobal
        )
        return {"Memory": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_Average_network_usage(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "Average network usage"', isglobal=isglobal
        )
        return {"Average_network_usage": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_Average_sessions(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "Average sessions"', isglobal=isglobal
        )
        return {"Average_sessions": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_Average_session_setup_rate(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "Average session setup rate"', isglobal=isglobal
        )
        return {"Average_session_setup_rate": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_Virus_caught(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "Virus caught"', isglobal=isglobal
        )
        return {"Virus_caught": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_IPS_attacks_blocked(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "IPS attacks blocked"', isglobal=isglobal
        )
        return {"IPS_attacks_blocked": get_sys_perf_status_val}

    @cmd_json_wrapper
    def get_fortigate_Uptime(self, isglobal=None):
        get_sys_perf_status_val = self.get_sys_perf(
            'get sys perf status | grep "Uptime"', isglobal=isglobal
        )
        return {"Uptime": get_sys_perf_status_val}


class FGTUtilities(FGTGlobalStatusInfo, FGTGlobalPerfInfo):
    """Class used to wrap up utility classes into a single object"""

    @staticmethod
    def parse_getcmd(getcmd):
        """Receives get cmd input and outputs jsons. Useful for config syntax.
        param: getcmd =
            FGVM01TM21002021 (global) # get sys ha
            group-id            : 0
            group-name          :
            mode                : standalone
            sync-packet-balance : disable
        return: json object indent 4
                {
            "group_id": "0",
            "group_name": "",
            "mode": "standalone",
            "sync_packet_balance": "disable",
            }
        """
        json_return_obj = {}
        for i in getcmd.splitlines():
            if ":" in i:
                item = i.split(":")
                if item[0]:
                    key_original = (
                        item.pop(0).strip().replace(" ", "_").replace("-", "_")
                    )
                    value = " ".join(item).strip()
                    json_return_obj[key_original] = value
        return json.dumps(json_return_obj, indent=4)


# if __name__ == "__main__":

#     #     EXAMPLES

#     fgt = "192.168.1.100", "admin", "test"
#     # fgt = "10.0.10.245", "admin", "test"

#     print("#" * 200 + "\n" + "1 - BASE CONNECTION" + "\n" + "#" * 200)
#     with base_connection(*fgt) as bc:
#         print(bc.send_single_cmd("print tablesize"))

#     print("#" * 200 + "\n" + "2 - GLOBAL STATUS INFO" + "\n" + "#" * 200)
#     with FGTGlobalStatusInfo(*fgt) as bc:
#         print(bc.get_fortigate_System_time())
#         print(bc.get_fortigate_FortiOS_x86_64())
#         print(bc.get_fortigate_Release_Version_Information())

#     print("#" * 200 + "\n" + "3 - GLOBAL SINGLE CMD" + "\n" + "#" * 200)
#     with FGTRunSingleCmdInGlobal(*fgt) as bc:
#         print(bc.run_single_cmd_in_global("get sys perf status", isglobal=True))

#     print("#" * 200 + "\n" + "4 - SINGLE CMD IN VDOM" + "\n" + "#" * 200)
#     with FGTRunSingleCmdInVdom(*fgt) as bc:
#         print(bc.run_single_cmd_in_vdom("sh router bgp", vdom="root"))

#     print("#" * 200 + "\n" + "5 - GLOBAL PERF INFO" + "\n" + "#" * 200)
#     with FGTGlobalPerfInfo(*fgt) as bc:
#         print(bc.get_fortigate_IPS_attacks_blocked(isglobal=True))
#         print(bc.get_fortigate_Uptime(isglobal=True))
#         print(bc.get_fortigate_Average_sessions(isglobal=True))
#         print(bc.get_fortigate_CPU_states(isglobal=True))

#     print("#" * 200 + "\n" + "6 - CONFIG SET IN VDOM" + "\n" + "#" * 200)
#     with FGTRunConfigSetInVdom(*fgt) as bc:
#         print(
#             bc.run_config_set_in_vdom(
#                 """
#                 sh router bgp
#                 sh router static
#                 get sys status
#                 sh log memory setting
#                 """,
#                 vdom="root",
#             )
#         )

#     print("#" * 200 + "\n" + "7 - CONFIG SET IN GLOBAL" + "\n" + "#" * 200)
#     with FGTRunConfigSetInGlobal(*fgt) as bc:
#         print(
#             bc.run_config_set_in_global(
#                 """
#                 get sys perf status
#                 sh sys ha
#                 get sys interface
#                 sh log syslogd setting
#                 sh log syslogd2 setting
#                 """,
#                 isglobal=True,
#             )
#         )

#     print("#" * 200 + "\n" + "8- GREPPER - CONFIG SET IN GLOBAL" + "\n" + "#" * 200)
#     # grepper test
#     with FGTRunConfigSetInGlobal(*fgt) as bc:
#         print(
#             bc.run_config_set_in_global(
#                 """
#                     get sys perf status
#                     sh sys ha
#                     """,
#                 isglobal=True,
#                 grep="session|Memory",
#             )
#         )

#     print("#" * 200 + "\n" + "9 - LOOP + GREPPER" + "\n" + "#" * 200)
#     # loop test with grepper
#     with FGTRunConfigSetLoop(*fgt) as bc:
#         print(
#             bc.run_config_set(
#                 """
#                     c g
#                     get sys perf status
#                     sh sys ha
#                     end
#                     c v
#                     edit root
#                     get router info bgp sum
#                     end
#                     """,
#                 grep="session",
#             ),
#         )

#     print("#" * 200 + "\n" + "10 - FGT UTILITIES" + "\n" + "#" * 200)
#     with FGTUtilities(*fgt) as bc:
#         print(bc.get_fortigate_System_time())
#         print(bc.get_fortigate_IPS_attacks_blocked(isglobal=True))
