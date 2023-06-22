#!/usr/bin/python3 

import os
import sys
import re
import tarfile
import gzip
import shutil
import json
import logging
import argparse
import socket
import struct
from format_ei import *
from ast import literal_eval
from logging.handlers import RotatingFileHandler



class colours():
    header = '\033[95m'
    okblue = '\033[94m'
    okgreen = '\033[92m'
    warning = '\033[93m'
    fail = '\033[91m'
    endc = '\033[0m'
    quote = '\033[1;36m'
    gray = '\033[0;37m'


DIV = "---------------------------------------------------------"

log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
log_file = 'ei.log'
ei_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5*1024*1024,backupCount=5, encoding=None, delay=0)
ei_handler.setFormatter(log_formatter)
ei_handler.setLevel(logging.INFO)
ei_log = logging.getLogger('root')
ei_log.setLevel(logging.INFO)
ei_log.addHandler(ei_handler)


def gsearch(path, re_pattern, delimiter="", index=0):
    pattern = re.compile(re_pattern)
    for line in open(path):
        if pattern.search(line):
            if delimiter:
                vals = re.split(delimiter, line.strip())
                return vals[index]
            else:
                return line.strip("\n")


def get_oldest_timestamp(log):
    match = ""
    var_log = os.listdir(BASE_PATH + "/var/log/")
    sys_log_files = []
    oldest_timestamp = "9999-99-99T99:99:99"
    for log_file in var_log:
        if re.match("^syslog", log_file):
            sys_log_files.append(log_file)

    for sys_log in sys_log_files:
        if ".gz" in sys_log:
            with gzip.open(BASE_PATH + "/var/log/" + sys_log, "rb") as d_syslog:
                for line in reversed(d_syslog.readlines()):
                    try:
                        match = re.findall(
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}[T][0-9]{2}:[0-9]{2}:[0-9]{2}", line)[0]
                    except:
                        pass

                    if match and match < oldest_timestamp:
                        oldest_timestamp = match
                        print("DEBUG oldest_timestamp" + oldest_timestamp)
                        break

    return oldest_timestamp


def get_edge_summary():

    AB_PATH_1 = BASE_PATH + "/node_config.json"
    AB_PATH_2 = BASE_PATH + "/config/vmware/edge/config.json"
    AB_PATH_5 = BASE_PATH + "/edge/tunnel-ports-stat"
    AB_PATH_6 = BASE_PATH + "/etc/network/interfaces"
    AB_PATH_7 = BASE_PATH + "/proc/meminfo"
    AB_PATH_8 = BASE_PATH + "/edge/cpu_info"
    AB_PATH_9 = BASE_PATH + "/edge/node-status"
    AB_PATH_10 = BASE_PATH + "/edge/controller-connections"
    KB = 1048576

    errors = []
    edge_summary = {}

    try: 
        with open(AB_PATH_1, "r", encoding="UTF-8") as jfile:
            try:
                node_config = json.load(jfile)
            except json.decoder.JSONDecodeError:
                errors.append(AB_PATH_1)
            else:
                try:
                    for config in node_config:
                        if config == "/api/v1/node":
                            edge_summary.update({"fqdn": node_config[config]["hostname"], "uuid": node_config[config]["node_uuid"],
                                                 "version": node_config[config]["node_version"], "kernel": node_config[config]["kernel_version"],
                                                 "date": node_config[config]["system_datetime"]})
                except KeyError as err:
                    errors.append("Unable to find value:" + str(err))
    except OSError as err:
        errors.append(err) 

    try: 
        with open(AB_PATH_9, "r", encoding="UTF-8") as rfile:
            lfile = rfile.read()
            temp_list = literal_eval(lfile)
            for item in temp_list:
                try:
                    edge_summary.update({"status": item["status"]})
                except KeyError as err:
                    errors.append("Unable to find value:" + str(err))    
    except OSError as err:
        errors.append(err)


    try:
        with open(AB_PATH_10, "r", encoding="UTF-8") as controllers:
            ctrl_string = controllers.read()
            ctrl_string = ctrl_string.replace("true", "True").replace("false", "False")
            ctrl_list = literal_eval(ctrl_string)
            #will include decimal to ip convertion here at the later stage
    except OSError as err:
        errors.append(err)

  
    try:
        addr = gsearch(AB_PATH_6, "address", "address ", 1)
        mask = gsearch(AB_PATH_6, "netmask", "netmask ", 1)
        gw = gsearch(AB_PATH_6, "gateway", "gateway ", 1)
        edge_summary.update({"mgmt": addr, "netmask": mask, "gateway": gw})
    except Exception as err:
        errors.append(str(err))

    try:
        with open(AB_PATH_1, "r", encoding="UTF-8") as jfile:
            try:
                node_config = json.load(jfile)
            except json.decoder.JSONDecodeError:
                errors.append(AB_PATH_1)
            else:
                try: 
                    for config in node_config:
                        if config == "/api/v1/node/network/name-servers":
                            edge_summary.update({"dns": node_config[config]["name_servers"]})
                except KeyError as err:
                    errors.append("Unable to find value:" + str(err))
    except OSError as err:
        errors.append(err)
    

    try:
        cpus = gsearch(AB_PATH_8, "CPU\(s\)", ":", index=1) 
        cores = gsearch(AB_PATH_8, "Core\(s\)", ":", index=1)
        edge_summary.update({"cpus": cpus.strip(), "cores_per_socket": cores.strip() })
        total_mem = gsearch(AB_PATH_7, "MemTotal", ":", index=1)
        total = int(total_mem.strip("kB")) // KB + 1
        edge_summary.update({"memory(GB)": total})
    except Exception as err:
        errors.append(str(err))


    try: 
        with open(AB_PATH_2, "r", encoding="UTF-8") as jfile:
            try:
                config = json.load(jfile)
            except json.decoder.JSONDecodeError:
                errors.append(AB_PATH_2)
            else:
                #if bare metal edge vm_form_factor attribute won't be present
                try:
                    edge_summary.update({"size": config["vm_form_factor"]})
                except KeyError as err:
                    errors.append("Unable to find value:" + str(err))

                edge_summary.update({"bare_metal": config["is_bare_metal_edge"]})
                edge_summary.update({"cloud_mode": config["public_cloud_mode"]})                      
    except Exception as err:
        errors.append(str(err))

    
    diag_dict = get_diag()
    
    if "core" in diag_dict["passed"]:
        core_dump = False
    else:
        core_dump = True
    
    edge_summary.update({"core_dump": core_dump})
    edge_summary.update(is_configured(get_lbs(), "lb_configued"))
    edge_summary.update(is_configured(get_ipsec_vpn(), "ipsec_configured"))
    edge_summary.update({"tunnels_down": get_tunnels("state") })


    try: 
        with open(AB_PATH_5, "r", encoding="UTF-8") as jfile:
            try:
                config = json.load(jfile)
            except json.decoder.JSONDecodeError:
                errors.append(AB_PATH_5)
            else:
                edge_summary.update({"teps": [], "tunnels": []})
                try:
                    for tep in config:
                        if tep["local-vtep-ip"] not in edge_summary["teps"]:
                            edge_summary["teps"].append(tep["local-vtep-ip"])
                except KeyError as err:
                    errors.append("Unable to find value:" + str(err))
    except Exception as err:
        errors.append(str(err))
    
    edge_summary["errors"] = errors
    return edge_summary


def get_tunnels(option):

    options = ["list", "state"]
    FILE_1 = BASE_PATH + "/edge/tunnel-ports-stat"
    tunnels = []
    tunnel_state = []

    
    with open(FILE_1, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
        except json.decoder.JSONDecodeError:
            ei_log.warn("Unable to obtain tunnel configuration from log bundle. Exception whilst reading /edge/tunnel-ports-stat")
        else:
            try:
                for tep in config:
                    tunnels.append({"local": tep["local-vtep-ip"], "remote": tep["remote-vtep-ip"], "encap": tep["encap"], "state": tep["admin"]})
            except KeyError as err:
                ei_log.warn(err)
    

    if option == options[0]:
        return tunnels
    
    elif option == options[1]:
        for tunnel in tunnels:
            if tunnel["state"] == "down":
                tunnel_state.append("down")   
        if "down" in tunnel_state:
            return True
        else:
            return False
    else:
        raise ValueError("A string of value 'list' or 'state' must be provided as argument")



def is_configured(configured, service):
    srv = {}
    if not configured:
        srv.update({service : False})
    else:
        srv.update({service: True})
    return srv


def get_edge_performance():

    flowcache_config = "/edge/flowcache-config"
    cpu_usage = "/var/run/vmware/edge/cpu_usage.json"
    cpu_dp_stats = "/edge/datapath-cpu-stats"

    edge_perf = {}
    
    try:
        with open(BASE_PATH + cpu_usage, "r", encoding="UTF-8") as jfile:
            try:
                config = json.load(jfile)
                edge_perf.update({"dp_cores": config["dpdk_cpu_cores"], "service_cores": config["non_dpdk_cpu_cores"], "hgt_dp_core": config["highest_cpu_core_usage_dpdk"],
                                     "hgt_service_core": config["highest_cpu_core_usage_non_dpdk"], "avg_dp_core": config["avg_cpu_core_usage_dpdk"],
                                     "avg_service_core": config["avg_cpu_core_usage_non_dpdk"]})
            except json.decoder.JSONDecodeError:
                ei_log.warn("Unable to obtain edge performance data from log bundle. Exception whilst reading:" + cpu_usage)
            except KeyError as err:
                ei_log.warn(str(err))
    except OSError as err:
        ei_log.warn(err)

   
    try:
        with open(BASE_PATH + flowcache_config, "r", encoding="UTF-8") as jfile:
            try:
                config = json.load(jfile)
                edge_perf.update({"flow_cache": config["enabled"]})
            except json.decoder.JSONDecodeError:
                ei_log.warn("Unable to obtain edge performance data from log bundle. Exception whilst reading:" + flowcache_config)
            except KeyError as e:
                ei_log.warn(str(e))
    except OSError as err:
        ei_log.warn(err)

    
    try: 
        with open(BASE_PATH + cpu_dp_stats, "r", encoding="UTF-8") as lfile:
            try:
                temp_list = literal_eval(lfile.read().strip())
            except Exception as err:
                ei_log.warn(str(err))
            else:
                edge_perf.update({"cores" : []})
                for core in temp_list:
                    edge_perf["cores"].append({"core": core["core"], "rx": core["rx"], "tx": core["rx"], "usage": core["usage"]})
    except OSError as err:
        ei_log.warn(err)

    return edge_perf

    
def sort_logical_routers(logical_routers, logical_topology):

    sorted_routers = list()

    for top in logical_topology:
        short_id = top["uuid"].split("*")
        for router in logical_routers:
            if str(short_id[1]) in str(router["uuid"]):
                sorted_routers.append(router)

    return sorted_routers


def get_logical_routers():

    FILE = BASE_PATH + "/edge/logical-routers"

    with open(FILE, "r", encoding='utf-8') as jfile:
        try:
            lr_json = json.load(jfile)
            routers = []
            temp = {}
            top = get_topology()
            ha_configs = get_ha()
            ipv6 = re.compile("f")

            for lr in range(len(lr_json)):

                lr = lr_json[lr]

                if lr["vrf"] != 0:

                    if "peer_vrf" in lr:
                        temp = {"uuid": lr["uuid"], "name": lr["name"], "type": lr["type"], "vrf": lr["vrf"],
                                "ha_config" : "None", "ha_state": "none", "ha_preempt": "none", "uplink": [], "linked": [], "backplane": [], "downlink": []}
                    else:
                        temp = {"uuid": lr["uuid"], "name": lr["name"], "type": lr["type"], "vrf": lr["vrf"],
                                "ha_config" : "None", "ha_state" : "none", "ha_preempt": "none", "uplink": [], "linked": [], "backplane": [], "downlink": []}

                    for ha in ha_configs:
                        
                        f_uuid = convert_uuid(temp["uuid"])

                        try:
                            if f_uuid == ha["uuid"]:
                                temp.update({"ha_config": ha["config"], "ha_state": ha["state"], "ha_preempt": ha["preempt"]})
                        except KeyError as err:
                            print("key error")
                        
                    for port in lr["ports"]:
                        if port["ptype"] == "downlink" or port["ptype"] == "backplane" or port["ptype"] == "uplink" or port["ptype"] == "linked":
                            for ip in port["ipns"]:
                                if not ipv6.match(ip):
                                    temp[port["ptype"]].append(ip)

                    f_uuid = convert_uuid(temp["uuid"])
                    for d in top:
                        if f_uuid in d.values():
                            temp["ws"] = d["ws"]

                    routers.append(temp)
            
            sortd = sort_logical_routers(routers, get_topology())  
            
            return sortd

        except json.decoder.JSONDecodeError:
            print(colours.warning +
                  "Unable to process data from {}".format(FILE) + colours.endc)

def clean_input(line):
    print(line)
    l = line.split(":")
    s = str(l)
    c = s.replace('"', '')
    return s

def convert_uuid(t_uuid):
    f_uuid = t_uuid[0:4] + ".*" + t_uuid[-4:]
    return f_uuid

def get_fw_stats():

    AB_PATH_1 = "/edge/fw-total-stats"
    fw_dict = {}
    fw_list = []
    
    with open(BASE_PATH + AB_PATH_1, "r", encoding="utf-8") as fw_stats:

        fw_stats_str = fw_stats.read()
        fw_stats_str = fw_stats_str.replace("true", "True").replace("false", "False")
        fw_stats_list = literal_eval(fw_stats_str)
        
        for fw_stat in fw_stats_list:

            fw_dict.update({"uuid": fw_stat["uuid"], "name": fw_stat["name"], "type": fw_stat["type"], "connection-count": fw_stat["connection-count"],
                           "tcp_ho_active_max": fw_stat["TCP Half Opened Active/Max"], "udp_active_max": fw_stat["UDP Active/Max"], "icmp_active_max": fw_stat["ICMP Active/Max"],
                           "other_active_max": fw_stat["Other Active/Max"], "nat_active_max": fw_stat["NAT Active/Max"]})
            
            fw_list.append(fw_dict)

        return fw_list  

def get_topology():

    topology = list()

    PATH = BASE_PATH + "/edge/logical_topology"
    with open(PATH, "r", encoding='utf-8') as file:
        for line in file:
            if "T0 " in line or "T1 " in line:
                uuid = re.search("\w{4}\.\*\w{4}", line)
                ws = get_leading_ws(line)
                topology.append({'uuid': uuid.group(), 'ws': ws})

    return topology



def get_ha():

    ha_config = {}
    ha_configs = []
    logical_topology = BASE_PATH + "/edge/logical_topology"
    
    with open(logical_topology, "r", encoding="utf-8") as topology:
        for line in topology:
            
            if "SR" in line:

                clean_line = line.replace("(", "").replace(")", "").replace(",", "").replace("|", "").replace("rank", "").strip().split()

                if "A/S" in clean_line and len(clean_line) == 7:
                    
                    ha_config.update({"uuid": clean_line[2], "config": clean_line[3], "preempt": clean_line[4], "state": clean_line[6]})
                    ha_configs.append(ha_config.copy())

                else:

                    ha_config.update({"uuid": clean_line[2], "config": clean_line[3], "preempt": "NA", "state": clean_line[5]})
                    ha_configs.append(ha_config.copy())
                
        return ha_configs


def get_leading_ws(line_arg):
    line = line_arg.rstrip()
    leading_ws = len(line) - len(line.lstrip())
    return leading_ws

def dec_to_ip(decimal):
    ip = socket.inet_ntoa(struct.pack('!L', decimal))
    return ip


def get_lbs():

    local_lb = []

    PATH = BASE_PATH + "/edge/lb-stats"

    with open(PATH, 'r', encoding='utf-8') as jfile:
        lbs = json.load(jfile)
        for lb in lbs["lbs"]:
            local_lb.append(
                {"LB Name": lb["display_name"], "LB Enabled": lb["enabled"], "LB Size": lb["size"], "LB UUID": lb["uuid"]})
            for vip in lb["virtual_servers"]:

                local_lb.append({"Name": vip["display_name"], "IP": vip["ip_address"], "Port": vip["port"], "Proto": vip["ip_protocol"],
                                 "Type": vip["type"], "Cur Ses": vip["curr_sess"], "Max Ses": vip["max_sess"], "Tot Ses": vip["total_sess"], 
                                 "Req Rate": vip["req_rate"], "Ses Rate": vip["sess_rate"], "UUID": vip["uuid"]})

    return local_lb


def get_ipsec_vpn():

    FILE_1 = BASE_PATH + "/edge/vpn-session"
    ipsec = []
    session = {}
    tunnel = {"uuid": "", "tunnel_status": "", "local_subnet": "", "peer_subnet": "", "tunnel_down_reason": ""}

    try:
        with open(FILE_1, "r", encoding="UTF-8") as vpn_sessions_file:
            try:
                vpn_sessions_str = vpn_sessions_file.read()
                vpn_sessions_str = vpn_sessions_str.replace("true", "True").replace("false", "False")
                vpn_sessions = literal_eval(vpn_sessions_str)
            except Exception as err:
                pass
                #print("No IPSEC configured on Edge.")
            else:
                for vpn_session in vpn_sessions:
                
                    session.update({"uuid": vpn_session["id"], "type": vpn_session["Type"], "status": vpn_session["Session_Status"],  
                                  "local_endpoint_ip": dec_to_ip(vpn_session["Local_Endpoint_Profile"]["Local_Address"]["ipv4"]),
                                   "peer_endpoint_ip": vpn_session["Peer_Endpoint_Profile"]["Peer_Address"],
                                    "session_down_reason": vpn_session["Session_Down_Reason"], "tunnels": []})
                    #print(vpn_session)
                    for policy in vpn_session["Policy"]:
                        tunnel.update({"uuid": policy["id"], "tunnel_status": policy["Tunnel_Status"]})
                        for local in policy["Local"]["IP_Address"]:
                            #print(1)
                            local_ip = dec_to_ip(local["ipv4"]) + "/" + str(local["prefix_length"])
                            tunnel.update({"local_subnet": local_ip})
                        for peer in policy["Peer"]["IP_Address"]:
                            #print(2)
                            peer_ip = dec_to_ip(peer["ipv4"]) + "/" + str(peer["prefix_length"])
                            tunnel.update({"peer_subnet":peer_ip})
                        
                        tunnel.update({"tunnel_down_reason": policy["Tunnel_Down_Reason"]})
                        session["tunnels"].append(tunnel.copy())
                    
                    ipsec.append(session.copy())
        
        return ipsec
 
    except OSError as err:
        print(err)

    
def get_diag():

    FILE_1 = BASE_PATH + "/edge/diagnosis"
    diag = {"passed": [], "failed": [], "warning":[]}

    try:
        with open(FILE_1, "r", encoding="UTF-8") as tfile:

            jfile = json.load(tfile)
            for item in jfile["passed"]:
                diag["passed"].append(item)

            for key, val in jfile["failed"].items():
                diag["failed"].append(val)

            for item in jfile["warning"]:
                diag["warning"].append(item)

    except OSError as err:
        errors.append(str(err))

    return diag

    
def format_list(list):

    for component in list:

        if "vrf" in component:
            ws = component["ws"] 
            ws -= 3
            print("{:{space}} {}".format("", DIV, space = ws))
            for key in component:
                print("{:{space}} {:14}: {}".format("", key, component[key], space = ws))
        else:  
            print(DIV)
            for key in component:
                print("{:18}: {}".format(key, component[key]))


def format_dict(dicts):

    for key, val in dicts.items():

        if key == "interfaces":
            print("{:16}:".format(key))
            for interface in val:
                print("{:>19} {}".format(":", str(interface)))
                 
        elif key == "tunnels":
            print("{:18}:".format(key))
            for tunnel in val:
                print("{:>19} {}".format(":", str(tunnel))) 
        elif key == "cores":
            print("{:18}:".format(key))
            for core in val:
                print("{:>19} {}".format(":", str(core))) 
        else:
            print("{:18}: {}".format(key, val))



def main():
        
    global BUNDLE
    global BASE_PATH

    parser = argparse.ArgumentParser()
    parser.add_argument("edge_bundle", type=str, help="NSX-T Edge Log Bundle")
    parser.add_argument("-s", "--summary", help="returns config summary", action="store_true")
    parser.add_argument("-p", "--performance", help="returns performance info", action="store_true")
    parser.add_argument("-r", "--router", help="returns a list of logical routers", action="store_true")
    parser.add_argument("-l", "--load-balancer", help="returns a list of load balancers", action="store_true")
    parser.add_argument("-f", "--firewall", help="returns connection stats", action="store_true")
    parser.add_argument("-i", "--ipsec", help="returns ipsec configuration", action="store_true")
    parser.add_argument("-d", "--diag", help="returns health check", action="store_true")
    parsed_args = parser.parse_args()
    args = vars(parsed_args)
    BUNDLE = args["edge_bundle"]
    
    try:
        os.chdir(BUNDLE)
        BASE_PATH = os.getcwd()
    except os.error as err:
        print(colours.warning + "Unable to access bundle:" + colours.endc, err)

    if args["summary"]:
        #format_summary(get_edge_summary())
        format_output(get_edge_summary(), "EDGE SUMMARY")
    elif args["performance"]:
        format_dict(get_edge_performance())
    elif args["router"]:
        format_list(get_logical_routers())
    elif args["load_balancer"]:
        format_list(get_lbs())
        #format_output(get_lbs())
    elif args["firewall"]:
        #format_list(get_fw_stats())
        format_fw_output(get_fw_stats())
    elif args["ipsec"]:
        #get_ipsec_vpn()
        format_output(get_ipsec_vpn(), "POLICY BASED VPN")
    elif args["diag"]:
        #format_dict(get_diag())
        format_output(get_diag(), "DIAGNOSTICS")


    """
    try:
        file = tarfile.open(sys.argv[1])
        file.extractall()
        file.close()
    except:
        print(colours.warning + "===> Unable to unpack Edge bundle" + colours.endc)
        exit(1)
    """


if __name__ == "__main__":
    main()

    
