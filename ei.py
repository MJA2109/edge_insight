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
from ast import literal_eval



class colours():
    header = '\033[95m'
    okblue = '\033[94m'
    okgreen = '\033[92m'
    warning = '\033[93m'
    fail = '\033[91m'
    endc = '\033[0m'
    quote = '\033[1;36m'
    gray = '\033[0;37m'


DIV = "-----------------------------------------------"

logging.basicConfig(level=logging.DEBUG, filename="ei.log", filemode="a",
                    format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")


def gsearch(path, re_pattern, filter="", index=0):
    pattern = re.compile(re_pattern)
    for line in open(path):
        if pattern.search(line):
            if filter:
                vals = re.split(filter, line.strip())
                return vals[index]
            else:
                return line.strip("\n")


def get_oldest_timestamp(log):
    match = ""
    var_log = os.listdir(AB_PATH + "/var/log/")
    sys_log_files = []
    oldest_timestamp = "9999-99-99T99:99:99"
    for log_file in var_log:
        if re.match("^syslog", log_file):
            sys_log_files.append(log_file)

    for sys_log in sys_log_files:
        if ".gz" in sys_log:
            with gzip.open(AB_PATH + "/var/log/" + sys_log, "rb") as d_syslog:
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

    FILE_1 = "/node_config.json"
    FILE_2 = "/config/vmware/edge/config.json"
    FILE_5 = "/edge/tunnel-ports-stat"
    FILE_6 = "/etc/network/interfaces"
    FILE_7 = "/proc/meminfo"
    FILE_8 = "/edge/cpu_info"
    KB = 1048576

    errors = []
    edge_summary = {}

    with open(AB_PATH + FILE_1, "r", encoding="UTF-8") as jfile:
        try:
            node_config = json.load(jfile)
            for config in node_config:
                if config == "/api/v1/node":
                    edge_summary.update({"fqdn": node_config[config]["fully_qualified_domain_name"], "uuid": node_config[config]["node_uuid"],
                                         "version": node_config[config]["node_version"], "kernel": node_config[config]["kernel_version"],
                                         "date": node_config[config]["system_datetime"]})
        except json.decoder.JSONDecodeError:
            errors.append(FILE_1)
        except KeyError as e:
            errors.append(str(e))



    with open(AB_PATH + FILE_6, "r", encoding="UTF-8"):
        try:
            addr = gsearch(AB_PATH + FILE_6, "address", "address ", 1)
            mask = gsearch(AB_PATH + FILE_6, "netmask", "netmask ", 1)
            gw = gsearch(AB_PATH + FILE_6, "gateway", "gateway ", 1)
            edge_summary.update({"mgmt": addr, "netmask": mask, "gateway": gw})

        except Exception as e:
            errors.append(str(e))


    with open(AB_PATH + FILE_1, "r", encoding="UTF-8") as jfile:
        try:
            node_config = json.load(jfile)
            for config in node_config:
                if config == "/api/v1/node/network/name-servers":
                    edge_summary.update({"dns": node_config[config]["name_servers"]})
        except json.decoder.JSONDecodeError:
            errors.append(FILE_1)
        except KeyError as e:
            errors.append(str(e))

    with open(AB_PATH + FILE_8, "r", encoding="UTF-8") as tfile:
        cpus = gsearch(AB_PATH + FILE_8, "CPU\(s\)", ":", index=1) 
        cores = gsearch(AB_PATH + FILE_8, "Core\(s\)", ":", index=1)
        edge_summary.update({"cpus": cpus.strip(), "cores_per_socket": cores.strip() })


    with open(AB_PATH + FILE_7, "r", encoding="UTF-8") as tfile:
     
        total_mem = gsearch(AB_PATH + FILE_7, "MemTotal", ":", index=1)
        total = int(total_mem.strip("kB")) // KB + 1

        edge_summary.update({"memory(GB)": total})

        
    with open(AB_PATH + FILE_2, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_summary.update({"cloud_mode": config["public_cloud_mode"]})
            edge_summary.update({"bare_metal": config["is_bare_metal_edge"]})
            edge_summary.update({"size": config["vm_form_factor"]})

        except json.decoder.JSONDecodeError:
            errors.append(FILE_2)
        except KeyError as e:
            errors.append(str(e))


    with open(AB_PATH + FILE_5, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_summary.update({"teps": [], "tunnels": []})
            for tep in config:
                if tep["local-vtep-ip"] not in edge_summary["teps"]:
                    edge_summary["teps"].append(tep["local-vtep-ip"])

                edge_summary["tunnels"].append(
                    {"local": tep["local-vtep-ip"], "remote": tep["remote-vtep-ip"], "encap": tep["encap"], "state": tep["admin"]})

        except json.decoder.JSONDecodeError:
            errors.append(FILE_5)
        except KeyError as e:
            errors.append(str(e))

    edge_summary["errors"] = errors
    return edge_summary


def get_edge_performance():

    FILE_3 = "/edge/flowcache-config"
    FILE_4 = "/var/run/vmware/edge/cpu_usage.json"
    FILE_9 = "/edge/datapath-cpu-stats"

    edge_perf = {}
    
    with open(AB_PATH + FILE_4, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_perf.update({"dp_cores": config["dpdk_cpu_cores"], "service_cores": config["non_dpdk_cpu_cores"], "hgt_dp_core": config["highest_cpu_core_usage_dpdk"],
                                 "hgt_service_core": config["highest_cpu_core_usage_non_dpdk"], "avg_dp_core": config["avg_cpu_core_usage_dpdk"],
                                 "avg_service_core": config["avg_cpu_core_usage_non_dpdk"]})

        except json.decoder.JSONDecodeError:
            errors.append(FILE_4)
        except KeyError as e:
            errors.append(str(e))

    with open(AB_PATH + FILE_3, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_perf.update({"flow_cache": config["enabled"]})

        except json.decoder.JSONDecodeError:
            errors.append(FILE_3)
        except KeyError as e:
            errors.append(str(e))

    
    with open(AB_PATH + FILE_9, "r", encoding="UTF-8") as lfile:
        temp_list = literal_eval(lfile.read().strip())
        edge_perf.update({"cores" : []})
        for core in temp_list:
            edge_perf["cores"].append({"core": core["core"], "rx": core["rx"], "tx": core["rx"], "usage": core["usage"]})
    

    return edge_perf

    


def sort_logical_routers(logical_routers, logical_topology):

    sorted_routers = list()

    for top in logical_topology:
        short_id = top["uuid"].split("*")
        for router in logical_routers:
            if str(short_id[1]) in str(router["UUID"]):
                sorted_routers.append(router)

    return sorted_routers


def get_logical_routers():

    FILE_1 = "/edge/logical-routers"

    with open(AB_PATH + FILE_1, "r", encoding='utf-8') as jfile:
        try:
            lr_json = json.load(jfile)
            routers = list()
            temp = dict()
            ipv6 = re.compile("f")
            top = get_topology()

            for lr in range(len(lr_json)):

                lr = lr_json[lr]

                if lr["vrf"] != 0:
                    if "peer_vrf" in lr:
                        temp = {"UUID": lr["uuid"], "Name": lr["name"], "Type": lr["type"], "VRF": lr["vrf"],
                                "Peer VRF": lr["peer_vrf"], "uplink": [], "linked": [], "backplane": [], "downlink": []}
                    else:
                        temp = {"UUID": lr["uuid"], "Name": lr["name"], "Type": lr["type"], "VRF": lr["vrf"],
                                "Peer VRF": "None", "uplink": [], "linked": [], "backplane": [], "downlink": []}
                    for port in lr["ports"]:
                        if port["ptype"] == "downlink" or port["ptype"] == "backplane" or port["ptype"] == "uplink" or port["ptype"] == "linked":
                            for ip in port["ipns"]:
                                if not ipv6.match(ip):
                                    temp[port["ptype"]].append(ip)

                    t_uuid = temp["UUID"]
                    f_uuid = t_uuid[0:4] + ".*" + t_uuid[-4:]
                    for d in top:
                        if f_uuid in d.values():
                            temp["ws"] = d["ws"]

                    routers.append(temp)

            sortd = sort_logical_routers(routers, get_topology())

            return sortd

        except json.decoder.JSONDecodeError:
            print(colours.warning +
                  "Unable to process data from {}".format(FILE_1) + colours.endc)

def clean_input(line):
    print(line)
    l = line.split(":")
    s = str(l)
    c = s.replace('"', '')
    return s


def get_fw_stats():

    FILE_1 = "/edge/fw-total-stats"
    fw_dict = {}
    fw_list = []
    
    with open(AB_PATH + FILE_1, "r", encoding="utf-8") as lfile:

        temp_list = literal_eval(lfile.read().strip())
        
        for section in temp_list:

            fw_dict.update({"uuid": section["uuid"], "name": section["name"], "type": section["type"], "connection-count": section["connection-count"],
                           "tcp_ho_active_max": section["TCP Half Opened Active/Max"], "udp_active_max": section["UDP Active/Max"], "icmp_active_max": section["ICMP Active/Max"],
                           "other_active_max": section["Other Active/Max"], "nat_active_max": section["NAT Active/Max"]})
            
            fw_list.append(fw_dict)

        return fw_list  

def get_topology():

    topology = list()

    PATH = AB_PATH + "/edge/logical_topology"
    with open(PATH, "r", encoding='utf-8') as file:
        for line in file:
            if "T0 " in line or "T1 " in line:
                uuid = re.search("\w{4}\.\*\w{4}", line)
                ws = get_leading_ws(line)
                topology.append({'uuid': uuid.group(), 'ws': ws})

    return topology


def get_leading_ws(line_arg):
    line = line_arg.rstrip()
    leading_ws = len(line) - len(line.lstrip())
    return leading_ws


def get_lbs():

    local_lb = []

    PATH = AB_PATH + "/edge/lb-stats"

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


def format_list(lists):

    for component in lists:
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
    global AB_PATH

    parser = argparse.ArgumentParser()
    parser.add_argument("edge_bundle", type=str, help="NSX-T Edge Log Bundle")
    parser.add_argument("-s", "--summary", help="returns config summary", action="store_true")
    parser.add_argument("-p", "--performance", help="returns performance info", action="store_true")
    parser.add_argument("-r", "--router", help="returns a list of logical routers", action="store_true")
    parser.add_argument("-l", "--load-balancer", help="returns a list of load balancers", action="store_true")
    parser.add_argument("-f", "--firewall", help="returns connection stats", action="store_true")
    parsed_args = parser.parse_args()
    args = vars(parsed_args)
    BUNDLE = args["edge_bundle"]
    
    try:
        os.chdir(BUNDLE)
        AB_PATH = os.getcwd()
    except os.error as err:
        print(colours.warning + "Unable to access bundle:" + colours.endc, err)

    if args["summary"]:
        format_dict(get_edge_summary())
    elif args["performance"]:
        format_dict(get_edge_performance())
    elif args["router"]:
        format_list(get_logical_routers())
    elif args["load_balancer"]:
        format_list(get_lbs())
    elif args["firewall"]:
        format_list(get_fw_stats())


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

    
