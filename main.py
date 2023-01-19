#!/usr/bin/env python3

import os
import sys
import re
import tarfile
import gzip
import shutil
import json
import logging


class colours():
    header = '\033[95m'
    okblue = '\033[94m'
    okgreen = '\033[92m'
    warning = '\033[93m'
    fail = '\033[91m'
    endc = '\033[0m'
    quote = '\033[1;36m'
    gray = '\033[0;37m'


bug_string = "DEBUG >>>>>>>>>>>>>>>>>>>>>>>>>>>"
bug = colours.fail + bug_string + colours.endc
DIV = "-----------------------------------------------"

logging.basicConfig(level=logging.DEBUG, filename="ei.log", filemode="a",
                    format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")


def gsearch(path, re_pattern, filter="", index=0):
    pattern = re.compile(re_pattern)
    for line in open(path):
        if pattern.search(line):
            if filter:
                vals = re.split(filter, line.strip())
                # DEBUG
                # print(vals)
                return vals[index]
            else:
                # DEBUG
                # print(line)
                return line.strip("\n")


def get_oldest_timestamp(log):
    match = ""
    var_log = os.listdir(AB_PATH + "/var/log/")
    # print(var_log)
    sys_log_files = []
    oldest_timestamp = "9999-99-99T99:99:99"
    for log_file in var_log:
        if re.match("^syslog", log_file):
            sys_log_files.append(log_file)

    # loop over files and get oldest syslog file
    for sys_log in sys_log_files:
        if ".gz" in sys_log:
            with gzip.open(AB_PATH + "/var/log/" + sys_log, "rb") as d_syslog:
                for line in reversed(d_syslog.readlines()):
                    try:
                        match = re.findall(
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}[T][0-9]{2}:[0-9]{2}:[0-9]{2}", line)[0]
                    except:
                        pass

                    # print("debug match" + match)
                    if match and match < oldest_timestamp:
                        oldest_timestamp = match
                        print("DEBUG oldest_timestamp" + oldest_timestamp)
                        break

    return oldest_timestamp


def get_edge_summary():

    FILE_1 = "/node_config.json"
    FILE_2 = "/config/vmware/edge/config.json"
    FILE_3 = "/edge/flowcache-config"
    FILE_4 = "/var/run/vmware/edge/cpu_usage.json"
    FILE_5 = "/edge/tunnel-ports-stat"

    edge_summary = {"errors": []}

    with open(AB_PATH + FILE_1, "r", encoding="UTF-8") as jfile:
        try:
            node_config = json.load(jfile)
            for config in node_config:
                if config == "/api/v1/node":
                    edge_summary.update({"fqdn": node_config[config]["fully_qualified_domain_name"], "uuid": node_config[config]["node_uuid"],
                                         "version": node_config[config]["node_version"], "kernel_version": node_config[config]["kernel_version"],
                                         "date": node_config[config]["system_datetime"]})

                if config == "/api/v1/node/network/interfaces":
                    edge_summary.update({"interfaces": []})
                    for interface in node_config[config]["results"]:
                        edge_summary["interfaces"].append({"interface": interface["interface_id"], "admin_status": interface["admin_status"],
                                                           "link_status": interface["link_status"], "ip_addresses": interface["ip_addresses"]})
                if config == "/api/v1/node/network/name-servers":
                    edge_summary.update(
                        {"dns": node_config[config]["name_servers"]})

        except json.decoder.JSONDecodeError:
            edge_summary["errors"].append(FILE_1)

    with open(AB_PATH + FILE_2, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_summary.update({"cloud_mode": config["public_cloud_mode"]})
            edge_summary.update({"bare_metal": config["is_bare_metal_edge"]})
            edge_summary.update({"size": config["vm_form_factor"]})

        except json.decoder.JSONDecodeError:
            edge_summary["errors"].append(FILE_2)

    with open(AB_PATH + FILE_3, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_summary.update({"flow_cache": config["enabled"]})

        except json.decoder.JSONDecodeError:
            edge_summary["errors"].append(FILE_3)

    with open(AB_PATH + FILE_4, "r", encoding="UTF-8") as jfile:
        try:
            config = json.load(jfile)
            edge_summary.update({"dp_cores": config["dpdk_cpu_cores"], "service_cores": config["non_dpdk_cpu_cores"], "highest_dp_core_usage": config["highest_cpu_core_usage_dpdk"],
                                 "highest_service_core_usage": config["highest_cpu_core_usage_non_dpdk"], "avg_dp_core_usage": config["avg_cpu_core_usage_dpdk"],
                                 "avg_service_core_usage": config["avg_cpu_core_usage_non_dpdk"]})

        except json.decoder.JSONDecodeError:
            edge_summary["errors"].append(FILE_4)

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
            edge_summary["errors"].append(FILE_5)

    print(json.dumps(edge_summary, indent=4))


def sort_logical_routers(debug, logical_routers, logical_topology):

    sorted_routers = list()

    for top in logical_topology:
        short_id = top["uuid"].split("*")
        for router in logical_routers:
            if str(short_id[1]) in str(router["UUID"]):
                sorted_routers.append(router)

    if debug:
        print(sorted_routers)
        print(type(sorted_routers))

    return sorted_routers


def get_logical_routers(debug):

    FILE_1 = "/edge/logical-routers"

    with open(AB_PATH + FILE_1, "r", encoding='utf-8') as jfile:
        try:
            lr_json = json.load(jfile)
            routers = list()
            temp = dict()
            ipv6 = re.compile("f")
            top = get_topology(False)

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
                    if debug:
                        print(routers)
                        print(type(routers))

                    return routers

        except json.decoder.JSONDecodeError:
            print(colours.warning +
                  "Unable to process data from {}".format(FILE_1) + colours.endc)


def get_topology(debug):

    topology = list()

    PATH = AB_PATH + "/edge/logical_topology"
    with open(PATH, "r", encoding='utf-8') as file:
        for line in file:
            if "T0 " in line or "T1 " in line:
                uuid = re.search("\w{4}\.\*\w{4}", line)
                ws = get_leading_ws(line)
                topology.append({'uuid': uuid.group(), 'ws': ws})

    if debug:
        print(topology)
        print(type(lb))

    return topology


def get_leading_ws(line_arg):
    line = line_arg.rstrip()
    leading_ws = len(line) - len(line.lstrip())
    return leading_ws


def get_lbs(debug):

    local_lb = []

    PATH = AB_PATH + "/edge/lb-stats"

    with open(PATH, 'r', encoding='utf-8') as jfile:
        lbs = json.load(jfile)
        for lb in lbs["lbs"]:
            local_lb.append(
                {"LB Name": lb["display_name"], "LB Enabled": lb["enabled"], "LB Size": lb["size"], "LB UUID": lb["uuid"]})
            for vip in lb["virtual_servers"]:

                local_lb.append({"Name": vip["display_name"], "IP": vip["ip_address"], "Port": vip["port"], "Proto": vip["ip_protocol"],
                                 "Type": vip["type"], "Cur Ses": vip["curr_sess"], "Max Ses": vip["max_sess"], "Tot Ses": vip["total_sess"], "UUID": vip["uuid"]})
    if debug:
        print(local_lb)
        print(type(local_lb))

    return local_lb


def format(lists):

    for component in lists:
        print(DIV)
        for key in component:
            print("{:10}: {}".format(key, component[key]))


if __name__ == "__main__":

    if len(sys.argv) == 3 and "nsx_edge" in sys.argv[1]:

        """
        try:
            file = tarfile.open(sys.argv[1])
            file.extractall()
            file.close()
        except:
            print(colours.warning + "===> Unable to unpack Edge bundle" + colours.endc)
            exit(1)
        """
        BUNDLE = sys.argv[1].strip(".tgz")
        os.chdir(BUNDLE)
        AB_PATH = os.getcwd()

        if sys.argv[2] == "-r" or sys.argv[2] == "--router":
            r = get_logical_routers(False)
            t = get_topology(False)
            rt = sort_logical_routers(False, r, t)
            format(rt)
        elif sys.argv[2] == "-lb" or sys.argv[2] == "--loadbalancer":
            lbs = get_lbs(debug=False)
            format(lbs)
        elif sys.argv[2] == "-s" or sys.argv[2] == "--summary":
            get_edge_summary()
        elif sys.argv[2] == "-h" or sys.argv[2] == "--help":
            print("")
            print("Options:")
            print("Returns a summary of Edge configuration: -s | --summary")
            print("Returns a list of Logical Routers: -r | --routers")
            print(
                "Returns a list of Load Balacers and assocated Virtual Servers: -b | --load-balancers")
            print("")

        else:
            print(colours.warning +
                  "===> Invalid flag. Please try again..." + colours.endc)

    else:
        # print(sys.argv)
        print(colours.warning +
              "===> Please provide log bundle and flag as arguments." + colours.endc)
