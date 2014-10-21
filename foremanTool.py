#!/usr/bin/env python
#If not standard should be in requirements.txt
import yaml
import foreman
import json
import getpass
import pprint
import sys
import re
from prettytable import PrettyTable
from foreman.client import Foreman
from cli.log import LoggingApp
import logging

sys.dont_write_bytecode = True

__author__ = ['Paul.Hardy']

class ForemanTool(LoggingApp):

    def get_connection(self, config):
        try:
            connection = Foreman(str(config["protocol"]) + "://" + str(config["hostname"]) + ":" + str(config["hostport"]), (str(config["username"]), str(config["password"])))
        except Exception as e:
            quit(e)
        return connection

    def get_config(self):
        try:
            config = yaml.load(open(self.params.config))['foreman'][self.params.farm]
        except IOError as e:
            self.log.error(e)
            quit("No Configuration file")
        except KeyError as e:
            self.log.debug(e)
            quit("No such farm to use - please check your configuration file")
        if config['password'] == "":
            config['password'] = str(getpass.getpass())
        return config

    def pretty_host(self, host, title):
        returned = []
        for key in title:
                try:
                    prop = host[key]
                    if type(prop) == str:
                        prop = prop.replace(' ','\n')
                    if type(prop) == dict:
                        prop = [str((k,v)).replace(',','\n') for k,v in prop.items()]
                        prop = (str(w) for w in prop)
                        prop = '\n'.join(prop)
                    if type(prop) == list:
                        prop = (str(w) for w in prop)
                        prop = '\n'.join(prop)
                    returned.append(prop)
                except KeyError:
                    returned.append("")
        return returned

    def delete_instances(self,conn):
        hosts = self.index_instances(conn)
        if len(hosts) == 0:
            quit("There are no instances that match what you are looking for.. quitting!")
        for host in hosts:
            host_id = host['host']['id']
            if self.params.auto != True:
                resp = raw_input("\nWould you like to Delete " + host['host']['name']  + "?: [y/n]")
                if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                    conn.destroy(host_id)
                else:
                    self.log.warn("Not operating on " + str(host_id) + " - " + host['host']['name'] )
                    continue
            else:
                conn.destroy(host_id)

    def destroy(self,conn,i):
        func = self.params.function
        if func == "Architecture":
            self.log.info(conn.show_architectures(i))
            resp = conn.destroy_architectures(i)
        elif func == "LDAP":
            self.log.info(conn.show_auth_source_ldaps(i))
            resp = conn.destroy_auth_source_ldaps(i)
        elif func == "Bookmark":
            self.log.info(conn.show_bookmarks(i))
            resp = conn.destroy_bookmarks(i)
        elif func == "Parameter":
            self.log.info(conn.show_common_parameters(i))
            resp = conn.destroy_common_parameters(i)
        elif func == "ComputeResource":
            self.log.info(conn.show_compute_resources(i))
            resp = conn.destroy_compute_resources(i)
        elif func == "Template":
            self.log.info(conn.show_templates(i))
            resp = conn.destroy_config_templates(i)
        elif func == "Domain":
            self.log.info(conn.show_domains(i))
            resp = conn.destroy_domains(i)
        elif func == "Environment":
            self.log.info(conn.show_environments(i))
            resp = conn.destroy_environments(i)
        elif func == "HostGroup":
            self.log.info(conn.show_hostgroups(i))
            resp = conn.destroy_hostgroups(i)
        elif func == "Host": 
            self.log.info(conn.show_hosts(i))
            resp = conn.destroy_hosts(i)
        elif func == "LookupKey":
            self.log.info(conn.show_lookup_keys(i))
            resp = conn.destroy_lookup_keys(i)
        elif func == "Media":
            self.log.info(conn.show_media(i))
            resp = conn.destroy_media(i)
        elif func == "Model":
            self.log.info(conn.show_models(i))
            resp = conn.destroy_models(i)
        elif func == "OperatingSystem":
            self.log.info(conn.show_operatingsystems(i))
            resp = conn.destroy_operatingsystems(i)
        elif func == "PartitionTable":
            self.log.info(conn.show_ptables(i))
            resp = conn.destroy_ptables(i)
        elif func == "PuppetClass":
            self.log.info(conn.show_puppetclasses(i))
            resp = conn.destroy_puppetclasses(i)
        elif func == "Report":
            self.log.info(conn.show_reports(i))
            resp = conn.destroy_reports(i)
        elif func == "Role":
            self.log.info(conn.show_roles(i))
            resp = conn.destroy_roles(i)
        elif func == "Proxy":
            self.log.info(conn.show_smart_proxies(i))
            resp = conn.destroy_smart_proxies(i)
        elif func == "Subnet":
            self.log.info(conn.show_subnets(i))
            resp = conn.destroy_subnets(i)
        elif func == "UserGroup":
            self.log.info(conn.show_usergroups(i))
            resp = conn.destroy_usergroups(i)
        elif func == "User":
            self.log.info(conn.show_users(i))
            resp = conn.destroy_users(i)
        else:
            quit("This element is not available yet - please try again!")
        self.log.debug(resp)
        return resp

    def update(self,conn):
        func = self.params.function
        i = self.index_instances(conn)
        if len(i) == 0:
            quit("Could not find what you wanted to update - Please try again")
        if len(i) > 1:
            for item in i:
                if self.params.auto != True:
                    resp = raw_input("\nWould you like to Delete " + host['host']['name']  + "?: [y/n]")
                    if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                        self.updater(conn,item['id'],func)
                    else:
                        self.log.warn("Not operating on " + str(host_id) + " - " + host['host']['name'] )
                    continue
                else:
                    self.updater(conn,item['id'],func)
        else:
            self.updater(conn,i['id'],func)

    def updater(self,conn,i,func):
        if func == "Architecture":
            self.log.info(conn.show_architectures(i))
            resp = self.update_architecture(conn,i)
        elif func == "LDAP":
            self.log.info(conn.show_auth_source_ldaps(i))
            resp = self.update_auth_source_ldaps(conn,i)
        elif func == "Bookmark":
            self.log.info(conn.show_bookmarks(i))
            resp = self.update_bookmark(conn,i)
        elif func == "Parameter":
            self.log.info(conn.show_common_parameters(i))
            resp = self.update_common_parameter(conn,i)
        elif func == "ComputeResource":
            self.log.info(conn.show_compute_resources(i))
            resp = self.update_compute_resource(conn,i)
        elif func == "Template":
            self.log.info(conn.show_templates(i))
            resp = self.update_config_template(conn,i)
        elif func == "Domain":
            self.log.info(conn.show_domains(i))
            resp = self.update_domain(conn,i)
        elif func == "Environment":
            self.log.info(conn.show_environments(i))
            resp = self.update_env(conn,i)
        elif func == "HostGroup":
            self.log.info(conn.show_hostgroups(i))
            resp = self.update_hostgroup(conn,i)
        elif func == "Host":
            self.log.info(conn.show_hosts(i))
            resp = conn.update_host(conn,i)
        elif func == "LookupKey":
            self.log.info(conn.show_lookup_keys(i))
            resp = self.update_lookup_key(conn,i)
        elif func == "Media":
            self.log.info(conn.show_media(i))
            resp = self.update_media(conn,i)
        elif func == "Model":
            self.log.info(conn.show_models(i))
            resp = self.update_model(conn,i)
        elif func == "OperatingSystem":
            self.log.info(conn.show_operatingsystems(i))
            resp = self.update_os(conn,i)
        elif func == "PartitionTable":
            self.log.info(conn.show_ptables(i))
            resp = self.update_ptable(conn,i)
        elif func == "PuppetClass":
            self.log.info(conn.show_puppetclasses(i))
            resp = self.update_puppetclass(conn,i)
        elif func == "Report":
            self.log.info(conn.show_reports(i))
            resp = self.update_report(conn,i)
        elif func == "Role":
            self.log.info(conn.show_roles(i))
            resp = self.update_role(conn,i)
        elif func == "Proxy":
            self.log.info(conn.show_smart_proxies(i))
            resp = self.update_smart_proxy(conn,i)
        elif func == "Subnet":
            self.log.info(conn.show_subnets(i))
            resp = self.update_subnet(conn,i)
        elif func == "UserGroup":
            self.log.info(conn.show_usergroups(i))
            resp = self.update_usergroup(conn,i)
        elif func == "User":
            self.log.info(conn.show_users(i))
            resp = self.update_user(conn,i)
        else:
            quit("This element is not available yet - please try again!")
        return resp

    def index_instances(self, conn):
        hosts = []
        returned = []
        page = 1
        try:
            function = self.params.function
        except Exception as e:
            self.log.debug(e)
            quit("This option requires the function flag (-F) please try again")
        if self.params.name == "all":
            search = None
        else:
            search = self.params.name
        while True:
            if function == "Host":
                resp = conn.index_hosts(page=page)
            elif function == "Architecture":
                resp = conn.index_architectures(page=page)
            elif function == "Audit":
                resp = conn.index_audits(page=page)
            elif function == "LDAP":
                resp = conn.index_auth_source_ldaps(page=page)
            elif function == "Bookmark":
                resp = conn.index_bookmarks(page=page) 
            elif function == "Parameter":
                resp = conn.index_common_parameters(page=page)
            elif function == "ComputeResource":
                resp = conn.index_compute_resources(page=page)
            elif function == "ConfigTemplate":
                resp = conn.index_config_templates(page=page)
            elif function == "Dashboard":
                resp = conn.index_dashboard(search=search)
            elif function == "Domain":
                resp = conn.index_domains(page=page)
            elif function == "Environment":
                resp = conn.index_environments(page=page)
            elif function == "Value":
                resp = conn.index_fact_values(page=page)
            elif function == "Home":
                resp = conn.index_home()
            elif function == "HostGroup":
                resp = conn.index_hostgroups(page=page)
            elif function == "LookupKey":
                resp = conn.index_lookup_keys(page=page)
            elif function == "Media": 
                resp = conn.index_media(page=page)
            elif function == "Model":
                resp = conn.index_models(page=page)
            elif function == "OperatingSystem":
                resp = conn.index_operatingsystems(page=page)
            elif function == "PartitionTable":
                resp = conn.index_ptables(page=page)
            elif function == "PuppetClass":
                resp = conn.index_puppetclasses(page=page)
            elif function == "Report":
                resp = conn.index_reports(page=page)
            elif function == "Role":
                resp = conn.index_roles(page=page)
            elif function == "Setting":
                resp = conn.index_settings(page=page)
            elif function == "Proxy":
                resp = conn.index_smart_proxies(page=page)
            elif function == "Subnet":
                resp = conn.index_subnets(page=page)
            elif function == "Template":
                resp = conn.index_template_kinds(page=page)
            elif function == "UserGroup":
                resp = conn.index_usergroups(page=page)
            elif function == "User":
                resp = conn.index_users(page=page)
            else:
                quit("This function does not exists yet")
            if len(resp) < 1:
                break
            page  += 1
            if function == "PuppetClass":
                temp = []
                for w in resp:
                    temp.append(resp[w][0]['puppetclass'])
                resp = temp
            hosts += resp
        if search != None:
            filtered_hosts = []
            for host in hosts:
                if search in str(host):
                    filtered_hosts.append(host)
            hosts = filtered_hosts
        if len(hosts) == 0:
            self.log.error("Search returned no matching elements")
            if self.params.mode == "index":
                quit()
        title = []
        host_list = []
        if self.params.pretty and self.params.mode == "index":
            title.append("id")
            for h in hosts[0]:
                if function == "PuppetClass":
                    if h != "id":
                        title.append(str(h))
                else:
                    for key in hosts[0][h]:
                        if key != "id":
                            title.append(str(key))
            table = PrettyTable(title)
            table.padding_width = 1
            for host in hosts:
                formatted_hosts = {}
                if function == "PuppetClass":
                    formatted_hosts['id'] = host['id']
                    for key in sorted(host):
                        if key != "id":
                            formatted_hosts[str(key)] = host[key]
                    host_list.append(formatted_hosts)
                else:
                    for h in host:
                        formatted_hosts['id'] = host[h]['id']
                        for key in sorted(host[h]):
                            if key != "id":
                                formatted_hosts[str(key)] = host[h][key]
                        host_list.append(formatted_hosts)
        else:
            for host in hosts:
                host_list.append(host)
        for host in host_list:
            if self.params.mode == "index":
                if self.params.pretty:
                    table.add_row(self.pretty_host(host,title))
                else:
                    self.log.error(host)
            returned.append(host)
        if self.params.pretty and self.params.mode == "index":
            print table.get_string(sortby="id")
        return returned

    def create_host(self,conn):
        basename = self.params.name
        if basename[-1].isdigit() == True:
            zfill = 1
            while basename[-zfill].isdigit() == True:
                zfill += 1
            zfill -= 1
            index = int(basename[-zfill:])
        else:
            index = len(self.index_instances(conn))
            zfill = 3
        data = self.params.extra
        if 'ip' in self.params.extra:
            data['ip'] = self.params.extra['ip']
        if 'mac' in self.params.extra:
            data['mac'] = self.params.extra['mac']
        for i in range(index, index + self.params.number):
            data['name'] = basename + '-'  + str(index + 1).zfill(zfill)
            try:
                info = conn.create_hosts(data)
                self.log.info(info)
            except foreman.client.ForemanException as e:
                self.log.debug(e)
                print json.loads(e.res.text)['host']['errors']['base'][0]
                if "Could not start VMX: Out of memory" in json.loads(e.res.text)['host']['errors']['base'][0]:
                    self.log.info("VMX Error from vSphere - will retry!")
                    self.create_host(conn)
            index += 1

    def todo(self,conn):
        print dir(conn)

    def detokenize_scripts(self,script,read=False):
        try:
            from definitions import definitions
        except Exception as e:
            self.log.debug(e)
            self.log.error("No Definitions file found! Script will not be detokenized!")
            return open(script, "r").read()
        config = definitions(self)
        regex= re.compile('@.*@')
        index = 0
        self.log.debug(script)
        try:
            if read == False:
                with open(script, "r") as f:
                    script = f.read()
                    while regex.search(script) != None:
                        for i, j in config.iteritems():
                            script = script.replace(i,j)
                        index += 1
                        self.log.info(index)
                        if index > 5:
                            self.log.debug(script)
                            break
            else:
                script = str(script)
                while regex.search(script) != None:
                    for i, j in config.iteritems():
                        script = script.replace(i,j)
                    index += 1
                    self.log.info(index)
                    if index > 5:
                        self.log.debug(script)
                        break
            return script
        except IOError as e:
            self.log.debug(e)
            quit('Could not find script - please check and try again')

    def deploy_runlist(self,conn):
        try:
            if self.params.tokenize == True:
                runlist = yaml.load(self.detokenize_scripts(self.params.name))
            else:
                runlist = yaml.load(open(self.params.name))
        except yaml.parser.ParserError as e:
            self.log.error(e)
            quit("Your YAML file appears to be corrupt - Please check and try again")
        except yaml.scanner.ScannerError as e:
            self.log.error(e)
            quit("Your YAML file appears to be corrupt - Please check and try again")
        except IOError as e:
            self.log.error(e)
            quit('Cannot find the runlist - please check and try again!')
        except Exception as e:
            self.log.error(e)
            quit('Something weird happened...')
        for element in runlist:
            try:
                cat = element['type']
                method = element['method']
                self.params.function = element['type']
                self.params.name = element['name']
            except KeyError:
                self.log.error("No type/name provided with element - Unsure what to do - Skipping!")
                continue
            if method == "create":
                self.log.error(self.create(conn,element))
            elif method == "update":
                self.log.error(self.update(conn))
            elif method == "delete":
                self.log.error(self.delete_instances(conn))
            else:
                self.log.error("Method " + method + " has not been created yet!")
                continue

    def compile_host_template(self,element):
        try:
            host_template = open(element['template']).read()
        except IOError as e:
            self.log.debug(e)
            quit("Cannot find the template!")
        except KeyError as e:
            self.log.debug(e)
            quit("template is not declared")
        except Exception as e:
            self.log.debug(e)
            quit("There has been a problem...")
        if 'number' in element:
            self.params.number = int(element['number'])
        for key in element:
            host_template = host_template.replace("@" + str(key) + "@", str(element[key]))
        host_template = json.loads(host_template)
        return dict(host_template)

    def create(self,conn,element):
        func = self.params.function
        rstN = self.params.name
        if func == "Host":
            element = self.compile_host_template(element)
        for key in sorted(element.iterkeys()):
            if type(element[key]) == unicode:
                if element[key].startswith('LookUp('):
                    self.log.debug("Looking up - " + str(key))
                    element[key] = self.lookup_element(conn,element[key])
            elif type(element[key]) == list:
                replacement = []
                for i in element[key]:
                    if i.startswith('LookUp('):
                        self.log.debug("Looking up - " + str(key))
                        replacement.append(self.lookup_element(conn,i))
                element[key] = replacement
        self.log.debug("Element now looks like:")
        self.log.debug(element)
        self.params.function = func
        self.params.name = rstN
        self.params.extra = element
        if func == "Architecture":
            self.log.info("Architecture")
            resp = self.create_architecture(conn)
        elif func == "LDAP":
            self.log.info("LDAP")
            resp = self.create_auth_source_ldaps(conn)
        elif func == "Bookmark":
            self.log.info("Bookmark")
            resp = self.create_bookmark(conn)
        elif func == "Parameter":
            self.log.info("Parameter")
            resp = self.create_common_parameter(conn)
        elif func == "ComputeResource":
            self.log.info("ComputeResource")
            resp = self.create_compute_resource(conn)
        elif func == "Template":
            self.log.info("Template")
            resp = self.create_config_template(conn)
        elif func == "Domain":
            self.log.info("Domain")
            resp = self.create_domain(conn)
        elif func == "Environment":
            self.log.info("Environment")
            resp = self.create_env(conn)
        elif func == "HostGroup":
            self.log.info("HostGroup")
            resp = self.create_hostgroup(conn)
        elif func == "Host":
            self.log.info("Host")
            resp = self.create_host(conn)
        elif func == "LookupKey":
            self.log.info("LookupKey")
            resp = self.create_lookup_key(conn)
        elif func == "Media":
            self.log.info("Media")
            resp = self.create_media(conn)
        elif func == "Model":
            self.log.info("Model")
            resp = self.create_model(conn)
        elif func == "OperatingSystem":
            self.log.info("OperatingSystem")
            resp = self.create_os(conn)
        elif func == "PartitionTable":
            self.log.info("PartitionTable")
            resp = self.create_ptable(conn)
        elif func == "PuppetClass":
            self.log.info("PuppetClass")
            resp = self.create_puppetclass(conn)
        elif func == "Report":
            self.log.info("Report")
            resp = self.create_report(conn)
        elif func == "Role":
            self.log.info("Role")
            resp = self.create_role(conn)
        elif func == "Proxy":
            self.log.info()
            resp = self.create_smart_proxy(conn)
        elif func == "Subnet":
            self.log.info("Subnet")
            resp = self.create_subnet(conn)
        elif func == "UserGroup":
            self.log.info("UserGroup")
            resp = self.create_usergroup(conn)
        elif func == "User":
            self.log.info("User")
            resp = self.create_user(conn)
        else:
            self.log.error("I don't know what to do with " + element['name'] + " of type " + cat)
            resp = "Error"
        return resp

    def create_smart_proxy(self,conn):
        smartProxy = {}
        try:
            smartProxy['name'] = self.params.name
            smartProxy['url'] = self.params.extra['url']
        except KeyError:
            quit("Please provide a JSON string with the url in place")
        try:
            proxy = conn.create_smart_proxies(smartProxy)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return proxy

    def create_compute_resource(self,conn):
        computeResource = {}
        try:
            computeResource['name'] = self.params.name
            computeResource['password'] = self.params.extra['password']
            computeResource['url'] = self.params.extra['url']
            computeResource['description'] = self.params.extra['description']
            computeResource['user'] = self.params.extra['user']
            computeResource['provider'] = self.params.extra['provider']
        except KeyError:
            quit("Please deliver a json string with - password, url, description, user and provider values ")
        if 'server' in self.params.extra:
            ComputeResource['server'] = self.params.extra['server']
        if 'uuid' in self.params.extra:
            ComputeResource['uuid'] = self.params.extra['uuid']
        if 'tenant' in self.params.extra:
            ComputeResource['tenant'] = self.params.extra['tenant']
        if 'region' in self.params.extra:
            ComputeResource['region'] = self.params.extra['region']
        try:
            resource = conn.create_compute_resources(computeResource)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return resource

    def create_subnet(self,conn):
        subnet = {}
        try:
            subnet['name'] = self.params.name
            subnet['mask'] = self.params.extra['subnetmask']
            subnet['network'] = self.params.extra['network']

        except KeyError:
            quit("Please enter a valid JSON string with name, subnetmask, network")
        if 'vlanid' in self.params.extra:
            subnet['vlanid'] = self.params.extra['vlanid']
        if 'dns_primary' in self.params.extra:
            subnet['dns_primary'] = self.params.extra['dns_primary']
        if 'gateway' in self.params.extra:
            subnet['gateway'] = self.params.extra['gateway']
        if 'to' in self.params.extra:
            subnet['to'] = self.params.extra['to']
        if 'dns_id' in self.params.extra:
            subnet['dns_id'] = self.params.extra['dns_id']
        if 'dhcp_id' in self.params.extra:
            subnet['dhcp_id'] = self.params.extra['dhcp_id']
        if 'from' in self.params.extra:
            subnet['from'] = self.params.extra['from']
        if 'dns_secondary' in self.params.extra:
            subnet['dns_secondary'] = self.params.extra['dns_secondary']
        if 'domain_ids' in self.params.extra:
            subnet['domain_ids'] = self.params.extra['domain_ids']
        if 'tftp_id' in self.params.extra:
            subnet['tftp_id'] = self.params.extra['tftp_id']
        try:
            sub = conn.create_subnets(subnet)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return sub

    def create_domain(self,conn):
        domain = {}
        try:
            domain['name'] = self.params.name
            domain['dns_id'] = self.params.extra['dns_id']
            domain['fullname'] = self.params.extra['fullname']
        except KeyError:
            quit("Please enter a valid JSON string with dns_id and description")
        if 'domain_parameters_attributes' in self.params.extra:
            domain['domain_parameters_attributes'] = self.params.extra['domain_parameters_attributes']
        try:
            dom = conn.create_domains(domain)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return dom

    def create_hostgroup(self,conn):
        hostgroup = {}
        try:
            hostgroup['name'] = self.params.name
        except KeyError:
            quit('Please provide a valid JSON string that has name')
        if 'operatingsystem_id' in self.params.extra:
            hostgroup['operatingsystem_id'] = self.params.extra['operatingsystem_id']
        if 'puppet_ca_proxy_id' in self.params.extra:
            hostgroup['puppet_ca_proxy_id'] = self.params.extra['puppet_ca_proxy_id']
        if 'ptable_id' in self.params.extra:
            hostgroup['ptable_id'] = self.params.extra['ptable_id']
        if 'environment_id' in self.params.extra:
            hostgroup['environment_id'] = self.params.extra['environment_id']
        if 'medium_id' in self.params.extra:
            hostgroup['medium_id'] = self.params.extra['medium_id']
        if 'subnet_id' in self.params.extra:
            hostgroup['subnet_id'] = self.params.extra['subnet_id']
        if 'architecture_id' in self.params.extra:
            hostgroup['architecture_id'] = self.params.extra['architecture_id']
        if 'puppet_proxy_id' in self.params.extra:
            hostgroup['puppet_proxy_id'] = self.params.extra['puppet_proxy_id']
        if 'puppetclass_ids' in self.params.extra:
            hostgroup['puppetclass_ids'] = self.params.extra['puppetclass_ids']
        if 'root_pass' in self.params.extra:
            hostgroup['root_pass'] = self.params.extra['root_pass']
        if 'domain_id' in self.params.extra:
            hostgroup['domain_id'] = self.params.extra['domain_id']
        try:
            hostg = conn.create_hostgroups(hostgroup)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return hostg

    def create_puppetclass(self,conn):
        puppetclass = {}
        try:
            puppetclass['name'] = self.params.name
        except KeyError:
            quit('Please provide a valid JSON string')
        try:
            pclass = conn.create_puppetclasses(puppetclass)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return pclass

    def create_hardwaremodel(self,conn):
        hardware = {}
        try:
            hardware['name'] = self.params.name
        except KeyError:
            quit('please provide a valid JSON string')
        if 'hardware_model' in self.params.extra:
            hardware['hardware_model'] = self.params.extra['hardware_model']
        if 'vendor_class' in self.params.extra:
            hardware['vendor_class'] = self.params.extra['vendor_class']
        if 'info' in self.params.extra:
            hardware['info'] = self.params.extra['info']
        try:
            model = conn.create_models(hardware)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return model

    def create_os(self,conn):
        os = {}
        try:
            os['name'] = self.params.name
            os['minor'] = self.params.extra['minor']
            os['major'] = self.params.extra['major']
        except KeyError:
            quit('Please provide a valid JSON string')
        try:
            operatingsys = conn.create_operatingsystems(os)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return operatingsys

    def create_env(self,conn):
        env = {}
        try:
            env['name'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create environment")
        try:
            environment = conn.create_environments(env)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return environment

    def create_install_media(self,conn):
        install = {}
        try:
            install['name'] = self.params.name
            install['path'] = self.params.extra['path']
            install['os_family'] = self.params.extra['os_family']
        except KeyError:
            quit('Please provide a Valid JSON string')
        try:
            installation = conn.create_media(install)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return installation

    def create_provision_template(self,conn):
        ptemp = {}
        try:
            ptemp['name'] = self.params.name
            ptemp['template'] = open(str(self.params.extra['layout'])).read()
            ptemp['operatingsystem_ids'] = self.params.extra['operatingsystem_ids']
            ptemp['snippet'] = self.params.extra['snippet']
        except KeyError as e:
            self.log.debug(e)
            quit('Please provide a Valid JSON string')
        except IOError as e:
            self.log.debug(e)
            quit("Could not find partition layout")
        if 'audit_comment' in self.params.extra:
            ptemp['audit_comment'] = self.params.extra['audit_comment']
        if 'template_kind_id' in self.params.extra:
            ptemp['template_kind_id'] = self.params.extra['template_kind_id']
        if 'template_combinations_attributes' in self.params.extra:
            ptemp['template_combinations_attributes'] = self.params.extra['template_combinations_attributes']
        try:
            ptemp = conn.create_config_templates(ptable)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return ptemp

    def create_architecture(self,conn):
        architecture = {}
        try:
            architecture['name'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create " + str(self.params.function))
        if 'operatingsystem_ids' in self.params.extra:
            architecture['operatingsystem_ids'] = self.params.extra['operatingsystem_ids']
        try:
            architecture = conn.create_architectures(architecture)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return architecture

    def create_ldap(self,conn):
        auth_source_ldap = {}
        try:
            auth_source_ldap['attr_login'] = self.params.extra['attr_login']
            auth_source_ldap['name'] = self.params.name
            auth_source_ldap['attr_mail'] = self.params.extra['attr_mail']
            auth_source_ldap['account_password'] = self.params.extra['account_password']
            auth_source_ldap['attr_firstname'] = self.params.extra['arttr_firstname']
            auth_source_ldap['host'] = self.params.extra['host']
            auth_source_ldap['attr_lastname'] = self.params.extra['attr_lastname']
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create " + str(self.params.function))
        if 'tls' in self.params.extra:
            auth_source_ldap['tls'] = self.params.extra['tls']
        if 'port' in self.params.extra:
            auth_source_ldap['port'] = self.params.extra['port']
        if 'account' in self.params.extra:
            auth_source_ldap['account'] = self.params.extra['account']
        if 'onthefly_register' in self.params.extra:
            auth_source_ldap['onthefly_register'] = self.params.extra['onthefly_register']
        if 'base_dn' in self.params.extra:
            auth_source_ldap['base_dn'] = self.params.extra['base_dn']
        try:
           auth_source_ldap = conn.create_auth_source_ldaps(auth_source_ldap)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return auth_source_ldap

    def create_paramter(self,conn):
        common_parameter = {}
        try:
            common_parameter['value'] = self.params.extra['value']
            common_parameter['name'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create " + str(self.params.function))
        try:
             common_paramter = conn.create_common_paramters(common_paramter)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return common_parameter

    def create_key(self,conn):
        lookup_key = {} 
        try:
            lookup_key['key'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create " + str(self.params.function))
        if 'default_value' in self.params.extra:
            lookup_key['default_value'] = self.params.extra['default_value']
        if 'description' in self.params.extra:
            lookup_key['description'] = self.params.extra['description']
        if 'path' in self.params.extra:
            lookup_key['path'] = self.params.extra['path']
        if 'puppetclass_id' in self.params.extra:
            lookup_key['puppetclass_id'] = self.params.extra['puppetclass_id']
        if 'lookup_values_count' in self.params.extra:
            lookup_key['lookup_values_count'] = self.params.extra['lookup_values_count']
        try:
           lookup_key = conn.create_lookup_keys(lookup_key)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return lookup_key

    def create_partitiontable(self,conn):
        ptable = {}
        try:
            ptable['layout'] = self.params.extra['layout']
            ptable['name'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create " + str(self.params.function))
        if 'os_family' in self.params.extra:
            ptable['os_family'] = self.params.extra['os_family']
        try:
           ptable  = conn.create_ptables(ptable)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem creating your " + str(self.params.function))
        return ptable

    def create_role(self,conn):
        role = {}
        try:
            role['name'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create environment")
        try:
            role = conn.create_roles(role)
        except Exception as e:
            self.log.error("Not enough detail provided with element - Unsure what to do - Skipping!")
            return
        return role

    def create_usergroup(self,conn):
        usergroup = {}
        try:
            usergroup['name'] = self.params.name
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create environment")
        try:
            usergroup = conn.create_usergroups(usergroup)
        except Exception as e:
            self.log.error("Not enough detail provided with element - Unsure what to do - Skipping!")
            return
        return usergroup

    def create_user(self,conn):
        user = {}
        try:
            user['login'] = self.params.name
            user['password'] = self.params.extra['password']
            user['mail'] = self.params.extra['mail']
            user['auth_source_id'] = self.params.extra['auth_source_id']
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot create environment")
        if 'firstname' in self.params.extra:
            user['firstname'] = self.params.extra['firstname']
        if 'admin' in self.params.extra:
            user['admin'] = self.params.extra['admin']
        if 'lastname' in self.params.extra:
            user['lastname'] = self.params.extra['lastname']
        try:
            user = conn.create_users(user)
        except Exception as e:
            self.log.error("Not enough detail provided with element - Unsure what to do - Skipping!")
            return
        return user

    def update_host(self,conn,i):
        host = {}
        self.log.info(conn.show_hosts(i))
        try:
            host['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update " + str(self.params.function))
        if 'new_name' in self.params.extra:
            host['name']  = self.params.extra['new_name']
        if 'architecture_id' in self.params.extra:
            host['architecture_id'] = self.params.extra['architecture_id']
        if 'model_id' in self.params.extra:
            host['model_id'] = self.params.extra['model_id']
        if 'puppet_proxy_id' in self.params.extra:
            host['puppet_proxy_id'] = self.params.extra['puppet_proxy_id']
        if 'environment_id' in self.params.extra:
            host['environment_id'] = self.params.extra['environment_id']
        if 'domain_id' in self.params.extra:
            host['domain_id'] = self.params.extra['domain_id']
        if 'mac' in self.params.extra:
            host['mac'] = self.params.extra['mac']
        if 'ip' in self.params.extra:
            host['ip'] = self.params.extra['ip']
        if 'operatingsystem_id' in self.params.extra:
            host['operatingsystem_id'] = self.params.extra['operatingsystem_id']
        if 'ptable_id' in self.params.extra:
            host['ptable_id'] = self.params.extra['ptable_id']
        if 'hostgroup_id' in self.params.extra:
            host['hostgroup_id'] = self.params.extra['hostgroup']
        if 'sp_subnet_id' in self.params.extra:
            host['sp_subnet_id']= self.params.extra['sp_subnet_id']
        if 'subnet_id' in self.params.extra:
            host['subnet_id'] = self.params.extra['subnet_id']
        if 'owner_id' in self.params.extra:
            host['owner_id']= self.params.extra['owner_id']
        if 'host_parameters_attributes' in self.params.extra:
            host['host_parameters_attributes'] = self.params.extra['host_parameters_attributes']
        if 'puppet_ca_proxy_id' in self.params.extra:
            host['puppet_ca_proxy_id'] = self.params.extra['puppet_ca_proxy_id']
        if 'image_id' in self.params.extra:
            host['image_id'] = self.params.extra['image_id']
        if 'medium_id' in self.params.extra:
            host['medium_id'] = self.params.extra['medium_id']
        try:
            host = conn.update_hosts(host)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return host

    def update_smart_proxy(self,conn,i):
        smartProxy = {}
        try:
            smartProxy['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Please provide a JSON string")
            if 'new_name' in self.params.extra:
                smartProxy['name'] = self.params.extra['new_name']
            if 'url' in self.params.extra:
                smartProxy['url'] = self.params.extra['url']
        try:
            proxy = conn.update_smart_proxies(smartProxy)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return proxy

    def update_compute_resource(self,conn,i):
        computeResource = {}
        try:
            computeResource['id'] = i
        except KeyError:
            quit("Please deliver a json string with - password, url, description, user and provider values ")
        if 'new_name' in self.params.extra:
            computeResource['name'] = self.params.extra['new_name']
        if 'password' in self.params.extra:
            computeResource['password'] = self.params.extra['password']
        if 'url' in self.params.extra:
            computeResource['url'] = self.params.extra['url']
        if 'description' in self.params.extra:
            computeResource['description'] = self.params.extra['description']
        if 'user' in self.params.extra:
            computeResource['user'] = self.params.extra['user']
        if 'provider' in self.params.extra:
            computeResource['provider'] = self.params.extra['provider']
        if 'server' in self.params.extra:
            ComputeResource['server'] = self.params.extra['server']
        if 'uuid' in self.params.extra:
            ComputeResource['uuid'] = self.params.extra['uuid']
        if 'tenant' in self.params.extra:
            ComputeResource['tenant'] = self.params.extra['tenant']
        if 'region' in self.params.extra:
            ComputeResource['region'] = self.params.extra['region']
        try:
            resource = conn.update_compute_resources(computeResource)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return resource

    def update_subnet(self,conn,i):
        subnet = {}
        try:
            subnet['id'] = i
        except KeyError:
            quit("Please enter a valid JSON string with name, subnetmask, network")
        if 'new_name' in self.params.extra:
            subnet['name'] = self.params.extra['new_name']
        if 'mask' in self.params.extra:
            subnet['mask'] = self.params.extra['subnetmask']
        if 'network' in self.params.extra:
            subnet['network'] = self.params.extra['network']
        if 'vlanid' in self.params.extra:
            subnet['vlanid'] = self.params.extra['vlanid']
        if 'dns_primary' in self.params.extra:
            subnet['dns_primary'] = self.params.extra['dns_primary']
        if 'gateway' in self.params.extra:
            subnet['gateway'] = self.params.extra['gateway']
        if 'to' in self.params.extra:
            subnet['to'] = self.params.extra['to']
        if 'dns_id' in self.params.extra:
            subnet['dns_id'] = self.params.extra['dns_id']
        if 'dhcp_id' in self.params.extra:
            subnet['dhcp_id'] = self.params.extra['dhcp_id']
        if 'from' in self.params.extra:
            subnet['from'] = self.params.extra['from']
        if 'dns_secondary' in self.params.extra:
            subnet['dns_secondary'] = self.params.extra['dns_secondary']
        if 'domain_ids' in self.params.extra:
            subnet['domain_ids'] = self.params.extra['domain_ids']
        if 'tftp_id' in self.params.extra:
            subnet['tftp_id'] = self.params.extra['tftp_id']
        try:
            sub = conn.update_subnets(subnet)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return sub

    def update_domain(self,conn,i):
        domain = {}
        try:
            domain['id'] = i
        except KeyError:
            quit("Please enter a valid JSON string with dns_id and description")
        if 'new_name' in self.params.extra:
            domain['name'] = self.params.extra['new_name']
        if 'dns_id' in self.params.extra:
            domain['dns_id'] = self.params.extra['dns_id']
        if 'fullname' in self.params.extra:
            domain['fullname'] = self.params.extra['fullname']
        if 'domain_parameters_attributes' in self.params.extra:
            domain['domain_parameters_attributes'] = self.params.extra['domain_parameters_attributes']
        try:
            dom = conn.update_domains(domain)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return dom

    def update_hostgroup(self,conn,i):
        hostgroup = {}
        try:
            hostgroup['id'] = i
        except KeyError:
            quit('Please provide a valid JSON string that has name')
        if 'new_name' in self.params.extra:
            hostgroup['name'] = self.params.extra['new_name']
        if 'operatingsystem_id' in self.params.extra:
            hostgroup['operatingsystem_id'] = self.params.extra['operatingsystem_id']
        if 'puppet_ca_proxy_id' in self.params.extra:
            hostgroup['puppet_ca_proxy_id'] = self.params.extra['puppet_ca_proxy_id']
        if 'ptable_id' in self.params.extra:
            hostgroup['ptable_id'] = self.params.extra['ptable_id']
        if 'environment_id' in self.params.extra:
            hostgroup['environment_id'] = self.params.extra['environment_id']
        if 'medium_id' in self.params.extra:
            hostgroup['medium_id'] = self.params.extra['medium_id']
        if 'subnet_id' in self.params.extra:
            hostgroup['subnet_id'] = self.params.extra['subnet_id']
        if 'architecture_id' in self.params.extra:
            hostgroup['architecture_id'] = self.params.extra['architecture_id']
        if 'puppet_proxy_id' in self.params.extra:
            hostgroup['puppet_proxy_id'] = self.params.extra['puppet_proxy_id']
        if 'puppetclass_ids' in self.params.extra:
            hostgroup['puppetclass_ids'] = self.params.extra['puppetclass_ids']
        if 'root_pass' in self.params.extra:
            hostgroup['root_pass'] = self.params.extra['root_pass']
        if 'domain_id' in self.params.extra:
            hostgroup['domain_id'] = self.params.extra['domain_id']
        try:
            hostgroup = conn.update_hostgroups(hostgroup)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return hostgroup

    def update_puppetclass(self,conn,i):
        puppetclass = {}
        try:
            puppetclass['id'] = i
        except KeyError:
            quit('Please provide a valid JSON string')
        if 'new_name' in self.params.extra:
            puppetclass['name'] = self.params.extra['new_name']
        try:
            pclass = conn.update_puppetclasses(puppetclass)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return pclass

    def update_hardwaremodel(self,conn,i):
        hardware = {}
        try:
            hardware['id'] = i
        except KeyError:
            quit('please provide a valid JSON string')
        if 'new_name' in self.params.extra:
            hardware['name'] = self.params.extra['new_name']
        if 'hardware_model' in self.params.extra:
            hardware['hardware_model'] = self.params.extra['hardware_model']
        if 'vendor_class' in self.params.extra:
            hardware['vendor_class'] = self.params.extra['vendor_class']
        if 'info' in self.params.extra:
            hardware['info'] = self.params.extra['info']
        try:
            model = conn.update_models(hardware)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return model

    def update_os(self,conn,i):
        os = {}
        try:
            os['id'] = i
        except KeyError:
            quit('Please provide a valid JSON string')
        if 'new_name' in self.params.extra:
            os['name'] = self.params.extra['new_name']
        if 'minor' in self.params.extra:
            os['minor'] = self.params.extra['minor']
        if 'major' in self.params.extra:
            os['major'] = self.params.extra['major']
        try:
            operatingsys = conn.update_operatingsystems(os)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return operatingsys

    def update_env(self,conn,i):
        env = {}
        try:
            env['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update environment")
        if 'new_name' in self.params.extra:
            env['name'] = self.params.extra['new_name']
        try:
            environment = conn.update_environments(env)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return environment

    def update_install_media(self,conn,i):
        install = {}
        try:
            install['id'] = i
        except KeyError:
            quit('Please provide a Valid JSON string')
        if 'new_name' in self.params.extra:
            install['name'] = self.params.extra['new_name']
        if 'path' in self.params.extra:
            install['path'] = self.params.extra['path']
        if 'os_family' in self.params.extra:
            install['os_family'] = self.params.extra['os_family']
        try:
            installation = conn.update_media(install)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return installation

    def update_provision_template(self,conn,i):
        ptemp = {}
        try:
            ptemp['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit('Please provide a Valid JSON string')
            try:
                ptemp['template'] = open(str(self.params.extra['layout'])).read()
            except IOError as e:
                self.log.debug(e)
                quit("Could not find partition layout")
        if 'new_name' in self.params.extra:
            ptemp['name'] = self.params.extra['new_name']
        if 'template' in self.params.extra:
            ptemp['template'] = self.params.extra['template']
        if 'operatingsystem_ids' in self.params.extra:
            ptemp['operatingsystem_ids'] = self.params.extra['operatingsystem_ids']
        if 'snippet' in self.params.extra:
            ptemp['snippet'] = self.params.extra['snippet']
        if 'audit_comment' in self.params.extra:
            ptemp['audit_comment'] = self.params.extra['audit_comment']
        if 'template_kind_id' in self.params.extra:
            ptemp['template_kind_id'] = self.params.extra['template_kind_id']
        if 'template_combinations_attributes' in self.params.extra:
            ptemp['template_combinations_attributes'] = self.params.extra['template_combinations_attributes']
        try:
            ptemp = conn.update_config_templates(ptable)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return ptemp

    def update_architecture(self,conn,i):
        architecture = {}
        try:
            architecture['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update " + str(self.params.function))
        if 'new_name' in self.params.extra:
            architecture['name'] = self.params.extra['new_name']
        if 'operatingsystem_ids' in self.params.extra:
            architecture['operatingsystem_ids'] = self.params.extra['operatingsystem_ids']
        try:
            architecture = conn.update_architectures(architecture)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return architecture

    def update_ldap(self,conn,i):
        auth_source_ldap = {}
        try:
            auth_source_ldap['name'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update " + str(self.params.function))
        if 'new_name' in self.params.extra:
            auth_source_ldap['name'] = self.params.extra['new_name']
        if 'attr_login' in self.params.extra:
            auth_source_ldap['attr_login'] = self.params.extra['attr_login']
        if 'attr_mail' in self.params.extra:
            auth_source_ldap['attr_mail'] = self.params.extra['attr_mail']
        if 'account_password' in self.params.extra:
            auth_source_ldap['account_password'] = self.params.extra['account_password']
        if 'attr_firstname' in self.params.extra:
            auth_source_ldap['attr_firstname'] = self.params.extra['arttr_firstname']
        if 'host' in self.params.extra:
            auth_source_ldap['host'] = self.params.extra['host']
        if 'attr_lastname' in self.params.extra:
            auth_source_ldap['attr_lastname'] = self.params.extra['attr_lastname']
        if 'tls' in self.params.extra:
            auth_source_ldap['tls'] = self.params.extra['tls']
        if 'port' in self.params.extra:
            auth_source_ldap['port'] = self.params.extra['port']
        if 'account' in self.params.extra:
            auth_source_ldap['account'] = self.params.extra['account']
        if 'onthefly_register' in self.params.extra:
            auth_source_ldap['onthefly_register'] = self.params.extra['onthefly_register']
        if 'base_dn' in self.params.extra:
            auth_source_ldap['base_dn'] = self.params.extra['base_dn']
        try:
           auth_source_ldap = conn.update_auth_source_ldaps(auth_source_ldap)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return auth_source_ldap

    def update_paramter(self,conn,i):
        common_parameter = {}
        try:
            common_parameter['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update " + str(self.params.function))
        if 'value' in self.params.extra:
            common_parameter['value'] = self.params.extra['value']
        if 'new_name' in self.params.extra:
            common_parameter['name'] = self.params.extra["new_name"]
        try:
             common_paramter = conn.update_common_paramters(common_paramter)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return common_parameter

    def update_key(self,conn,i):
        lookup_key = {} 
        try:
            lookup_key['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update " + str(self.params.function))
        if 'new_key' in self.params.extra:
            lookup_key['key'] = self.params.extra['new_key']
        if 'default_value' in self.params.extra:
            lookup_key['default_value'] = self.params.extra['default_value']
        if 'description' in self.params.extra:
            lookup_key['description'] = self.params.extra['description']
        if 'path' in self.params.extra:
            lookup_key['path'] = self.params.extra['path']
        if 'puppetclass_id' in self.params.extra:
            lookup_key['puppetclass_id'] = self.params.extra['puppetclass_id']
        if 'lookup_values_count' in self.params.extra:
            lookup_key['lookup_values_count'] = self.params.extra['lookup_values_count']
        try:
           lookup_key = conn.update_lookup_keys(lookup_key)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return lookup_key

    def update_partitiontable(self,conn,i):
        ptable = {}
        try:
            ptable['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update " + str(self.params.function))
        if 'layout' in self.params.extra:
            ptable['layout'] = self.params.extra['layout']
        if 'new_name' in self.params.extra:
            ptable['name'] = self.params.extra['new_name']
        if 'os_family' in self.params.extra:
            ptable['os_family'] = self.params.extra['os_family']
        try:
           ptable  = conn.update_ptables(ptable)
        except Exception as e:
            self.log.error(e)
            quit("There was a problem updating your " + str(self.params.function))
        return ptable

    def update_role(self,conn,i):
        role = {}
        try:
            role['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update environment")
        if 'new_name' in self.params.extra:
            role['name'] = self.params.extra['new_name']
        try:
            role = conn.update_roles(role)
        except Exception as e:
            self.log.error("Not enough detail provided with element - Unsure what to do - Skipping!")
            return
        return role

    def update_usergroup(self,conn,i):
        usergroup = {}
        try:
            usergroup['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update environment")
        if 'new_name' in self.params.extra:
            usergroup['name'] = self.params.extra['new_name']
        try:
            usergroup = conn.update_usergroups(usergroup)
        except Exception as e:
            self.log.error("Not enough detail provided with element - Unsure what to do - Skipping!")
            return
        return usergroup

    def update_user(self,conn,i):
        user = {}
        try:
            user['id'] = i
        except KeyError as e:
            self.log.debug(e)
            quit("Cannot update environment")
        if 'new_login' in self.params.extra:
            user['login'] = self.params.extra['new_name']
        if 'password' in self.params.exta:
            user['password'] = self.params.extra['password']
        if 'mail' in self.params.extra:
            user['mail'] = self.params.extra['mail']
        if 'auth_source_id' in self.params.extra:
            user['auth_source_id'] = self.params.extra['auth_source_id']
        if 'firstname' in self.params.extra:
            user['firstname'] = self.params.extra['firstname']
        if 'admin' in self.params.extra:
            user['admin'] = self.params.extra['admin']
        if 'lastname' in self.params.extra:
            user['lastname'] = self.params.extra['lastname']
        try:
            user = conn.update_users(user)
        except Exception as e:
            self.log.error("Not enough detail provided with element - Unsure what to do - Skipping!")
            return
        return user

    def lookup_element(self,conn,element):
        self.params.name = element[element.find("(")+1:element.find(")")].split(':')[1]
        self.params.function = element[element.find("(")+1:element.find(")")].split(':')[0]
        self.log.debug("Looking up type: " + str(self.params.function) + " and searching for: " + self.params.name)
        elements = self.index_instances(conn)
        if len(elements) == 0:
            self.log.error("Could not Look up " + str(element))
            returned = ""
        elif len(elements) > 1:
            self.log.error("Found more than one matching your specification... returning most likely")
            returned = elements[0]
        else:
            returned = elements[0]
        if "id" not in returned:
            returned = returned[returned.keys()[0]]
        return int(returned['id'])

#===========================MAIN===========================#

    def main(self):
        self.log.debug("Starting")
        mode = self.params.mode
        if self.params.function == None and self.params.mode != "runlist":
            quit("Please provide a Function (-F) to filter what you would like to interact with")
        self.log.debug("Mode Selected: " + mode)
        if self.params.mode == "create" or self.params.mode == "update":
            if self.params.extra == None:
                quit("Please provide extra information to the script (-e) in a JSON string")
        self.log.debug("Getting Config")
        config = self.get_config()
        self.log.debug("Config: " + str(config['hostname'] + " as " + str(config['username'])))
        self.log.debug("Connecting to Foreman")
        connection = self.get_connection(config)
        self.log.debug("Connection Test...")
        if not connection:
            message = "No connection could be established - aborting!"
            self.log.debug(message)
            quit(message)
        self.log.debug("...Passed!")
        if mode == "index":
            self.index_instances(connection)
        elif mode == "todo":
            self.todo(connection)
        elif mode == "update":
            if self.params.tokenize == True:
                self.params.extra = self.detokenize_scripts(self.params.extra,True)
            self.update(connection)
        elif mode == "delete":
            self.delete_instances(connection)
        elif mode == "runlist":
            self.deploy_runlist(connection)
        elif mode == "create":
            if self.params.tokenize == True:
                self.params.extra = self.detokenize_scripts(self.params.extra,True)
            self.create(connection,json.loads(str(self.params.extra)))
        else:
            message = "Please choose a Valid Mode! - You have selected %s" % mode
            self.log.debug(message)
            quit(message)
        self.log.debug("Finished")

#===========================MAGIC==============================#

if __name__ == "__main__":
    foremanTool=ForemanTool()

    foremanTool.add_param("-m", "--mode", help="What to make foreman do. Excepted Values: ['index','create','delete','update','runlist']", default=None, required=True, action="store")
    foremanTool.add_param("-f", "--farm", help="Which foreman instance to connect to", default=None, required=True, action="store")
    foremanTool.add_param("-n", "--name", help="Name of the Instance to inspect or build or the path of runlist when using the runlist function", default=None, required=True, action="store")
    foremanTool.add_param("-N", "--number", help="Number of instances to build - required to create instances", default=1, required=False, type=int, action="store")
    foremanTool.add_param("-F", "--function", help="Used to instruct the script what to create/update/index/delete through foreman ['Architecture', 'Audit', 'LDAP', 'Bookmark', 'Parameter', 'ComputeResource', 'ConfigTemplate', Environment', 'HostGroup', 'Host', 'LookupKey', 'Media', 'Model', 'OperatingSystem', 'PartitionTable', 'PuppetClass', 'Role', 'Setting', 'Proxy', 'Subnet', 'Template', 'UserGroup', 'User']", default=None, required=False, action="store")
    foremanTool.add_param("-e", "--extra", help="Extra detail supplied in JSON to a function - normally used for create mechanisms", default=None, required=False, action="store")
    foremanTool.add_param("-c", "--config", help="Change the Configuration file location", default="./config/config.yaml", required=False, action="store")
    foremanTool.add_param("-p", "--pretty", help="Allow Pretty printing when indexing", default=False, required=False, action="store_true")
    foremanTool.add_param("-A", "--auto", help="Changes script to not prompt for guidance - USE WITH CAUTION!", default=False, required=False, action="store_true")
    foremanTool.add_param("-T", "--tokenize", help="Action to decide if the runlist needs to be de-tokenized - reqires a definitions.py file in the same dir", default=None, required=False, action="store_true")

    foremanTool.run()
