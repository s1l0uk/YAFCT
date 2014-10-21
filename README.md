YAFCT - Yet Another Foreman CLI Tool!
=====================================

Introduction
------------

> YAFCT is a single file script to help administrators automate the creation of resources as well as being a swiss army knife for Foreman administrators to help make their lives a bit easier. It makes use of the Python Foreman Module to interact with the Foreman API to action requests around the orchestration of Foreman in your infrastructure. This tool was created as a more versatile version of the hammer as it will allow you to create your own templates to use Foreman for your architecture.

TLDR;
----
```
usage: main [-h] [-l LOGFILE] [-q] [-s] [-v] -m MODE -f FARM -n NAME [-N NUMBER] [-F FUNCTION] [-e EXTRA] [-c CONFIG]
[-p] [-A] [-T]
optional arguments:
-h, --help                        show this help message and exit
-l LOGFILE, --logfile LOGFILE     log to file (default: log to stdout)
-q, --quiet                       decrease the verbosity
-s, --silent                      only log warnings
-v, --verbose                     raise the verbosity
-m MODE, --mode MODE              What to make Foreman do. Excepted Values:
                                  ['index','create','delete','update','runlist']
-f FARM, --farm FARM              Which Foreman instance to connect to
-n NAME, --name NAME              Name of the Instance to inspect or build or the path of runlist when using the runlist 
                                  function
-N NUMBER, --number NUMBER        Number of instances to build - required to create instances
-F FUNCTION, --function FUNCTION  Used to instruct the script what to create/update/index/delete through Foreman  
                                  ['Architecture', 'Audit', 'LDAP', 'Bookmark','Parameter', 'ComputeResource', 
                                  'ConfigTemplate', 'Environment', 'HostGroup','Host', 'LookupKey','Media', 'Model', 
                                  'OperatingSystem', 'PartitionTable','PuppetClass', 'Role', 'Setting', 'Proxy', 
                                  'Subnet','Template', 'UserGroup', 'User' ]
-e EXTRA, --extra EXTRA           Extra detail supplied in JSON to a function - normally used for create mechanisms
-c CONFIG, --config CONFIG        Change the Configuration file location
-p, --pretty                      Allow Pretty printing when indexing
-A, --auto                        Changes script to not prompt for guidance - USE WITH CAUTION!
-T, --tokenize                    Action to decide if the runlist needs to be de-tokenized - reqires a definitions.py 
                                  file in the same dir.
```

Assumptions
-----------
- You have set up the Foreman and it is ready to work
- You have access to the Foreman logs to find the required fields to create the json templates for your architecture
- You have a standard naming convention 
- You don't intend to have more than 999 of a given fleet of instances (You can have more - but you lose some automation)

Setup
-----
**install**

> First, install all the required modules with:

```
$ pip install -r requirements.txt
```

**config file**

> Fill in the YAML configuration to give the script the need parameters to connect to your vSphere API

```
---
foreman:
  DATACENTRE-1: #Farm Name
    protocol: "https"
    hostname: "10.220.103.17"
    hostport: "443"
    username: 'SuperAdminAccount'
    password: "" #LeaveBlank to be prompted 
  DATACENTRE-A: #Farm Name
    protocol: "https"
    hostname: "10.220.103.17"
    hostport: "443"
    username: 'SuperAdminAccount'
    password: "" #LeaveBlank to be prompted 
```

> At this point you can use a lot of the functionality of the script, but to get more control and repeatability of your environment you can configure the definitions file and runlists.

Runlists
--------

> Runlists are a powerful way of creating your infrastructure in an ordered way. It can allow you to build an environment with a single command and provides updates while you watch the infrastructure build.
> Using this functionality with tokens allows you to create repeatable environments that can be different depending on how the tokens are placed. You can even use tokens to populate other tokens to allow the operator to keep convention while maintaining a single set of scripts and runlists.

> For Example:

```
---
- "name": "@DC_LOWER@-mgmt-fmn-001.@DOMAIN@"
  "type": "Proxy"
  "method": "create"
  "url": "https://@DC_LOWER@-foreman-proxy:8443"
- "name": "@DC_LOWER@-X-environment"
  "type": "ComputeResource"
  "method": "create"
  "url": "1.1.1.1"
  "password": "SuperSecurePassword-WOOHOO!"
  "provider": "Vmware"
- "name": "@DOMAIN@"
  "type": "Domain"
  "method": "create"
  "fullname": "@DOMAIN@ - Management"
  "dns_id": LookUp(Proxy:Main)
- "name": "@DC_LOWER@"
  "type": "Subnet"
  "method": "create"
  "mask": "0.0.0.0"
  "network": "1.1.1.1"
  "gateway": "1.1.1.254"
  "dns_primary": "@DNS_MASTER_IP@"
  "dns_secondary": "@DNS_SLAVE_IP@"
  "from": "1.1.1.1"
  "to": "255.255.255.254"
  "domain_ids": [ LookUp(Domain:@DC_UPPER@-DOMAIN) ]
  "tftp_id": LookUp(Proxy:Main)
  "dhcp_id": LookUp(Proxy:Main)
  "dns_id": LookUp(Proxy:Main)
- "name": "base"
  "type": "PuppetClass"
  "method": "create"
- "name": "VMware Virtual Platform"
  "type": "HardwareModel"
  "method": "create"
```

#LookUp(ITEM:REGEX)

> Because the Foreman API works on ID numbers instead of Names and the search can be a bit flakey, a method was introduced to look up the IDs for the operator to aid in automation. This allows the users to specify the category of element and a regex to match on which will replace the LookUp declaration with the resulting ID number.

Definitions and Tokenisation
----------------------------

> The Definitions file is where the script gets it's information to tokenise the scripts, runlists and data supplied to creations commands.
> It is a python Dictionary and it pretty easy to understand. Just add your Key and Value to this file and the add your Key to any script or runlist to allow it be detokenised.

```
#!/usr/bin/env python

#If a token requires another token then please specify it before the needed token

def definitions(self):
    definitions = {
      '@DATA_CENTRE-A_FRIENDLY_MESSAGE@' : "Hello World!",
      '@DATA_CENTRE-1_FRIENDLY_MESSAGE@' : "World Hello!",
      '@FRIENDLY_MESSAGE@'               : "@@CU_UPPER@_FRIENDLY_MESSAGE@",
      '@DC_LOWER@'                       : str(self.params.farm).lower(),
      '@DC_UPPER@'                       : self.params.farm,
    }
```

Modes
-----

> The script was designed to be a single file script but has grown many functions. To run the script you need to select a mode to run in.

**extra data**

> Some commands require extra data to be supplied to the script in a json format - These vary depending on which function of the script is being used. It is heavily used during creation statements through the Foreman and to see the exact variables needed to complete the function you can check [here]. 

> The API documentation should tell you when fields are needed to complete the function and required to be added via a JSON string provided to the application on the commandline ...Or inside a file with a $(cat file) add to the command to cheat:

```
-e $(cat ./file/with/json.json)
```

**index**

> The Index function allows the operator to index a variety of the different elements that the Foreman manages for us. The following elements are what the Foreman Tool can currently index the following:

- Architecture
- Audit
- LDAP
- Bookmark
- Parameter
- ComputeResource
- ConfigTemplate
- Environment
- HostGroup
- Host
- LookupKey
- Media
- Model
- OperatingSystem
- PartitionTable
- PuppetClass
- Role
- Setting
- Proxy
- Subnet
- Template
- UserGroup
- User

> For Example:

```
./foremanTool.py -f <Instance of Foreman to use> -m index -n <Keyword to search for or "all"> -F <what you would like to Index> [-p to display the results in a table as opposed to JSON] 
```

**create**

> The Foreman Tool was built with the original idea of being able to create elements of the Foreman through its API. The script is capable of creating all the resources mentioned above that it can index on. 

> For Example:

```
./foremanTool.py -f <Instance of Foreman to work on> -m create -F <Element you want to create> -n <Name of instance to create> -e "<Needed JSON string>" [-i number of instances to create] [-T to detokenise] [-A for automatic mode]
```

**delete**

> As well as creating the Foreman Tool can also delete resources from itself with the delete mode set and a regex to match on the resouces that it will try and delete.

> For Example:

```
./foremanTool.py -f <Instance of Foreman to use> -m delete -n <Keyword to search for or "all"> -F <what you would like to Delete> 
```

**update**

> On top of creating and deleting elements through the Foreman, you can also update the element to give it new values. The command follows the same sort of syntax used for creating. The only notable difference is when you change the name of an element you use the flag of new_name in the json strings.

> For Example:

```
./foremanTool.py -f <Instance of Foreman to work on> -m update -F <Element you want to update e.g. Host> -n <Name of instance to update> -e "<Needed JSON string>" [-T to detokenise]
```

**runlist**

> The runlist option gives the operator the feature to create runlists which the Foreman can build in an ordered fashion which helps in the automation of the creation of environments or start ups. 

> For Example:

```
./foremanTool.py -f <Name of Foreman Instance to use> -m runlist -n <Path to run list> [-T to detokenise] [-A for automatic mode]
```

Templates
---------

> The difference between this tool and others such as Hammer is that this tool attempts to give the operator more flexibility in what they want to do with the Foreman and the interactions with the API. The template method allows the user to create there only templates which integrates with their own infrastructure. This section should help new users to uncover what they need to provide in the JSON templates and strings to allow them to build.

**Creation**

> By default templates should live in the template folder and be referenced in the JSON (or YAML when using runlists) to instruct the script which template it should be using to detokenise before requesting the creation/update from the API. To make things simpler when populating these templates on the fly we use the @ symbol to surround the key as the value.

> For example:

```
"network": "@network@"
```

> So when the script sees this it will populate network to the value of network from the JSON data passed with the -e (extra) flag.

> When creating new templates to see how your Infrastructure will work with this script. It is wise to create a set of instances through the GUI. This will allow you to use 1 of the 2 options below to create a template that works for your infrastructure set (Please feel free to contribute these back to the repo as this will allow others who had these troubles to see a mock up of how it should look)

*Dev Tools - Browser*

> During a "Manual Build" using the GUI of the Foreman it is possible to see what the Foreman is sending on to main Foreman build class by checking your Browsers developers tools.

> In Chrome you can click: view > Developer > Developer Tools

> This will provide you with a panel at the bottom of the screen to see what is being sent and received back. After you action a manual request to build, you will see a JSON entry containing all the fields needed to build on your infrastructure. If you copy this and present it in a template with the appropriate tokens which will be overwritten by the extra data when you issue the command, you will be able to build on your infrastructure.

*Logs*

> If you are lucky enough to have root access to the Foreman Instance, you can scan the the logs with:

```
$ tail -F /var/log/foreman/production.log
```

> With this open in a terminal window you can action a manual request to build against the Foreman and snatch the sent JSON from the Foreman logs and adapt to create a template.


**Use**

> As previously mentioned the use of the template is specified by template key in the JSON/YAML data provided to the script. The Value of the template key should reflect a relative path to the template from the script.

License
----

> TBC - Apache?? MIT??


[here]:http://pythonhosted.org/python-foreman/client.html