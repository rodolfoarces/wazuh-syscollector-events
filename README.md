# Reporting scripts

To obtain index data from syscheck and syscollector, these helper scripts can help

You will need to download the files and place them in a directory in the Wauh Manager (Master or Worker)

```
curl -LO https://github.com/rodolfoarces/syscollector-report/blob/dev/src/syscollector-report.py && chmod 700 ./syscollector-report.py
curl -LO  https://github.com/rodolfoarces/syscollector-report/blob/dev/src/fim-report.py && chmod 700 ./fim-report.py
curl -L https://github.com/rodolfoarces/syscollector-report/blob/dev/src/example.syscollector-report.conf -o ./syscollector-report.conf
```

The `/var/ossec/wodles/syscollector-report.conf` is to be adjusted acordigly to the Wazuh Server API user.

To execute the Syscollector helper

```
/var/ossec/framework/python/bin/python3 /var/ossec/wodles/syscollector-report.py
```

To execute the Syscheck helper

```
/var/ossec/framework/python/bin/python3 /var/ossec/wodles/fim-report.py
```

It can also be executed as a wodle

```
<ossec_config>
<wodle name="command">
  <disabled>no</disabled>
  <tag>fim-report</tag>
  <command>/var/ossec/wodles/fim-report.py</command>
  <interval>30m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>no</run_on_start>
  <timeout>0</timeout>
  <skip_verification>yes</skip_verification>
</wodle>

<wodle name="command">
  <disabled>no</disabled>
  <tag>fim-report</tag>
  <command>/var/ossec/wodles/syscollector-report.py</command>
  <interval>30m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>no</run_on_start>
  <timeout>0</timeout>
  <skip_verification>yes</skip_verification>
</wodle>
</ossec_config>
```

To trigger alerts based on these events, you will need the following rules present, adjust the rule ids acordingly:

```
<group name="syscollector,">
    <rule id="100002" level="3">
        <location>wazuh-manager->syscollector</location>
        <description>Syscollector event</description>
    </rule>
</group>

<group name="syscheck,">
    <rule id="100003" level="3">
        <location>wazuh-manager->syscheck</location>
        <description>Syscheck event</description>
    </rule>
</group>

```
