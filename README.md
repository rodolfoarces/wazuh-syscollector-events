# Reporting scripts

To obtain index data from syscheck and syscollector, these helper scripts can help

You will need to download the files and place them in a directory in the Wauh Manager (Master or Worker)

```
curl -L https://raw.githubusercontent.com/rodolfoarces/wazuh-syscollector-events/refs/heads/dev/src/wazuh-syscollector-events.py && chmod 700 ./wazuh-syscollector-events.py
curl -L https://raw.githubusercontent.com/rodolfoarces/wazuh-syscollector-events/refs/heads/dev/src/example.wazuh-syscollector-events.conf -o ./wazuh-syscollector-events.conf
```

The `/var/ossec/wodles/wazuh-syscollector-events.conf` is to be adjusted acordigly to the Wazuh Server API user.

To execute the Syscollector helper

```
/var/ossec/framework/python/bin/python3 /var/ossec/wodles/wazuh-syscollector-events.py
```

It can also be executed as a wodle

```
<ossec_config>

<wodle name="command">
  <disabled>no</disabled>
  <tag>syscollector-report</tag>
  <command>/var/ossec/wodles/wazuh-syscollector-events.py</command>
  <interval>30m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>no</run_on_start>
  <timeout>0</timeout>
  <skip_verification>yes</skip_verification>
</wodle>
</ossec_config>
```

The previous configuration requires the following parameter set on the `etc/local_internal_options.conf` file

```
wazuh_command.remote_commands=1
```

To trigger alerts based on these events, you will need the following rules present, adjust the rule ids acordingly:

```
<group name="syscollector,">
    <rule id="100002" level="3">
        <location>wazuh-manager->syscollector</location>
        <description>Syscollector event</description>
    </rule>
</group>

```

In the Wazuh Dashboard, you must edit the pipeline


`☰ > Indexer Management > Dev Tools`


```
PUT _ingest/pipeline/filebeat-7.10.2-wazuh-alerts-pipeline
{
    "description": "Wazuh alerts pipeline",
    "processors": [
      {
        "json": {
          "field": "message",
          "add_to_root": true
        }
      },
      {
        "set": {
          "field": "data.aws.region",
          "value": "{{data.aws.awsRegion}}",
          "override": false,
          "ignore_failure": true,
          "ignore_empty_value": true
        }
      },
      {
        "set": {
          "field": "data.aws.accountId",
          "value": "{{data.aws.aws_account_id}}",
          "override": false,
          "ignore_failure": true,
          "ignore_empty_value": true
        }
      },
      {
        "geoip": {
          "field": "data.srcip",
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "geoip": {
          "field": "data.win.eventdata.ipAddress",
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "geoip": {
          "field": "data.aws.sourceIPAddress",
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "geoip": {
          "field": "data.aws.client_ip",
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "geoip": {
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true,
          "field": "data.aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
        }
      },
      {
        "geoip": {
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true,
          "field": "data.aws.httpRequest.clientIp"
        }
      },
      {
        "geoip": {
          "field": "data.gcp.jsonPayload.sourceIP",
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "geoip": {
          "ignore_failure": true,
          "field": "data.office365.ClientIP",
          "target_field": "GeoLocation",
          "properties": [
            "city_name",
            "country_name",
            "region_name",
            "location"
          ],
          "ignore_missing": true
        }
      },
      {
        "date": {
          "field": "timestamp",
          "target_field": "@timestamp",
          "formats": [
            "ISO8601"
          ],
          "ignore_failure": false
        }
      },
		{
			"date_index_name": {
				"if": "ctx?.location == 'wazuh-manager->syscollector'",
				"field": "timestamp",
				"date_rounding": "d",
				"index_name_prefix": "{{fields.index_prefix}}syscollector-",
				"index_name_format": "yyyy.MM.dd",
				"ignore_failure": true
			}
		},
      {
        "date_index_name": {
			"if": "ctx?.location != 'wazuh-manager->syscollector'",
			"field": "timestamp",
			"date_rounding": "d",
			"index_name_prefix": "fields.index_prefix",
			"index_name_format": "yyyy.MM.dd",
			"ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "message",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "ignore_missing": true,
          "ignore_failure": true,
          "field": "ecs"
        }
      },
      {
        "remove": {
          "field": "beat",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "input_type",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "ignore_missing": true,
          "ignore_failure": true,
          "field": "tags"
        }
      },
      {
        "remove": {
          "field": "count",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "@version",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "log",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "ignore_missing": true,
          "ignore_failure": true,
          "field": "offset"
        }
      },
      {
        "remove": {
          "field": "type",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "host",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "fields",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "field": "event",
          "ignore_missing": true,
          "ignore_failure": true
        }
      },
      {
        "remove": {
          "ignore_failure": true,
          "field": "fileset",
          "ignore_missing": true
        }
      },
      {
        "remove": {
          "field": "service",
          "ignore_missing": true,
          "ignore_failure": true
        }
      }
    ],
    "on_failure": [
      {
        "drop": {}
      }
    ]
}
```
