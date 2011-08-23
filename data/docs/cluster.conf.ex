<?xml version="1.0"?>
<cluster name="cluster1" config_version="15">

  <cman keyfile="/var/lib/pve-cluster/corosync.authkey">
  </cman>

  <clusternodes>
    <clusternode name="node1" votes="1" nodeid="1"/>
    <clusternode name="node2" votes="1" nodeid="2"/>
    <clusternode name="node3" votes="1" nodeid="3"/>
  </clusternodes>

  <rm>
    <failoverdomains/>
    <resources/>
    <service autostart="1" exclusive="0" recovery="relocate" name="testip">
      <ip address="192.168.3.11" monitor_link="1"/>
    </service>
  </rm>

</cluster>
