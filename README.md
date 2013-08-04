groups-iptables
===============

A hacky little perl script that I put together to allow people to generate iptables scripts from simple group based templates

When managing highly available services, you tend to need to think in terms of rules like :  "permit partner x to acceess all webservers hosting the partner service".  If you use an IPTables based gateway, this involves lots of rules which are similar, and leaves you with a simple way to screw up (miss one webserver out of one particular rule).  

This software allows you to express iptables rules based on groups, and in english form, and outputs a simple script which can be used to configure IPTables on your gateway.
