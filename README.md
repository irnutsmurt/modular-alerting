# modular-alerting
modular alerting script that is uses a config file to add scripts as needed. Alerting scripts that are looped are threaded. The threads are monitored and released after 90 seconds if the loop doesn't successfully complete. 
