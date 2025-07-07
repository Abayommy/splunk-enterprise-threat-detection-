```spl
index=* sourcetype=*auth* (failed OR Failed OR FAILED) | eval src_ip=coalesce(src_ip, client_ip, "unknown") | eval user=coalesce(failed_user, invalid_user, user, "unknown") | bucket _time span=1m | stats count dc(user) as unique_users by _time src_ip | where count > 5 | eval risk_level=case(count>20, "CRITICAL", count>10, "HIGH", count>5, "MEDIUM") | sort -countEOF
