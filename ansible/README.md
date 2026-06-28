# RadSec Pi enrollment

`scripts/install-lego-radsec.sh` (self-armed by `update.sh`) installs the lego
scaffolding + generates the Pi's DNS-01 key, but the Pi gets NO cert until it is
enrolled. Enrollment is two steps, split along the access boundaries:

1. **GATED -- CA admin, on ca-dns** (a Pi/.3 must not authorize itself to the CA):
   get the Pi pubkey and register it:

       ssh <pi> sudo cat /etc/lego/ssh_id.pub        # or read it from the play output
       sudo /usr/local/sbin/register-radsec-pi.sh '<that pubkey line>'   # on ca-dns

2. **Ansible from .3** (svc_ansible, one narrow sudo grant): issue the cert +
   create the Zabbix cert-expiry item/triggers:

       ansible-playbook -i inventory/netbox.yml ansible/enroll-radsec-pi.yml \
           -l <pi> -e zabbix_api_token=<dedicated-token>

The play prints the exact step-1 command (with the pubkey). Renewal afterwards is
hands-off (the Pi daily `lego-radsec.timer`). To then send the Pi->central auth hop
over RadSec, open the 3 firewall layers to `.13:2083` and set `RADSEC_UPSTREAM=true`
in the Pi `.env`.
