# RadSec Pi enrollment

`scripts/install-lego-radsec.sh` (self-armed by `update.sh`) installs the lego
scaffolding on every Pi but stays a **no-op until the Pi is enrolled**. Enrollment
is the one step a Pi must NOT self-serve (it would let a compromised Pi mint certs
for any internal name, incl. central), so it runs from the Ansible control node:

    ansible-playbook -i inventory ansible/enroll-radsec-pi.yml -l <pi_host> \
        --extra-vars "zabbix_api_token=<dedicated-token>"

It registers the Pi's DNS-01 key with `acme-hook@ca-dns`, triggers first issuance
(`lego run`), and creates the Zabbix cert-expiry item + 2 triggers. Renewal is then
hands-off (the Pi's daily `lego-radsec.timer`). Validated by hand on `d2001-jh-pi01`
2026-06-26 before being codified here.
