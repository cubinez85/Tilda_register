# Tilda_register
sudo nano /etc/postgresql/14/main/pg_hba.conf
change block "local" is for Unix domain socket connections only:
# "local" is for Unix domain socket connections only
local   all             all                                     md5
# IPv4 local connections:
host    all             all             127.0.0.1/32            md5
# IPv6 local connections:
host    all             all             ::1/128                 md5
sudo nano /etc/postfix/main.cf
mynetworks = 127.0.0.0/8 172.23.132.3/32 95.174.94.246 176.109.109.221
