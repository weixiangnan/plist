#!/bin/sh -e
################################################################
# 该脚本用于在ubuntu上安装以下类型VPN：
# * IPSec
# * L2TP over IPSec
# * PPTP
# 已在ubuntu 14.04 64bit LTS服务器上测试成功
#
# 该脚本应该也能够直接用于debian家族服务器
# 对于其他类型的linux发行版本，请根据需要适当修改以下指令：
# * apt-get
# 
################################################################

################################################################
# 运行方法：
# * 需要root权限, 切换到root用户或者使用sudo
# * 需要三个参数：
#     1. interface: 外网网卡名
#     2. ip: 外网ip
#     3. key: 验证密钥「加盟商后台可查看」
#
# 示例：
# $ sudo ./setup_vpn.sh eth0 45.76.223.157 01a3d8a177
#
# 说明：
# 可以使用ifconfig查看本机的网卡名和外网ip
#
################################################################

if [ "$#" -lt 3 ]; then
    echo "usage: ./$0 interface ip key"
    exit 1
fi

PUBLIC_IF=$1
PUBLIC_IP=$2
IPSEC_PSK=91vpnl2tp
RADIUS_SERVER1=1233211234567.xyz
RADIUS_SERVER2=1233211234567.info
RADIUS_SERVER_KEY=$3

DNS1=8.8.8.8
DNS2=114.114.114.114

echo ==============================================
echo ==============================================
echo =          编译安装程序
echo ==============================================
echo ==============================================

# 1. 安装依赖库
apt-get install make
apt-get install gcc
apt-get update
apt-get install -y wget curl libgmp-dev libssl-dev radiusclient1 xl2tpd pptpd

# 2. 下载strongswan源代码并解压
wget -qO- http://download.strongswan.org/strongswan-5.4.0.tar.bz2 | tar xjv

# 3. 编译安装
cd /root/strongswan-5.4.0
./configure --sysconfdir=/etc --enable-openssl --enable-nat-transport --disable-mysql --disable-ldap --enable-md4 --enable-eap-mschapv2 --enable-eap-aka --enable-eap-aka-3gpp2 --enable-eap-gtc --enable-eap-identity --enable-eap-md5 --enable-eap-peap --enable-eap-radius --enable-eap-sim --enable-eap-sim-file --enable-eap-simaka-pseudonym --enable-eap-simaka-reauth --enable-eap-simaka-sql --enable-eap-tls --enable-eap-tnc --enable-eap-ttls
make install
cd ../

echo ==============================================
echo ==============================================
echo =          配置ipsec
echo ==============================================
echo ==============================================

# 配置ipsec
cat > /etc/ipsec.conf <<EOF
config setup
    uniqueids=never

conn %default
    keyexchange=ike
    left=%any
    leftsubnet=0.0.0.0/0
    right=%any

conn IKE-BASE
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    leftcert=server.cert.pem
    rightsourceip=10.28.0.0/24

conn IKEv2-EAP
    also=IKE-BASE
    keyexchange=ikev2
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,3des-sha1!
    leftsendcert=always
    leftid=$PUBLIC_IP
    leftauth=pubkey
    leftfirewall=yes
    rightauth=eap-radius
    rightsendcert=never
    eap_identity=%any
    rekey=no
    dpdaction=clear
    fragmentation=yes
    auto=add

conn IKEv1-PSK
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes
    leftauth=psk
    rightauth=psk
    rightauth2=xauth-radius
    auto=add
    dpdaction=clear

conn L2TP-PSK
    keyexchange=ikev1
    authby=secret
    leftprotoport=17/1701
    leftfirewall=no
    rightprotoport=17/%any
    type=transport
    auto=add
EOF

cat > /etc/ipsec.secrets <<EOF
: RSA server.key.pem
: PSK "$IPSEC_PSK"
EOF

cat > /etc/strongswan.conf <<EOF
charon {
	load_modular = no
	
	filelog {
		/var/log/charon.log {
			# format string as passed to strftime(3)
			time_format = %b %e %T
			append = yes
			default = 0
			ike_name = yes
		}
	}

	plugins {
		eap-radius {
			accounting = yes
			servers {
				primary {
					address = $RADIUS_SERVER1
					secret = $RADIUS_SERVER_KEY
					auth_port = 1812
					acct_port = 1813
					nas_identifier = 91
				}
				secondary {
					address = $RADIUS_SERVER2
					secret = $RADIUS_SERVER_KEY
					auth_port = 1812
					acct_port = 1813
					nas_identifier = 91
				}
			}
		}
	}

    # dns server for client
	dns1 = $DNS1
	dns2 = $DNS2
	
	# for Windows WINS Server
	nbns1 = $DNS1
	nbns2 = $DNS2
}
EOF

curl -s -o /etc/ipsec.d/certs/server.cert.pem http://cert.1233211234567.xyz:9090/gencert.php?ip=$PUBLIC_IP

cat > /etc/ipsec.d/cacerts/ca.cert.pem <<EOF
-----BEGIN CERTIFICATE-----
MIIDKjCCAhKgAwIBAgIIQyLt7v9aQGQwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UE
BhMCQ04xDDAKBgNVBAoTA1ZQTjEWMBQGA1UEAxMNU3Ryb25nU3dhbiBDQTAeFw0x
NjA2MjcwODIyMjBaFw0yNjA2MjUwODIyMjBaMDMxCzAJBgNVBAYTAkNOMQwwCgYD
VQQKEwNWUE4xFjAUBgNVBAMTDVN0cm9uZ1N3YW4gQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDIIwEzF9RndOHzlWODFgSsaQpBnOLq3kprbiuOMAiY
gXwLakUhV7zyBLxmE1jpkwuA3zcer8Djpcn5hF1M9nzZ6ZK876tWUMATp8xH0JaC
/wHzq+q5v8ZudxNOVThKuZeHXQlt94/tALixxNfBcTtbuaBI7dAHNx4MXxpjEIqg
Z9/ssrJzoHzUn60lI9CCw7RA6UUuqXSVAMruJjwcud+vXsUOjrNAiJEB7TE95AuC
zW0kJDMT6WeLdZKuZR1l7LLzILVyfKftYvcUNv5cCqVWvuLgzTiVG/AClQuYYJV9
+8Ka35e1U9uCUq4hXnc4Mfi1M1aCLs8KlIIn6fDziK1bAgMBAAGjQjBAMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRfHCu2hv+scx8i
NNmx4SzNKID/3DANBgkqhkiG9w0BAQsFAAOCAQEArLWhrSTJ5xD0TyzXiKY9hk8U
vfu7mWtDWMBCC4kK5mTVj/aaCaT2xp3reuUk68+kWtIPJtpbruZLjkCUypV+xwO3
3Kytk7vnraITxODws1w7JwFn749AOk1JK4lXkfBpTCfbXU4TirDGusXOg4iHc3C8
N8zrHhmRYgiczrAd7xvUhOy8zDkSUFus1YIE/U4nJ0YJ1rEj6Ay9zBP2yYyZMLQu
hEDpknnLG1cAB0agkhDh9CHYG+XVMEQA9JBXQYw08zSwVjGoXaDBHvPNqL1gk9Zb
J1GRR/aSBQmVvG/rJOKY28JTMrJ4bWn73x8wDiAsFRDFTpNh4GNM9LSwQ2uaFA==
-----END CERTIFICATE-----
EOF

cat > /etc/ipsec.d/private/server.key.pem <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAKCAQEAvvKYLrqG2sIYz8GvUKRm9oYZ/1jIFMLTSjerl6FbsjEbdRsg
TJpjyysyNBHhB8gDWdmkIz67NNLb8giZgkeDsHnjuiow/pQFfDIGTNNRBIWqsooX
eMipj/+1wdxqdHhUfkoGAWYwFEPA4YFHes0Zp+tnDIhjHsWCMDbcYik44f4J5HtT
kY28yEItwrap5VtpQ5spRbytzpRrtDaZg4L+X8irMBSp9A3X8qC8KlfCHRFHY16t
LA3EaKgiRlvQjc/xr7pfnjTdk/2SLJ+ueJx+K1m3y8Yp8oUIS23BKQpPhXw3xt08
zUAL+pnnyF0+RbSfkYwbRzInum1gcRv0ZttKfQIDAQABAoH/Os86mvNAF+yG9g+c
SVDnQU042JaSdwQaPvWUp+yoswjVB1UhVAtyZ+DhlPg4pOJqpFWjjxRUjVQnuXuB
fjAI7MXVNxl4rbpCuOW98bAPVOTLfdUoUgiRx6GB3jHWeoJkXZtPswBx5r1JHPlp
tkcWoy+/rOKRDNFQN3TY7un40/L+2kxxmiEbVbidEHceMKT2cgPIVPlM3/X+CiQI
l7jSXXcjrYva++kbGPDWuhpXOt9wkTUnp/Sktpk04cVo9a8q7y9I97M8IG0BDG+o
Jiktfbo6Oww1RrX5aBx1wgh2Grs30bjnBrVwfu7VoPaHbtifTCHfvPjETADY0VSB
xnEzAoGBAPNhRsJaDtZToJ425tETSIuBysCummAkbsh0ULQ/RDPlIfLSu88++lAc
2BSy4gCxdxBeSyWXHEhmem1obEhump4YE7ap3YykYVKGN90A9CHUvCgFgKEOhkCr
R419CEt+Kd7wwPM8igFoHokgNc4+Tl1VQ4U92+gRkNccjRwtRelPAoGBAMjZT1tm
Co7p3bIuHrKgN44EV614GtMqQ9VoPh/+s4REGl6a7yAOynAmMsjgw500YSWV2PIT
yos2eODnplnhMzi1Q+nCyqsbdtMxT+38fktoM2dhcUBCq3GijQPVJZF8eite8WVT
YeVHenOaqFeHFeI9osyRGASdsD/gUCZuPcRzAoGALyXxJ0V7Clo5C21nWal6rEwA
k0M/9NAaBgtCdyiqdcM1yGy6pXN12n87/QaKccfvYORjemzDteLkZL2N/Jowqd/Q
MdrGaLCPigUmXVIJ+WPU74vhV1IRAAYuXmKScM2IHwBU4MohkhQxli7/PW0kkUAr
TGynZVXB0Wpei87ZdFECgYAgiAoxfKKjKUAOVygDuK2m5A8rerOllkfsbfj6B7Ad
8UXwItoucBbb+WPqY3VrpgtCIjZEZ248BDOqAftQvYglXD7GwxU+h7FEXc1bd7Uh
E5yX1xGX3fSU8EY047Y1DVtgYP1qcwn9MAmmZdt0ad3iiicvSSUBwmTEw9lXkC2S
/wKBgAlhhFYcHaJIjp93XzoGXD7sCOR6crD8BBHvzgRN/MFRX3v5giEL1qbG0TBc
s7G5aCoU0NFXDyhVhkwjxDqEHhNe/JNTxPCiPfdU8F+lN7FdLalDYu6VtSAU1IR1
5B+9Kenx6tT17xVej4YGXn0j9sllflkpV7nj2aEICiDYxGbm
-----END RSA PRIVATE KEY-----
EOF

echo ==============================================
echo ==============================================
echo =          配置radiusclient
echo ==============================================
echo ==============================================

cat > /etc/radiusclient/servers <<EOF
$RADIUS_SERVER1 $RADIUS_SERVER_KEY
EOF

cat > /etc/radiusclient/radiusclient.conf <<EOF
auth_order	radius,local
login_tries	4
login_timeout	60
nologin /etc/nologin
issue	/etc/radiusclient/issue
nas_identifier 91
authserver 	$RADIUS_SERVER1:1812
acctserver 	$RADIUS_SERVER1:1813
servers		/etc/radiusclient/servers
dictionary 	/etc/radiusclient/dictionary
login_radius	/usr/sbin/login.radius
seqfile		/var/run/radius.seq
mapfile		/etc/radiusclient/port-id-map
default_realm
radius_timeout	10
radius_retries	3
login_local	/bin/login
EOF

cat > /etc/radiusclient/dictionary.microsoft <<EOF
VENDOR          Microsoft       311     Microsoft
BEGIN VENDOR    Microsoft
ATTRIBUTE       MS-CHAP-Response        1       string  Microsoft
ATTRIBUTE       MS-CHAP-Error           2       string  Microsoft
ATTRIBUTE       MS-CHAP-CPW-1           3       string  Microsoft
ATTRIBUTE       MS-CHAP-CPW-2           4       string  Microsoft
ATTRIBUTE       MS-CHAP-LM-Enc-PW       5       string  Microsoft
ATTRIBUTE       MS-CHAP-NT-Enc-PW       6       string  Microsoft
ATTRIBUTE       MS-MPPE-Encryption-Policy 7     string  Microsoft
# This is referred to as both singular and plural in the RFC.
# Plural seems to make more sense.
ATTRIBUTE       MS-MPPE-Encryption-Type 8       string  Microsoft
ATTRIBUTE       MS-MPPE-Encryption-Types  8     string  Microsoft
ATTRIBUTE       MS-RAS-Vendor           9       integer Microsoft
ATTRIBUTE       MS-CHAP-Domain          10      string  Microsoft
ATTRIBUTE       MS-CHAP-Challenge       11      string  Microsoft
ATTRIBUTE       MS-CHAP-MPPE-Keys       12      string  Microsoft encrypt=1
ATTRIBUTE       MS-BAP-Usage            13      integer Microsoft
ATTRIBUTE       MS-Link-Utilization-Threshold 14 integer        Microsoft
ATTRIBUTE       MS-Link-Drop-Time-Limit 15      integer Microsoft
ATTRIBUTE       MS-MPPE-Send-Key        16      string  Microsoft
ATTRIBUTE       MS-MPPE-Recv-Key        17      string  Microsoft
ATTRIBUTE       MS-RAS-Version          18      string  Microsoft
ATTRIBUTE       MS-Old-ARAP-Password    19      string  Microsoft
ATTRIBUTE       MS-New-ARAP-Password    20      string  Microsoft
ATTRIBUTE       MS-ARAP-PW-Change-Reason 21     integer Microsoft
ATTRIBUTE       MS-Filter               22      string  Microsoft
ATTRIBUTE       MS-Acct-Auth-Type       23      integer Microsoft
ATTRIBUTE       MS-Acct-EAP-Type        24      integer Microsoft
ATTRIBUTE       MS-CHAP2-Response       25      string  Microsoft
ATTRIBUTE       MS-CHAP2-Success        26      string  Microsoft
ATTRIBUTE       MS-CHAP2-CPW            27      string  Microsoft
ATTRIBUTE       MS-Primary-DNS-Server   28      ipaddr
ATTRIBUTE       MS-Secondary-DNS-Server 29      ipaddr
ATTRIBUTE       MS-Primary-NBNS-Server  30      ipaddr Microsoft
ATTRIBUTE       MS-Secondary-NBNS-Server 31     ipaddr Microsoft
#ATTRIBUTE      MS-ARAP-Challenge       33      string  Microsoft
#
#       Integer Translations
#
#       MS-BAP-Usage Values
VALUE           MS-BAP-Usage            Not-Allowed     0
VALUE           MS-BAP-Usage            Allowed         1
VALUE           MS-BAP-Usage            Required        2
#       MS-ARAP-Password-Change-Reason Values
VALUE   MS-ARAP-PW-Change-Reason        Just-Change-Password            1
VALUE   MS-ARAP-PW-Change-Reason        Expired-Password                2
VALUE   MS-ARAP-PW-Change-Reason        Admin-Requires-Password-Change  3
VALUE   MS-ARAP-PW-Change-Reason        Password-Too-Short              4
#       MS-Acct-Auth-Type Values
VALUE           MS-Acct-Auth-Type       PAP             1
VALUE           MS-Acct-Auth-Type       CHAP            2
VALUE           MS-Acct-Auth-Type       MS-CHAP-1       3
VALUE           MS-Acct-Auth-Type       MS-CHAP-2       4
VALUE           MS-Acct-Auth-Type       EAP             5
#       MS-Acct-EAP-Type Values
VALUE           MS-Acct-EAP-Type        MD5             4
VALUE           MS-Acct-EAP-Type        OTP             5
VALUE           MS-Acct-EAP-Type        Generic-Token-Card      6
VALUE           MS-Acct-EAP-Type        TLS             13
END-VENDOR Microsoft
EOF

if ! grep -Fxq "INCLUDE /etc/radiusclient/dictionary.microsoft" /etc/radiusclient/dictionary; then
  echo "" >> /etc/radiusclient/dictionary
  echo "INCLUDE /etc/radiusclient/dictionary.microsoft" >> /etc/radiusclient/dictionary
  echo "INCLUDE /etc/radiusclient/dictionary.merit" >> /etc/radiusclient/dictionary
fi

echo ==============================================
echo ==============================================
echo =          配置l2tp
echo ==============================================
echo ==============================================

cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = 10.28.1.2-10.28.1.254
local ip = 10.28.1.1
length bit = yes
require chap = yes
refuse pap = yes
require authentication = yes
name = 91server
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
EOF

cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns $DNS1
ms-dns $DNS2

asyncmap 0
auth
crtscts
lock
hide-password
modem
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1400
noccp
connect-delay 5000
logfile /var/log/xl2tpd.log
plugin radius.so
plugin radattr.so
EOF

echo ==============================================
echo ==============================================
echo =          配置pptp
echo ==============================================
echo ==============================================

cat > /etc/pptpd.conf <<EOF
option /etc/ppp/options.pptpd
logwtmp
localip 10.28.2.1
remoteip 10.28.2.2-254
EOF

cat > /etc/ppp/options.pptpd <<EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns $DNS1
ms-dns $DNS2
proxyarp
nodefaultroute
lock
nobsdcomp
novj
novjccomp
nologfd
plugin radius.so
plugin radattr.so
EOF

echo ==============================================
echo ==============================================
echo =                  启动
echo ==============================================
echo ==============================================

if [ -f /etc/rc.local ];then
    cp /etc/rc.local /etc/rc.local.old
fi

cat > /etc/rc.local <<EOF
#!/bin/sh -e
# 91vpn autostart config

sysctl -w net.ipv4.ip_forward=1

iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1723 -j ACCEPT

iptables -t nat -A POSTROUTING -s 10.28.0.0/16 -o $PUBLIC_IF -j MASQUERADE

ipsec restart
service xl2tpd restart
service pptpd restart

exit 0
EOF

sysctl -w net.ipv4.ip_forward=1

iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1723 -j ACCEPT

iptables -t nat -A POSTROUTING -s 10.28.0.0/16 -o $PUBLIC_IF$ -j MASQUERADE

ipsec restart
service xl2tpd restart
service pptpd restart

echo ==============================================
echo ==============================================
echo =                  安装成功
echo ==============================================
echo ==============================================
