#!/bin/bash

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] OS not supported, exting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
}
ip_address
IPADDR="$(ip_address)"
apt-get update && apt-get update
#Install Privoxy
function privoxy(){
  apt-get install privoxy -y
sed -i 's/[::]:8118/#[::]:8118/g' /etc/privoxy/config
sed -i 's/localhost:8118/0.0.0.0:8080/g' /etc/privoxy/config
service privoxy restart
}
privoxy
#Openvpn Port
Openvpn_Port1='110'
#Provoxy_Port
Privoxy_Port1='8080'
Privoxy_Port2='8000'
#Install ufw
apt-get install ufw -y
#Configure ufw
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw
cat <<ufw>> /etc/ufw/before.rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/16 -o ens3 -j MASQUERADE
COMMIT
ufw
 # Iptables Rule for OpenVPN server
 PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
 IPCIDR='10.200.0.0/16'
 iptables -I FORWARD -s $IPCIDR -j ACCEPT
 iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
 iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
#enable ports
ufw allow 110/tcp
ufw allow 8080/tcp
ufw allow 8000/tcp
ufw allow OpenSSH
ufw disable
ufw enable
#Enable IP Forwarding
sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf'
echo >> /etc/sysctl.conf net.ipv4.ip_forward = 1
sysctl -p
# Generating openvpn dh.pem file using openssl
 openssl dhparam -out /etc/openvpn/dh.pem 1024
#Install Openvpn
apt-get install openvpn -y
mkdir /etc/openvpn/easy-rsa/keys
cp -r /usr/share/easy-rsa /etc/openvpn/

#Setup CA
cat <<EOT3>> /usr/share/doc/openvpn/examples/sample-keys/ca.crt
-----BEGIN CERTIFICATE-----
MIIE2TCCA8GgAwIBAgIJAOPmjEHN9pwDMA0GCSqGSIb3DQEBCwUAMIGjMQswCQYD
VQQGEwJQSDEQMA4GA1UECBMHS29yblZQTjEQMA4GA1UEBxMHS29yblZQTjEQMA4G
A1UEChMHS29yblZQTjETMBEGA1UECxMKVHJpbml0eVZQTjETMBEGA1UEAxMKS29y
blZQTiBDQTEQMA4GA1UEKRMHS29yblZQTjEiMCAGCSqGSIb3DQEJARYTa29ybnZw
bjMwQGdtYWlsLmNvbTAeFw0yMTAyMjcxMTA2MzlaFw0zMTAyMjUxMTA2MzlaMIGj
MQswCQYDVQQGEwJQSDEQMA4GA1UECBMHS29yblZQTjEQMA4GA1UEBxMHS29yblZQ
TjEQMA4GA1UEChMHS29yblZQTjETMBEGA1UECxMKVHJpbml0eVZQTjETMBEGA1UE
AxMKS29yblZQTiBDQTEQMA4GA1UEKRMHS29yblZQTjEiMCAGCSqGSIb3DQEJARYT
a29ybnZwbjMwQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKhE6BX1+sXgyXTSqZuILMbWi5xW7KhCDG4K2V1kszIfZ1nedq8AXl+GBrx2
DVES+osOTTqfau36HPngJ4s8akafgZVWRVIzeSi0ZpXEtrYhVaXG1RBWXYkDHk+S
ycBMaVm6IXSj7pjNmlTdZXJhpcseZaOFsEQhICJGRQF6heD3FDC8AS4FwyE/yTYh
nSGT6vNqzVNOE9egtvkLBGJiVjuhuWB1cuPkRPIzvKlbva6lfcABss/InbZv/iDk
YR52XgG4d4vZKwS/XcoQtl5T3otbVazsWIY5t0+9zOoPn44IofeXvydZDxwk3fQV
KtrHMslSDCbVfL/58KCzSywKBNMCAwEAAaOCAQwwggEIMB0GA1UdDgQWBBSMoBB0
PW+BG5PQWd4ewPZgcfgLMjCB2AYDVR0jBIHQMIHNgBSMoBB0PW+BG5PQWd4ewPZg
cfgLMqGBqaSBpjCBozELMAkGA1UEBhMCUEgxEDAOBgNVBAgTB0tvcm5WUE4xEDAO
BgNVBAcTB0tvcm5WUE4xEDAOBgNVBAoTB0tvcm5WUE4xEzARBgNVBAsTClRyaW5p
dHlWUE4xEzARBgNVBAMTCktvcm5WUE4gQ0ExEDAOBgNVBCkTB0tvcm5WUE4xIjAg
BgkqhkiG9w0BCQEWE2tvcm52cG4zMEBnbWFpbC5jb22CCQDj5oxBzfacAzAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAaGlZieMPCeVdhFwMGmVKDFHH1
2usE6tmnCMvbHImvO/8uPzr5l3jzC8SndyHxx5Rc73TSV8FYXyb6eCqt1DouWWdG
PFhYcgyq/OcDHOg4R65QZYpn/1UCOHHr13MWwx2sLkc0WhtLMfOjuWo5pcgAlmjc
7M6C4k8BjPdOh7Bkh45QSIWokKkgJj1Ibhp6zxaFi0J4Gy71UCKvalt/lKJ1S1rH
MbdS39mT8p3Toz+AAYx/UEKkC84Sx35oULhsBz1qEwCBmSwYxxe1ccSW97SuPcBO
VFZ+LzZmP3coiDaaau4fMFRVYxINFJpX0faRn82gLPNLAcvIyqE/aXyoGVaQ
-----END CERTIFICATE-----
EOT3
#Setup Server.crt
cat <<EOT5>> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=PH, ST=KornVPN, L=KornVPN, O=KornVPN, OU=TrinityVPN, CN=KornVPN CA/name=KornVPN/emailAddress=kornvpn30@gmail.com
        Validity
            Not Before: Feb 27 11:06:39 2021 GMT
            Not After : Feb 25 11:06:39 2031 GMT
        Subject: C=PH, ST=KornVPN, L=KornVPN, O=KornVPN, OU=TrinityVPN, CN=server/name=KornVPN/emailAddress=kornvpn30@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c5:39:f1:a8:1a:f3:62:9f:1f:73:5f:e4:fa:ce:
                    af:4a:26:71:52:f8:aa:5e:39:7c:b1:38:7c:39:87:
                    32:5f:f5:23:9b:ac:24:3e:b7:4e:3c:88:d4:65:fd:
                    a7:ef:48:04:67:29:8c:98:21:a4:dd:15:e7:6c:14:
                    48:f2:79:43:38:ac:2d:c3:17:97:c0:d9:85:24:0e:
                    c3:75:2a:97:62:bb:4d:bd:95:03:b2:9f:5c:06:9e:
                    75:da:38:90:80:2b:ac:db:a1:02:3f:59:f6:db:8f:
                    53:54:50:f8:38:3f:5e:21:7a:cd:77:25:db:ef:0f:
                    0b:a4:af:b6:bb:f3:64:ea:6b:43:e1:90:c2:51:71:
                    37:06:fc:1c:fc:59:54:e8:d9:11:23:e3:df:d9:9d:
                    10:92:83:51:98:20:80:51:d9:70:63:05:7f:12:ee:
                    77:ac:d2:ca:47:f0:c9:c2:41:2e:40:6b:77:d4:30:
                    d8:ae:d7:74:28:b3:bf:d6:71:de:35:d4:db:f7:43:
                    d8:d2:c0:34:92:41:87:26:4d:37:d2:ed:b4:f0:75:
                    5d:ad:ac:86:89:6f:64:9a:30:e8:55:14:7f:57:4c:
                    5c:b8:4b:9b:5b:e6:5d:5b:4f:dd:27:7b:f0:b0:71:
                    9e:80:03:62:81:2b:25:95:9d:a4:e3:07:ba:9e:63:
                    cd:5f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Cert Type:
                SSL Server
            Netscape Comment:
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier:
                89:3D:FB:D1:A0:03:76:CE:B7:42:8D:4D:5E:E5:55:FD:40:4B:AA:DA
            X509v3 Authority Key Identifier:
                keyid:8C:A0:10:74:3D:6F:81:1B:93:D0:59:DE:1E:C0:F6:60:71:F8:0B:32
                DirName:/C=PH/ST=KornVPN/L=KornVPN/O=KornVPN/OU=TrinityVPN/CN=KornVPN CA/name=KornVPN/emailAddress=kornvpn30@gmail.com
                serial:E3:E6:8C:41:CD:F6:9C:03

            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Key Usage:
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name:
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         5f:c9:26:3f:aa:5d:ab:48:54:b0:8b:93:4e:46:d8:2e:ee:ae:
         2c:c1:7f:0b:f7:de:27:00:b4:8a:a0:4c:a9:d6:71:c1:96:bb:
         b6:17:9d:eb:fd:9d:42:f5:c1:c9:b4:19:8f:a6:19:c2:5d:26:
         12:94:c4:e8:b7:a2:34:d9:06:2d:2e:e5:a4:c5:4b:66:4a:b3:
         5e:82:f7:f7:37:81:76:64:5e:56:8f:e2:b5:61:0d:75:0f:4f:
         d6:ea:94:c9:1e:6a:3e:c2:f5:58:9c:b9:3e:20:b7:53:ab:75:
         00:8c:0c:bf:d5:97:02:46:47:44:1f:fe:f6:cd:0f:04:8b:97:
         ff:08:74:bd:ba:4c:48:5e:c7:75:f0:44:8c:98:f5:25:31:5f:
         08:c5:da:4f:0e:71:ed:56:16:5e:78:8a:1e:c5:57:de:46:06:
         f6:39:26:bb:a6:2c:77:47:ec:c7:0f:76:4e:81:7e:5e:34:f8:
         a7:42:d5:1c:d1:b9:cf:89:49:71:19:fc:c2:eb:32:e5:ea:da:
         0f:06:3c:b3:5b:c4:22:44:57:49:f0:f9:d8:0f:1f:20:9e:17:
         1b:cf:b2:31:17:c5:8c:10:82:fe:ed:fd:1d:87:5b:03:74:47:
         db:92:b7:e5:30:3b:e3:fb:56:dd:b8:1a:27:bb:45:70:01:5c:
         c7:a1:4d:42
-----BEGIN CERTIFICATE-----
MIIFSDCCBDCgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBozELMAkGA1UEBhMCUEgx
EDAOBgNVBAgTB0tvcm5WUE4xEDAOBgNVBAcTB0tvcm5WUE4xEDAOBgNVBAoTB0tv
cm5WUE4xEzARBgNVBAsTClRyaW5pdHlWUE4xEzARBgNVBAMTCktvcm5WUE4gQ0Ex
EDAOBgNVBCkTB0tvcm5WUE4xIjAgBgkqhkiG9w0BCQEWE2tvcm52cG4zMEBnbWFp
bC5jb20wHhcNMjEwMjI3MTEwNjM5WhcNMzEwMjI1MTEwNjM5WjCBnzELMAkGA1UE
BhMCUEgxEDAOBgNVBAgTB0tvcm5WUE4xEDAOBgNVBAcTB0tvcm5WUE4xEDAOBgNV
BAoTB0tvcm5WUE4xEzARBgNVBAsTClRyaW5pdHlWUE4xDzANBgNVBAMTBnNlcnZl
cjEQMA4GA1UEKRMHS29yblZQTjEiMCAGCSqGSIb3DQEJARYTa29ybnZwbjMwQGdt
YWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMU58aga82Kf
H3Nf5PrOr0omcVL4ql45fLE4fDmHMl/1I5usJD63TjyI1GX9p+9IBGcpjJghpN0V
52wUSPJ5QzisLcMXl8DZhSQOw3Uql2K7Tb2VA7KfXAaeddo4kIArrNuhAj9Z9tuP
U1RQ+Dg/XiF6zXcl2+8PC6SvtrvzZOprQ+GQwlFxNwb8HPxZVOjZESPj39mdEJKD
UZgggFHZcGMFfxLud6zSykfwycJBLkBrd9Qw2K7XdCizv9Zx3jXU2/dD2NLANJJB
hyZNN9LttPB1Xa2sholvZJow6FUUf1dMXLhLm1vmXVtP3Sd78LBxnoADYoErJZWd
pOMHup5jzV8CAwEAAaOCAYcwggGDMAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQD
AgZAMDQGCWCGSAGG+EIBDQQnFiVFYXN5LVJTQSBHZW5lcmF0ZWQgU2VydmVyIENl
cnRpZmljYXRlMB0GA1UdDgQWBBSJPfvRoAN2zrdCjU1e5VX9QEuq2jCB2AYDVR0j
BIHQMIHNgBSMoBB0PW+BG5PQWd4ewPZgcfgLMqGBqaSBpjCBozELMAkGA1UEBhMC
UEgxEDAOBgNVBAgTB0tvcm5WUE4xEDAOBgNVBAcTB0tvcm5WUE4xEDAOBgNVBAoT
B0tvcm5WUE4xEzARBgNVBAsTClRyaW5pdHlWUE4xEzARBgNVBAMTCktvcm5WUE4g
Q0ExEDAOBgNVBCkTB0tvcm5WUE4xIjAgBgkqhkiG9w0BCQEWE2tvcm52cG4zMEBn
bWFpbC5jb22CCQDj5oxBzfacAzATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8E
BAMCBaAwEQYDVR0RBAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4IBAQBfySY/
ql2rSFSwi5NORtgu7q4swX8L994nALSKoEyp1nHBlru2F53r/Z1C9cHJtBmPphnC
XSYSlMTot6I02QYtLuWkxUtmSrNegvf3N4F2ZF5Wj+K1YQ11D0/W6pTJHmo+wvVY
nLk+ILdTq3UAjAy/1ZcCRkdEH/72zQ8Ei5f/CHS9ukxIXsd18ESMmPUlMV8IxdpP
DnHtVhZeeIoexVfeRgb2OSa7pix3R+zHD3ZOgX5eNPinQtUc0bnPiUlxGfzC6zLl
6toPBjyzW8QiRFdJ8PnYDx8gnhcbz7IxF8WMEIL+7f0dh1sDdEfbkrflMDvj+1bd
uBonu0VwAVzHoU1C
-----END CERTIFICATE----- 
EOT5
#Setup Server.key
cat <<EOT4>> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFOfGoGvNinx9z
X+T6zq9KJnFS+KpeOXyxOHw5hzJf9SObrCQ+t048iNRl/afvSARnKYyYIaTdFeds
FEjyeUM4rC3DF5fA2YUkDsN1Kpdiu029lQOyn1wGnnXaOJCAK6zboQI/Wfbbj1NU
UPg4P14hes13JdvvDwukr7a782Tqa0PhkMJRcTcG/Bz8WVTo2REj49/ZnRCSg1GY
IIBR2XBjBX8S7nes0spH8MnCQS5Aa3fUMNiu13Qos7/Wcd411Nv3Q9jSwDSSQYcm
TTfS7bTwdV2trIaJb2SaMOhVFH9XTFy4S5tb5l1bT90ne/CwcZ6AA2KBKyWVnaTj
B7qeY81fAgMBAAECggEAHkcH90Oz64b8IA0vrOU/+cUvDorINNDkeJxwTbCYpiyO
+94QbmRbqWVkHggz2MMYkfHJ+Kzpj1tGfMwcasT88d1U5SdhD6UVEHUHwpv4Q5r3
k0wmFizqxsVa2FZosJSD4++y1aDtCcXWCBKqGJB51e/xTQJN4kRQCEdFaVMzQd1S
gtk85krnKBFNqplbXOl1j1oT66OOBp6Kl0B8TDutxogyL88OGcS/PZjjVcEWR+4u
n/QiNgHq643G/iVzhMp3zz5v8ph4mAyg1vTC5ZOul98zm8ITGWnyL4YuHpDz/Rj7
f19Q2m1/kxn9ghOHB/hCVp1XGb7DNx0XfIERYOTAmQKBgQD0JP+djz1HWYJYw5sf
ILSRYubf6ndWPy3VsaUkL/ucBxZHAxdOumjOjHPpctqPPOQOrvgf8xDOJtAmvECQ
aZDwjsE0/kCFv474oxn1rP2jL38XRGNIFWx2ry09wZ6zC+2keXy3xuvlycLnmiGN
B9051bfT0as9KNeiGX/akHXkuwKBgQDOzbKcIc3QnDziRkDrwY6Q/BsRjJZua1bg
y04N3wySRg164Tgu586xjVPi6iUzouc/QoPBDOQDesJt+bA0oHmkx+WDdqXR32oK
uBWreyM8B2X9qmhKTEp9hDVEa/FK+5NtGQ2HP9TIhMNRtiPiQlXKjKJ757XtnmiP
9xaZFwKBrQKBgQChS0Q4sqY4WhE8VVZJNVE179I5wmw+5ZSBZlCE3NJsnV4BYjBm
yc5uDuqRI1jzYrYEYWH5sZq7p3bC8IHzJlskIhvQx9yWwBxTdWW0IiqbQcjD9WFm
AQlcS5UnBKC1Bz9j9wMHYvr8H9SNMA3UX4qvJ9u/q/hmenIjXJdULTZF+wKBgQCd
ljmIqGnBkY0DkC1geXo+GR43XT40ni7x1XqBL3rQ6/jRrlW1yIbE3cESpQH8OyKk
HfdwYHZQAHewfhg7wh1v57OJXhw1tV2FFYnNxmOvFqQtjHE0TLZmtxwwK2EPlm1d
MT4R1h47Po/n8Def7pSZaFlYudT0YUWkjtD1j4clcQKBgAF9MxvASdLaW0E+TJuQ
AvAlp4hFyfEMhzSAdxKxDZnLhlJuAc4jdl9FsOkIVJQDYQmSOdNbFA/+CYdG8Elq
JLfMdbtBIHRQjHBGp7OcWcOk0lIbgWrWDDoNrtlfzlkp1QEPtl8LMywz1fLNtQ/V
g9lQqIe86ZfEaI2aX5moZijl
-----END PRIVATE KEY-----
EOT4
#Configure Openvpn Server
cat <<EOT1>> /etc/openvpn/server.conf
port $Openvpn_Port1
proto tcp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/tecadmin-server.crt
key /etc/openvpn/server/tecadmin-server.key
dh /etc/openvpn/server/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1"

push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
duplicate-cn
cipher AES-256-CBC
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-CBC-SHA256
auth SHA512
auth-nocache
keepalive 20 60
persist-key
persist-tun
compress lz4
daemon
user nobody
group nogroup
log-append /var/log/openvpn.log
verb 2
EOT1

#Configure Openvpn Client
cat <<EOT2>> /etc/openvpn/client/client.ovpn
client
dev tun
proto tcp
remote $IPADDR $Openvpn_Port1
ca ca.crt
cert client.crt
key client.key
cipher AES-256-CBC
auth SHA512
auth-nocache
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-CBC-SHA256
resolv-retry infinite
compress lz4
nobind
persist-key
persist-tun
mute-replay-warnings
verb 2
EOT2
systemctl start openvpn@server
systemctl enable openvpn@server
systemctl status openvpn@server

