#!/usr/bin/env bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	wulabing
#	Dscription: Xray onekey Management
#	email: admin@wulabing.com
#====================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# 字体颜色配置
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# 变量
shell_version="1.3.11"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/xray_web/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')
WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

function shell_mode_check() {
  if [ -f ${xray_conf_dir}/config.json ]; then
    if [ "$(grep -c "wsSettings" ${xray_conf_dir}/config.json)" -ge 1 ]; then
      shell_mode="ws"
    else
      shell_mode="tcp"
    fi
  else
    shell_mode="None"
  fi
}
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "Pengguna saat ini adalah root, mulai proses penginstalan"
  else
    print_error "Pengguna saat ini bukan pengguna root, silakan beralih ke pengguna root dan jalankan kembali skrip."
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 memenuhi"
    sleep 1
  else
    print_error "$1 gagal (misalnya percobaan)"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "Sistem saat ini adalah Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    ${INS} wget
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/basic/nginx.repo


  elif [[ "${ID}" == "ol" ]]; then
    print_ok "Sistem saat ini adalah Oracle Linux ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/basic/nginx.repo
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "Sistem saat ini adalah Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    # nginx 安装预处理
    $INS curl gnupg2 ca-certificates lsb-release debian-archive-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/debian `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

    apt update

  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "Sistem saat ini adalah Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    # nginx 安装预处理
    $INS curl gnupg2 ca-certificates lsb-release ubuntu-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

    apt update
  else
    print_error "Sistem saat ini adalah ${ID} ${VERSION_ID} Tidak ada dalam daftar sistem yang didukung"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # 关闭各类防火墙
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx pemasangan"
  else
    print_ok "Nginx sudah ada sebelumnya"
  fi
  # 遗留问题处理
  mkdir -p /etc/nginx/conf.d >/dev/null 2>&1
}
function dependency_install() {
  ${INS} lsof tar
  judge "pemasangan lsof tar"

  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    ${INS} crontabs
  else
    ${INS} cron
  fi
  judge "pemasangan crontab"

  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
    systemctl start crond && systemctl enable crond
  else
    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron

  fi
  judge "crontab Konfigurasi memulai sendiri "

  ${INS} unzip
  judge "pemasangan unzip"

  ${INS} curl
  judge "pemasangan curl"

  # upgrade systemd
  ${INS} systemd
  judge "Instalasi/peningkatan systemd"

  # Nginx 后置 无需编译 不再需要
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    yum -y groupinstall "Development tools"
  #  else
  #    ${INS} build-essential
  #  fi
  #  judge "编译工具包 安装"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  elif [[ "${ID}" == "ol" ]]; then
    ${INS} pcre pcre-devel zlib-devel openssl openssl-devel
    # Oracle Linux 不同日期版本的 VERSION_ID 比较乱 直接暴力处理。如出现问题或有更好的方案，请提交 Issue。
    yum-config-manager --enable ol7_developer_EPEL >/dev/null 2>&1
    yum-config-manager --enable ol8_developer_EPEL >/dev/null 2>&1
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/binary/jq && chmod +x /usr/bin/jq
    judge "安装 jq"
  fi

  # 防止部分系统xray的默认bin目录缺失
  mkdir /usr/local/bin >/dev/null 2>&1
}

function basic_optimization() {
  # 最大文件打开数
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # RedHat 系发行版关闭 SELinux
  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}

function domain_check() {
  read -rp "Silakan masukkan informasi nama domain Anda(eg: www.wulabing.com):" domain
  domain_ip=$(curl -sm8 ipget.net/?ip="${domain}")
  print_ok "Mengambil informasi alamat IP, harap menunggu dengan sabar"
  wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
    # 关闭wgcf-warp，以防误判VPS IP情况
    wg-quick down wgcf >/dev/null 2>&1
    print_ok "Ditutup wgcf-warp"
  fi
  local_ipv4=$(curl -4 ip.sb)
  local_ipv6=$(curl -6 ip.sb)
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    # 纯IPv6 VPS，自动添加DNS64服务器以备acme.sh申请证书使用
    echo -e nameserver 2a01:4f8:c2c:123f::1 > /etc/resolv.conf
    print_ok "mengidentifikasi sebagai IPv6 Only 的 VPS，Tambah Otomatis DNS64 server"
  fi
  echo -e "Nama domain diselesaikan melalui DNS ke alamat IP：${domain_ip}"
  echo -e "Alamat IPv4 publik lokal： ${local_ipv4}"
  echo -e "Alamat IPv6 publik lokal： ${local_ipv6}"
  sleep 2
  if [[ ${domain_ip} == "${local_ipv4}" ]]; then
    print_ok "Alamat IP nama domain yang diselesaikan melalui DNS cocok dengan alamat IPv4 asli"
    sleep 2
  elif [[ ${domain_ip} == "${local_ipv6}" ]]; then
    print_ok "Alamat IP nama domain yang diselesaikan melalui DNS cocok dengan alamat IPv6 asli"
    sleep 2
  else
    print_error "Harap pastikan nama domain telah menambahkan data A/AAAA yang benar, jika tidak, xray tidak akan berfungsi dengan benar"
    print_error "Alamat IP nama domain yang diselesaikan melalui DNS tidak cocok dengan alamat IPv4/IPv6 lokal. Apakah Anda ingin melanjutkan instalasi?？（y/n）" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "Lanjutkan instalasi"
      sleep 2
      ;;
    *)
      print_error "Instalasi dihentikan"
      exit 2
      ;;
    esac
  fi
}

function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 Port tidak ditempati"
    sleep 1
  else
    print_error "terdeteksi $1 Port ditempati，mengikuti $1 Informasi Penggunaan Port"
    lsof -i:"$1"
    print_error "5s Setelah itu, ia akan mencoba membunuh proses yang ditempati secara otomatis"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill memenuhi"
    sleep 1
  fi
}
function update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "Ada versi baru, apakah sudah diperbarui [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/install.sh
      print_ok "Pembaruan selesai"
      print_ok "Anda dapat melakukan ini dengan bash $0 Penerapan prosedur ini"
      exit 0
      ;;
    *) ;;
    esac
  else
    print_ok "Versi saat ini adalah versi terbaru"
    print_ok "Anda dapat melakukan ini dengan bash $0 Implementasi prosedur ini"
  fi
}

function xray_tmp_config_file_check_and_use() {
  if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
    mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
  else
    print_error "xray Pengecualian modifikasi file konfigurasi"
  fi
}

function modify_UUID() {
  [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray TCP UUID modifikasi"
}

function modify_UUID_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws UUID modifikasi"
}

function modify_fallback_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray fallback_ws modifikasi"
}

function modify_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"streamSettings","wsSettings","path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws modifikasi"
}

function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf && wget -O ${domain}.conf https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/web.conf
  sed -i "s/xxx/${domain}/g" ${nginx_conf}
  judge "Nginx Modifikasi Konfigurasi"
  
  systemctl enable nginx
  systemctl restart nginx
}

function modify_port() {
  read -rp "Masukkan nomor port (default：443)：" PORT
  [ -z "$PORT" ] && PORT="443"
  if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
    print_error "Masukkan nilai antara 0 dan 65535"
    exit 1
  fi
  port_exist_check $PORT
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"port"];'${PORT}')' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray Modifikasi Port"
}

function configure_xray() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_xtls-rprx-vision.json
  modify_UUID
  modify_port
}

function configure_xray_ws() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_tls_ws_mix-rprx-vision.json
  modify_UUID
  modify_UUID_ws
  modify_port
  modify_fallback_ws
  modify_ws
}

function xray_install() {
  print_ok "pemasangan Xray"
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
  judge "Xray pemasangan"

  # 用于生成 Xray 的导入链接
  echo $domain >$domain_tmp_dir/domain
  judge "Catatan Domain"
}

function ssl_install() {
  #  使用 Nginx 配合签发 无需安装相关依赖
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    ${INS} socat nc
  #  else
  #    ${INS} socat netcat
  #  fi
  #  judge "安装 SSL 证书生成脚本依赖"

  curl -L https://get.acme.sh | bash
  judge "Menginstal Skrip Pembuatan Sertifikat SSL"
}

function acme() {
  "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  sed -i "6s/^/#/" "$nginx_conf"
  sed -i "6a\\\troot $website_dir;" "$nginx_conf"
  systemctl restart nginx

  if "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force; then
    print_ok "SSL Pembuatan Sertifikat Berhasil"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "SSL Konfigurasi Sertifikat Berhasil"
      sleep 2
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        print_ok "diaktifkan wgcf-warp"
      fi
    fi
  elif "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force --listen-v6; then
    print_ok "SSL Pembuatan Sertifikat Berhasil"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "SSL Konfigurasi Sertifikat Berhasil"
      sleep 2
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        print_ok "diaktifkan wgcf-warp"
      fi
    fi
  else
    print_error "SSL Kegagalan Pembuatan Sertifikat"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
      wg-quick up wgcf >/dev/null 2>&1
      print_ok "diaktifkan wgcf-warp"
    fi
    exit 1
  fi

  sed -i "7d" "$nginx_conf"
  sed -i "6s/#//" "$nginx_conf"
}

function ssl_judge_and_install() {

  mkdir -p /ssl >/dev/null 2>&1
  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    print_ok "/ssl File sertifikat sudah ada di direktori"
    print_ok "Menghapus atau tidak /ssl File sertifikat dalam direktori [Y/N]?"
    read -r ssl_delete
    case $ssl_delete in
    [yY][eE][sS] | [yY])
      rm -rf /ssl/*
      print_ok "dihapus"
      ;;
    *) ;;

    esac
  fi

  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "File sertifikat sudah ada"
  elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
    echo "File sertifikat sudah ada"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --ecc
    judge "Pemberdayaan Sertifikat"
  else
    mkdir /ssl
    cp -a $cert_dir/self_signed_cert.pem /ssl/xray.crt
    cp -a $cert_dir/self_signed_key.pem /ssl/xray.key
    ssl_install
    acme
  fi

  # Xray 默认以 nobody 用户运行，证书权限适配
  chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    signedcert=$(xray tls cert -domain="$local_ipv6" -name="$local_ipv6" -org="$local_ipv6" -expire=87600h)
  else
    signedcert=$(xray tls cert -domain="$local_ipv4" -name="$local_ipv4" -org="$local_ipv4" -expire=87600h)
  fi
  echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
  echo $signedcert | jq '.key[]' | sed 's/\"//g' >$cert_dir/self_signed_key.pem
  openssl x509 -in $cert_dir/self_signed_cert.pem -noout || (print_error "Gagal menghasilkan sertifikat yang ditandatangani sendiri" && exit 1)
  print_ok "Sertifikat yang ditandatangani sendiri berhasil dibuat"
  chown nobody.$cert_group $cert_dir/self_signed_cert.pem
  chown nobody.$cert_group $cert_dir/self_signed_key.pem
}

function configure_web() {
  rm -rf /www/xray_web
  mkdir -p /www/xray_web
  print_ok "Apakah akan mengonfigurasi halaman penyamaran？[Y/N]"
  read -r webpage
  case $webpage in
  [yY][eE][sS] | [yY])
    wget -O web.tar.gz https://raw.githubusercontent.com/wulabing/Xray_onekey/main/basic/web.tar.gz
    tar xzf web.tar.gz -C /www/xray_web
    judge "Kamuflase situs"
    rm -f web.tar.gz
    ;;
  *) ;;
  esac
}

function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  rm -rf $website_dir
  print_ok "Apakah akan menghapus instalasi nginx [Y/N]?"
  read -r uninstall_nginx
  case $uninstall_nginx in
  [yY][eE][sS] | [yY])
    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
      yum remove nginx -y
    else
      apt purge nginx -y
    fi
    ;;
  *) ;;
  esac
  print_ok "Apakah akan menghapus instalasi acme.sh [Y/N]?"
  read -r uninstall_acme
  case $uninstall_acme in
  [yY][eE][sS] | [yY])
    "$HOME"/.acme.sh/acme.sh --uninstall
    rm -rf /root/.acme.sh
    rm -rf /ssl/
    ;;
  *) ;;
  esac
  print_ok "Pencopotan pemasangan selesai"
  exit 0
}

function restart_all() {
  systemctl restart nginx
  judge "Nginx aktifkan (sebuah rencana)"
  systemctl restart xray
  judge "Xray aktifkan (sebuah rencana)"
}

function vless_xtls-rprx-vision_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "URL link (VLESS + TCP + TLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls&flow=$FLOW#TLS_wulabing-$DOMAIN"

  print_ok "URL link (VLESS + TCP + XTLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "URL barcode (VLESS + TCP + TLS) （Silakan kunjungi di browser Anda）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%26flow=$FLOW%23TLS_wulabing-$DOMAIN"

  print_ok "URL barcode (VLESS + TCP + XTLS) （Silakan kunjungi di browser Anda）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"
}

function vless_xtls-rprx-vision_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Xray informasi konfigurasi ${Font}"
  echo -e "${Red} alamat（address）:${Font}  $DOMAIN"
  echo -e "${Red} pelabuhan（port）：${Font}  $PORT"
  echo -e "${Red} pengguna ID（UUID）：${Font} $UUID"
  echo -e "${Red} kontrol aliran（flow）：${Font} $FLOW"
  echo -e "${Red} metode enkripsi（security）：${Font} none "
  echo -e "${Red} protokol transportasi（network）：${Font} tcp "
  echo -e "${Red} Jenis kamuflase（type）：${Font} none "
  echo -e "${Red} Keamanan Transportasi：${Font} xtls 或 tls"
}

function ws_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Xray informasi konfigurasi ${Font}"
  echo -e "${Red} alamat（address）:${Font}  $DOMAIN"
  echo -e "${Red} pelabuhan（port）：${Font}  $PORT"
  echo -e "${Red} pengguna ID（UUID）：${Font} $UUID"
  echo -e "${Red} metode enkripsi（security）：${Font} none "
  echo -e "${Red} protokol transportasi（network）：${Font} ws "
  echo -e "${Red} Jenis kamuflase（type）：${Font} none "
  echo -e "${Red} path（path）：${Font} $WS_PATH "
  echo -e "${Red} Keamanan Transportasi：${Font} tls "
}

function ws_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "URL link (VLESS + TCP + TLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls#TLS_wulabing-$DOMAIN"

  print_ok "URL link (VLESS + TCP + XTLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"

  print_ok "URL link (VLESS + WebSocket + TLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?type=ws&security=tls&path=%2f${WS_PATH_WITHOUT_SLASH}%2f#WS_TLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "URL barcode (VLESS + TCP + TLS) （Silakan kunjungi di browser Anda）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%23TLS_wulabing-$DOMAIN"

  print_ok "URL barcode (VLESS + TCP + XTLS) （Silakan kunjungi di browser Anda）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"

  print_ok "URL barcode (VLESS + WebSocket + TLS) （Silakan kunjungi di browser Anda）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?type=ws%26security=tls%26path=%2f${WS_PATH_WITHOUT_SLASH}%2f%23WS_TLS_wulabing-$DOMAIN"
}

function basic_information() {
  print_ok "VLESS+TCP+XTLS+Nginx Instalasi berhasil"
  vless_xtls-rprx-vision_information
  vless_xtls-rprx-vision_link
}

function basic_ws_information() {
  print_ok "VLESS+TCP+TLS+Nginx with WebSocket Instalasi Mode Campuran Berhasil"
  ws_information
  print_ok "————————————————————————"
  vless_xtls-rprx-vision_information
  ws_link
}

function show_access_log() {
  [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${RedBG}log File tidak ada${Font}"
}

function show_error_log() {
  [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${RedBG}log File tidak ada${Font}"
}

function bbr_boost_sh() {
  [ -f "tcp.sh" ] && rm -rf ./tcp.sh
  wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

function mtproxy_sh() {
  wget -N --no-check-certificate "https://github.com/wulabing/mtp/raw/master/mtproxy.sh" && chmod +x mtproxy.sh && bash mtproxy.sh
}

function install_xray() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_information
}
function install_xray_ws() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray_ws
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_ws_information
}
menu() {
  update_sh
  shell_mode_check
  echo -e "\t Xray Skrip Manajemen Instalasi ${Red}[${shell_version}]${Font}"
  echo -e "\t---authored by wulabing---"
  echo -e "\thttps://github.com/wulabing\n"

  echo -e "Versi yang saat ini diinstal：${shell_mode}"
  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}0.${Font}  Tingkatkan Skrip"
  echo -e "${Green}1.${Font}  pemasangan Xray (VLESS + TCP + XTLS / TLS + Nginx)"
  echo -e "${Green}2.${Font}  pemasangan Xray (VLESS + TCP + XTLS / TLS + Nginx hingga VLESS + TCP + TLS + Nginx + WebSocket Pola kemunduran dan pola yang hidup berdampingan)"
  echo -e "—————————————— Perubahan konfigurasi ——————————————"
  echo -e "${Green}11.${Font} memodifikasi UUID"
  echo -e "${Green}13.${Font} memodifikasi port koneksi"
  echo -e "${Green}14.${Font} memodifikasi WebSocket PATH"
  echo -e "—————————————— Lihat Informasi ——————————————"
  echo -e "${Green}21.${Font} Lihat Log Akses Langsung"
  echo -e "${Green}22.${Font} Melihat log kesalahan waktu nyata"
  echo -e "${Green}23.${Font} Lihat Tautan Konfigurasi Xray"
  #    echo -e "${Green}23.${Font}  查看 V2Ray 配置信息"
  echo -e "—————————————— Opsi lainnya ——————————————"
  echo -e "${Green}31.${Font} Pemasangan BBR 4-in-1, Skrip Pemasangan yang Tajam"
  echo -e "${Yellow}32.${Font} pemasangan MTproxy （Tidak disarankan, harap nonaktifkan atau hapus instalan untuk pengguna yang relevan.）"
  echo -e "${Green}33.${Font} pencopotan pemasangan Xray"
  echo -e "${Green}34.${Font} perbarui Xray-core"
  echo -e "${Green}35.${Font} pemasangan Xray-core versi beta (Pre)"
  echo -e "${Green}36.${Font} Memperbarui Sertifikat SSL Secara Manual"
  echo -e "${Green}40.${Font} batalkan"
  read -rp "Silakan masukkan nomor：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    install_xray_ws
    ;;
  11)
    read -rp "Silakan masukkan UUID:" UUID
    if [[ ${shell_mode} == "tcp" ]]; then
      modify_UUID
    elif [[ ${shell_mode} == "ws" ]]; then
      modify_UUID
      modify_UUID_ws
    fi
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    if [[ ${shell_mode} == "ws" ]]; then
      read -rp "Silakan masuk ke jalur(contoh：/wulabing/ Membutuhkan kedua sisi untuk memuat /):" WS_PATH
      modify_fallback_ws
      modify_ws
      restart_all
    else
      print_error "Model saat ini tidak Websocket pola pikir (paradigma)"
    fi
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "xray File konfigurasi tidak ada"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  32)
    mtproxy_sh
    ;;
  33)
    source '/etc/os-release'
    xray_uninstall
    ;;
  34)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  35)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  36)
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "Masukkan nomor yang benar"
    ;;
  esac
}
menu "$@"
