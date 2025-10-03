#!/bin/bash
#
# vsftpd_setup.sh - Скрипт автоматической установки и настройки vsftpd
# Описание: Полная настройка FTP-сервера с использованием SSL/TLS, управление пользователями, настройка брандмауэра
# Автор: saym101
# Версия: 2.9
# Лицензия: MIT
# Репозиторий: https://github.com/yourusername/vsftpd-setup
#
# Функции:
# - Автоматическая установка vsftpd
# - Настройка SSL / TLS
# - Управление пользователями (добавление / удаление / список)
# - Настройка брандмауэра (UFW)
# - Управление службами
# - Просмотр журналов

set -euo pipefail

# ============================================================================
# ОБРАБОТКА ПАРАМЕТРОВ КОМАНДНОЙ СТРОКИ
# ============================================================================

# Обработка аргументов командной строки
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -v|--version)
            show_version
            exit 0
            ;;
        -i|--install)
            AUTO_INSTALL="yes"
            shift
            ;;
        -u|--user)
            FTP_USER="$2"
            shift 2
            ;;
        -p|--password)
            FTP_PASS="$2"
            shift 2
            ;;
        -y|--yes)
            AUTO_YES="yes"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# ============================================================================
# КОНСТАНТЫ И ПЕРЕМЕННЫЕ
# ============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly CONFIG_FILE="/etc/vsftpd.conf"
readonly CONFIG_BACKUP="/etc/vsftpd.conf.$(date +%Y%m%d-%H%M%S).bak"
readonly USERLIST_FILE="/etc/vsftpd/vsftpd.userlist"
readonly SHARED_DIR="/srv/ftp-user"
readonly SSL_DIR="/etc/vsftpd/ssl"
readonly LOG_FILE="$SCRIPT_DIR/vsftpd_setup.log"
readonly INFO_FILE="$SCRIPT_DIR/vsftpd_setup_info.txt"
readonly INSTALL_MARKER="/etc/vsftpd/.vsftpd_setup_installed"
readonly VSFTPD_USERS="/etc/vsftpd/users"
readonly PAM_FILE="/etc/pam.d/vsftpd"

# Порты для пассивного режима
PASV_MIN_PORT="${PASV_MIN_PORT:-40000}"
PASV_MAX_PORT="${PASV_MAX_PORT:-50000}"

# Переменные для настроек
PASV_ADDRESS=""
ENABLE_SSL="yes"  # По умолчанию включаем SSL
FTP_USER=""
FTP_PASS=""

# Переменные для неинтерактивного режима
AUTO_INSTALL="${AUTO_INSTALL:-no}"
AUTO_YES="${AUTO_YES:-no}"

# Цвета для вывода
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m' # No Color

# ============================================================================
# ФУНКЦИИ ВЫВОДА
# ============================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $*" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "\n${GREEN}=== $* ===${NC}\n"
}

# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

show_usage() {
    cat << 'EOF'
Usage: ./vsftpd_setup.sh [OPTIONS]

Automated vsftpd installation and configuration script for Debian/Ubuntu

Options:
  -h, --help          Show this help message
  -v, --version       Show version information
  -i, --install       Run installation non-interactively with default settings
  -u, --user USER     Create FTP user non-interactively
  -p, --password PASS Set password for user (if not specified, generates random)
  -y, --yes           Auto-confirm all prompts

Examples:
  ./vsftpd_setup.sh                    # Interactive mode
  ./vsftpd_setup.sh --install          # Auto-install with defaults
  ./vsftpd_setup.sh -u myuser -p pass123 # Create user non-interactively
  ./vsftpd_setup.sh -u myuser          # Create user with random password

EOF
}

show_version() {
    echo "vsftpd_setup.sh version 2.9"
    echo "Automated vsftpd installation and configuration script"
}

create_dir() {
    mkdir -p "$SSL_DIR"
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        print_error "Требуется команда: $1"
        exit 1
    fi
}

check_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        print_error "Скрипт необходимо запустить от имени root"
        echo "Используйте: sudo $SCRIPT_NAME"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/debian_version ] && [ ! -f /etc/lsb-release ]; then
        print_error "Этот скрипт поддерживает только Debian/Ubuntu системы"
        exit 1
    fi
}

check_installation() {
    # Проверяем наличие маркера установки и работу службы
    if [ -f "$INSTALL_MARKER" ] && systemctl is-active --quiet vsftpd 2>/dev/null; then
        return 0  # Установлено
    else
        return 1  # Не установлено
    fi
}

detect_external_ip() {
    local ip=""
    
    # Попытка определить внешний IP
    if command -v curl >/dev/null 2>&1; then
        ip=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "")
    fi
    
    if [ -z "$ip" ] && command -v wget >/dev/null 2>&1; then
        ip=$(wget -qO- --timeout=5 ifconfig.me 2>/dev/null || echo "")
    fi
    
    if [ -z "$ip" ]; then
        ip=$(hostname -I | awk '{print $1}')
    fi
    
    echo "$ip"
}

show_main_menu() {
    clear
    cat <<'EOF'
╔════════════════════════════════════════════════════════════════════════════╗
║  Дополнительная информация: man vsftpd.conf                                ║
║  Поддержка: https://security.appspot.com/vsftpd.html                       ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
    echo
}

# ============================================================================
# ОСНОВНЫЕ ФУНКЦИИ
# ============================================================================

install_packages() {
    print_header "Установка необходимых пакетов"
    
    need_cmd apt
    need_cmd systemctl
    
    print_info "Обновление списка пакетов..."
    apt update -y >> "$LOG_FILE" 2>&1
    
    print_info "Установка vsftpd и openssl..."
    apt install -y --no-install-recommends vsftpd openssl ssl-cert >> "$LOG_FILE" 2>&1
    
    print_success "Пакеты установлены"
}

configure_pam() {
    print_header "Настройка PAM для vsftpd"
    
    cat > "$PAM_FILE" << 'EOF'
# Standard behaviour for ftpd(8).
auth	required	pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed

# Note: vsftpd handles anonymous logins on its own. Do not enable pam_ftp.so.

# Standard pam includes
@include common-account
@include common-session
@include common-auth
# auth required pam_shells.so - ЗАКОММЕНТИРОВАНО для работы с nologin shell
auth    required    pam_unix.so
account required    pam_unix.so
session required    pam_unix.so
EOF

    print_success "PAM конфигурация обновлена (исправлена работа с nologin shell)"
}

backup_config() {
    print_header "Резервное копирование конфигурации"
    
    if [ -f "$CONFIG_FILE" ]; then
        cp -a "$CONFIG_FILE" "$CONFIG_BACKUP"
        print_success "Резервная копия создана: $CONFIG_BACKUP"
    else
        print_warning "Конфигурационный файл не найден (первая установка)"
    fi
}

ask_pasv_address() {
    print_header "Настройка пассивного режима"
    
    local detected_ip
    detected_ip=$(detect_external_ip)
    
    if [ -n "$detected_ip" ]; then
        print_info "Обнаружен IP-адрес: $detected_ip"
    fi
    
    read -r -p "Укажите внешний IP или домен для работы через NAT\шлюз. Для работы в локальной сети не нужен. (Enter = пропустить): " PASV_ADDRESS
    
    if [ -n "${PASV_ADDRESS// }" ]; then
        print_success "Будет использован адрес: $PASV_ADDRESS"
    else
        print_warning "Пассивный адрес не указан (может не работать через NAT)"
    fi
}

ssl_configure() {
    print_header "Настройка SSL/TLS (FTPS)"
    
    read -r -p "Включить SSL/TLS для защищенного соединения? (yes/no, default: yes): " ENABLE_SSL
    ENABLE_SSL=${ENABLE_SSL:-yes}
    
    if [ "$ENABLE_SSL" != "yes" ]; then
        print_info "SSL/TLS не будет использоваться"
        return
    fi
    
    print_info "Использование системного SSL сертификата..."
    
    # Проверяем наличие системного сертификата
    if [ ! -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" ]; then
        print_warning "Системный SSL сертификат не найден, генерируем новый..."
        make-ssl-cert generate-default-snakeoil --force-override
    fi
    
    print_success "SSL/TLS будет использовать системный сертификат"
}

create_config() {
    print_header "Создание конфигурации vsftpd"
    
    local ssl_block=""
    if [ "$ENABLE_SSL" = "yes" ]; then
        ssl_block=$(cat <<'EOF'
# SSL настройки
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=YES
EOF
)
    else
        ssl_block="ssl_enable=NO"
    fi
    
    local pasv_address_line=""
    if [ -n "$PASV_ADDRESS" ]; then
        pasv_address_line="pasv_address=$PASV_ADDRESS"
    fi
    
cat > "$CONFIG_FILE" <<EOF
# ============================================================================
# Конфигурация vsftpd
# Создано автоматически: $(date)
# Скрипт: $SCRIPT_NAME
# ============================================================================

# --- Основные настройки ---
listen=YES
listen_ipv6=NO

# --- Безопасность ---
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022

# --- Сообщения и логи ---
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=YES

# --- Chroot (изоляция пользователей) ---
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty

# --- PAM ---
pam_service_name=vsftpd

# --- Список разрешенных пользователей ---
userlist_enable=YES
userlist_file=$USERLIST_FILE
userlist_deny=NO

# --- Пассивный режим ---
pasv_enable=YES
pasv_min_port=$PASV_MIN_PORT
pasv_max_port=$PASV_MAX_PORT
$pasv_address_line
pasv_promiscuous=YES

# --- Директория конфигов пользователей ---
user_config_dir=$VSFTPD_USERS

$ssl_block

# --- Дополнительные настройки ---
dual_log_enable=YES
seccomp_sandbox=NO
max_clients=50
max_per_ip=5

# --- Таймауты ---
idle_session_timeout=600
data_connection_timeout=120

EOF

    print_success "Конфигурационный файл создан: $CONFIG_FILE"
}

setup_directories() {
    print_header "Создание директорий"
    
    # Создаем userlist файл
    mkdir -p "$(dirname "$USERLIST_FILE")"
    touch "$USERLIST_FILE"
    print_success "Создан файл списка пользователей: $USERLIST_FILE"
    
    # Создаем общую директорию
    mkdir -p "$SHARED_DIR"
    chmod 755 "$SHARED_DIR"
    chown root:ftp "$SHARED_DIR"
    print_success "Создана общая директория: $SHARED_DIR"
    
    # Создаем директорию для конфигов пользователей
    mkdir -p "$VSFTPD_USERS"
    print_success "Создана директория для конфигов пользователей: $VSFTPD_USERS"
    
    # Проверяем наличие secure_chroot_dir
    if [ ! -d "/var/run/vsftpd/empty" ]; then
        mkdir -p "/var/run/vsftpd/empty"
        chmod 755 "/var/run/vsftpd/empty"
        print_success "Создана директория для chroot: /var/run/vsftpd/empty"
    fi
}

restart_service() {
    print_header "Перезапуск службы vsftpd"
    
    systemctl daemon-reload
    systemctl enable vsftpd >> "$LOG_FILE" 2>&1
    systemctl restart vsftpd
    
    sleep 2
    
    if systemctl is-active --quiet vsftpd; then
        print_success "Служба vsftpd запущена и работает"
    else
        print_error "Служба vsftpd не запустилась. Проверьте логи: journalctl -xeu vsftpd"
        exit 1
    fi
}

add_ftp_user_interactive() {
    print_header "Добавление FTP-пользователя"
    
    # Сбрасываем переменные перед созданием пользователя
    FTP_USER=""
    FTP_PASS=""
    
    create_ftp_user
    
    # Перезапускаем vsftpd для применения изменений
    systemctl restart vsftpd
    print_success "Служба vsftpd перезапущена"
    
    # Сохраняем информацию о новом пользователе
    save_user_info
    
    local user_info_file="$SCRIPT_DIR/${FTP_USER}_info.txt"
    
    print_success "Пользователь успешно добавлен!"
    echo
    print_info "Информация о пользователе сохранена в: $user_info_file"
    echo
    
    # Показываем информацию о пользователе
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 ДАННЫЕ НОВОГО ПОЛЬЗОВАТЕЛЯ                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo "  Имя пользователя: $FTP_USER"
    echo "  Пароль:           $FTP_PASS"
    echo "  Директория:       $SHARED_DIR/$FTP_USER"
    echo "  Протокол:         $([ "$ENABLE_SSL" = "yes" ] && echo "FTPS" || echo "FTP")"
    echo
    echo "  Файл с данными:   $user_info_file"
    echo
    print_warning "ЗАПИШИТЕ пароль! Он больше не будет показан!"
    echo
    
    read -r -p "Нажмите Enter для возврата в меню..."
}

generate_password() {
    # Генерация случайного пароля из 12 символов
    # Включает: большие буквы, маленькие буквы, цифры и спецсимволы
    local password=""
    password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' < /dev/urandom | head -c 12)
    echo "$password"
}

create_ftp_user() {
    print_header "Создание FTP-пользователя"

    while true; do
        read -r -p "Имя пользователя: " FTP_USER
        
        # Проверка на пустое имя
        if [ -z "$FTP_USER" ]; then
            print_error "Имя пользователя не может быть пустым"
            continue
        fi
        
        # Проверка на латинские символы и цифры
        if [[ ! "$FTP_USER" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            print_error "Имя пользователя может содержать только:"
            echo "  - Латинские буквы (a-z, A-Z)"
            echo "  - Цифры (0-9)"
            echo "  - Символы: _ -"
            echo "  НЕ используйте кириллицу, пробелы или специальные символы!"
            continue
        fi
        
        # Проверка длины имени
        if [ ${#FTP_USER} -lt 2 ]; then
            print_error "Имя пользователя должно быть не менее 2 символов"
            continue
        fi
        
        if [ ${#FTP_USER} -gt 32 ]; then
            print_error "Имя пользователя должно быть не более 32 символов"
            continue
        fi
        
        # Проверка существования пользователя
        if id "$FTP_USER" >/dev/null 2>&1; then
            print_warning "Пользователь $FTP_USER уже существует"
            read -r -p "Использовать существующего пользователя? (yes/no): " USE_EXISTING
            if [ "$USE_EXISTING" = "yes" ]; then
                break
            else
                continue
            fi
        else
            break
        fi
    done

    # Генерация пароля автоматически
    FTP_PASS=$(generate_password)
    print_info "Генерация случайного пароля..."
    print_success "Пароль сгенерирован: $FTP_PASS"
    echo
    print_warning "ЗАПИШИТЕ этот пароль! Он больше не будет показан!"
    echo

    # Создание пользователя
    if ! id "$FTP_USER" >/dev/null 2>&1; then
        useradd -m -s /usr/sbin/nologin "$FTP_USER"
        print_success "Пользователь $FTP_USER создан"
    fi

    echo "$FTP_USER:$FTP_PASS" | chpasswd
    print_success "Пароль установлен"

    # Создаем личную директорию пользователя
    local user_dir="$SHARED_DIR/$FTP_USER"
    mkdir -p "$user_dir"
    chown "$FTP_USER":ftp "$user_dir"
    chmod 750 "$user_dir"
    print_success "Домашняя директория создана: $user_dir"

    # Добавляем пользователя в userlist
    if ! grep -qx "$FTP_USER" "$USERLIST_FILE" 2>/dev/null; then
        echo "$FTP_USER" >> "$USERLIST_FILE"
        print_success "Пользователь добавлен в список разрешенных"
    fi

    # Создаем конфиг пользователя
    local user_config_file="$VSFTPD_USERS/$FTP_USER"
    cat > "$user_config_file" << EOF
local_root=$SHARED_DIR/$FTP_USER
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
EOF

    print_success "Конфигурация пользователя создана: $user_config_file"
    
    # Сохраняем пароль в временный файл для отображения в summary
    local temp_pass_file="/tmp/ftp_pass_${FTP_USER}.tmp"
    echo "$FTP_PASS" > "$temp_pass_file"
    chmod 600 "$temp_pass_file"
}

remove_ftp_user_interactive() {
    print_header "Удаление FTP-пользователя"
    
    # Показываем список пользователей
    if [ ! -f "$USERLIST_FILE" ] || [ ! -s "$USERLIST_FILE" ]; then
        print_warning "Нет зарегистрированных FTP-пользователей"
        read -r -p "Нажмите Enter для возврата в меню..."
        return
    fi
    
    # Получаем список пользователей в массив
    local users=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && users+=("$user")
    done < "$USERLIST_FILE"
    
    local total_users=${#users[@]}
    
    echo "Текущие FTP-пользователи: $total_users"
    echo "─────────────────────────"
    
    # Определяем количество столбцов
    local columns=1
    if [ $total_users -gt 50 ]; then
        columns=5
    elif [ $total_users -gt 30 ]; then
        columns=4
    elif [ $total_users -gt 15 ]; then
        columns=3
    elif [ $total_users -gt 5 ]; then
        columns=2
    fi

    # Вычисляем количество строк на столбец
    local rows=$(( (total_users + columns - 1) / columns ))

    # Выводим в несколько столбцов
    for ((i=0; i<rows; i++)); do
        for ((j=0; j<columns; j++)); do
            local index=$((i + j * rows))
            if [ $index -lt $total_users ]; then
                printf "  %-3d %-20s" $((index + 1)) "${users[index]}"
            fi
        done
        echo
    done
    
    echo
    echo "─────────────────────────"
    read -r -p "Введите НОМЕР пользователя для удаления (0 для отмены) [0]: " user_number
    user_number=${user_number:-0}  # По умолчанию 0 (отмена)
    
    # Проверка на отмену
    if [ "$user_number" = "0" ]; then
        print_info "Удаление отменено"
        read -r -p "Нажмите Enter для возврата в меню..."
        return
    fi
    
    # Проверка валидности номера
    if ! [[ "$user_number" =~ ^[0-9]+$ ]] || [ "$user_number" -lt 1 ] || [ "$user_number" -gt "$total_users" ]; then
        print_error "Неверный номер пользователя. Допустимые значения: 1-$total_users"
        read -r -p "Нажмите Enter для возврата в меню..."
        return
    fi
    
    # Получаем имя пользователя по номеру
    local DEL_USER="${users[$((user_number-1))]}"
    
    echo
    print_warning "Будут выполнены следующие действия:"
    echo "  - Удаление пользователя $DEL_USER ($user_number) из системы"
    echo "  - Удаление из списка разрешенных ($USERLIST_FILE)"
    echo "  - Удаление конфигурационного файла"
    echo "  - Домашняя директория $SHARED_DIR/$DEL_USER будет сохранена"
    echo
    read -r -p "Продолжить удаление? (yes/no) [no]: " CONFIRM
    CONFIRM=${CONFIRM:-no}  # По умолчанию no
    
    if [ "$CONFIRM" != "yes" ]; then
        print_info "Отменено пользователем"
        read -r -p "Нажмите Enter для возврата в меню..."
        return
    fi
    
    # Удаляем из userlist
    sed -i "/^${DEL_USER}$/d" "$USERLIST_FILE"
    print_success "Удален из списка разрешенных"
    
    # Удаляем конфиг пользователя
    rm -f "$VSFTPD_USERS/$DEL_USER"
    print_success "Конфигурационный файл удален"
    
    # Удаляем системного пользователя
    if id "$DEL_USER" >/dev/null 2>&1; then
        userdel "$DEL_USER" 2>/dev/null || true
        print_success "Системный пользователь удален"
    fi
    
    print_success "Пользователь $DEL_USER ($user_number) успешно удален"
    print_info "Домашняя директория сохранена: $SHARED_DIR/$DEL_USER"
    
    # Перезапускаем vsftpd
    systemctl restart vsftpd
    print_success "Служба vsftpd перезапущена"
    
    echo
    read -r -p "Нажмите Enter для возврата в меню..."
}

configure_firewall() {
    print_header "Настройка межсетевого экрана (UFW)"
    
    if ! command -v ufw >/dev/null 2>&1; then
        read -r -p "UFW не установлен. Установить? (yes/no, default: no): " INSTALL_UFW
        INSTALL_UFW=${INSTALL_UFW:-no}
        
        if [ "$INSTALL_UFW" != "yes" ]; then
            print_info "Настройка firewall пропущена"
            return
        fi
        
        apt install -y ufw >> "$LOG_FILE" 2>&1
        print_success "UFW установлен"
    fi
    
    read -r -p "Настроить UFW для FTP? (yes/no, default: no): " CONFIGURE_UFW
    CONFIGURE_UFW=${CONFIGURE_UFW:-no}
    
    if [ "$CONFIGURE_UFW" != "yes" ]; then
        print_info "Настройка UFW пропущена"
        return
    fi
    
    # Проверяем текущие правила
    print_info "Текущие правила UFW:"
    ufw status numbered | head -20
    
    echo
    print_info "Добавление правил для FTP..."
    
    # Базовые FTP порты
    ufw allow 20/tcp comment 'FTP data' >> "$LOG_FILE" 2>&1
    ufw allow 21/tcp comment 'FTP control' >> "$LOG_FILE" 2>&1
    ufw allow ${PASV_MIN_PORT}:${PASV_MAX_PORT}/tcp comment 'FTP passive' >> "$LOG_FILE" 2>&1
    
    # Проверяем и добавляем SSH порт
    local ssh_port=""
    if ufw status | grep -q "22/tcp.*ALLOW"; then
        print_info "SSH порт 22/tcp уже разрешен"
    else
        # Проверяем какой SSH порт используется
        if ss -tlnp | grep -q ":22 "; then
            ufw allow 22/tcp comment 'SSH' >> "$LOG_FILE" 2>&1
            print_info "Добавлен SSH порт 22/tcp"
        else
            # Ищем нестандартный SSH порт
            ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
            if [ -n "$ssh_port" ] && [ "$ssh_port" != "22" ]; then
                print_warning "Обнаружен нестандартный SSH порт: $ssh_port"
                ufw allow ${ssh_port}/tcp comment 'SSH custom' >> "$LOG_FILE" 2>&1
                print_info "Добавлен SSH порт ${ssh_port}/tcp"
            else
                ufw allow OpenSSH comment 'SSH' >> "$LOG_FILE" 2>&1
                print_info "Добавлен стандартный SSH (OpenSSH)"
            fi
        fi
    fi
    
    # Запрос дополнительных портов
    echo
    print_info "Добавление дополнительных портов (опционально)"
    read -r -p "Добавить дополнительные порты? (yes/no, default: no): " ADD_MORE_PORTS
    
    if [ "$ADD_MORE_PORTS" = "yes" ]; then
        while true; do
            echo
            read -r -p "Введите порт или диапазон (например: 80 или 8000:8010) или 'done' для завершения: " port_input
            
            if [ "$port_input" = "done" ] || [ "$port_input" = "" ]; then
                break
            fi
            
            # Проверяем валидность порта
            if [[ "$port_input" =~ ^[0-9]+(:[0-9]+)?$ ]]; then
                read -r -p "Комментарий для порта $port_input: " port_comment
                port_comment=${port_comment:-"Custom port"}
                
                ufw allow "$port_input/tcp" comment "$port_comment" >> "$LOG_FILE" 2>&1
                print_success "Добавлен порт $port_input/tcp: $port_comment"
            else
                print_error "Некорректный формат порта: $port_input"
            fi
        done
    fi
    
    print_success "Правила UFW добавлены"
    
    # Показываем итоговые правила
    echo
    print_info "Итоговые правила UFW:"
    ufw status numbered
    
    # Включение UFW
    if ! ufw status | grep -q "Status: active"; then
        echo
        read -r -p "Включить UFW сейчас? (yes/no, default: no): " ENABLE_UFW
        ENABLE_UFW=${ENABLE_UFW:-no}
        
        if [ "$ENABLE_UFW" = "yes" ]; then
            print_warning "ВНИМАНИЕ: UFW будет включен. Убедитесь, что SSH порт разрешен!"
            echo "Текущие разрешенные SSH порты:"
            ufw status | grep -E "(ssh|SSH|22|${ssh_port})"
            echo
            read -r -p "Продолжить включение UFW? (yes/no): " CONFIRM_ENABLE
            
            if [ "$CONFIRM_ENABLE" = "yes" ]; then
                ufw --force enable >> "$LOG_FILE" 2>&1
                print_success "UFW включен"
                
                # Тестовое подключение к SSH
                echo
                print_info "Проверка SSH подключения..."
                if timeout 5 bash -c "echo > /dev/tcp/localhost/${ssh_port:-22}" 2>/dev/null; then
                    print_success "SSH порт ${ssh_port:-22} доступен"
                else
                    print_warning "Не удалось проверить SSH порт. Убедитесь, что он разрешен в UFW!"
                fi
            else
                print_info "UFW не включен. Включите позже: sudo ufw enable"
            fi
        else
            print_info "UFW не включен. Включите позже: sudo ufw enable"
        fi
    else
        print_success "UFW уже активен"
        
        # Перезагрузка правил
        ufw reload >> "$LOG_FILE" 2>&1
        print_success "Правила UFW применены"
    fi
}

list_ftp_users() {
    print_header "Список FTP-пользователей"

    if [ ! -f "$USERLIST_FILE" ] || [ ! -s "$USERLIST_FILE" ]; then
        print_warning "Список пользователей пуст или отсутствует"
        echo
        read -r -p "Нажмите Enter для возврата в меню..."
        return
    fi

    # Получаем список пользователей
    local users=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && users+=("$user")
    done < "$USERLIST_FILE"

    local total_users=${#users[@]}
    
    echo "Текущие FTP-пользователи: $total_users"
    echo "─────────────────────────"

    # Определяем количество столбцов в зависимости от количества пользователей
    local columns=1
    if [ $total_users -gt 50 ]; then
        columns=5
    elif [ $total_users -gt 30 ]; then
        columns=4
    elif [ $total_users -gt 15 ]; then
        columns=3
    elif [ $total_users -gt 5 ]; then
        columns=2
    fi

    # Вычисляем количество строк на столбец
    local rows=$(( (total_users + columns - 1) / columns ))

    # Выводим в несколько столбцов
    for ((i=0; i<rows; i++)); do
        for ((j=0; j<columns; j++)); do
            local index=$((i + j * rows))
            if [ $index -lt $total_users ]; then
                printf "  %-3d %-20s" $((index + 1)) "${users[index]}"
            fi
        done
        echo
    done

    echo
    echo "Выберите действие:"
    echo "  1) Добавить FTP-пользователя"
    echo "  2) Удалить FTP-пользователя" 
    echo "  0) Вернуться в главное меню (по умолчанию)"
    echo

    while true; do
        read -r -p "Ваш выбор [0]: " choice
        choice=${choice:-0}  # По умолчанию 0
        case "$choice" in
            1)
                add_ftp_user_interactive
                break
                ;;
            2)
                remove_ftp_user_interactive
                break
                ;;
            0)
                break
                ;;
            *)
                echo "Неверный выбор. Попробуйте еще раз."
                ;;
        esac
    done
}

save_user_info() {
    if [ -z "$FTP_USER" ] || [ -z "$FTP_PASS" ]; then
        print_error "Ошибка: не указаны данные пользователя для сохранения"
        return 1
    fi
    
    local user_info_file="$SCRIPT_DIR/${FTP_USER}_info.txt"
    local external_ip
    external_ip=$(detect_external_ip)
    
    local protocol="ftp"
    if [ "$ENABLE_SSL" = "yes" ]; then
        protocol="ftps"
    fi
    
    local user_info
    user_info=$(cat <<EOF
╔════════════════════════════════════════════════════════════════════════════╗
║                      ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ FTP                            ║
╚════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────┐
│ УЧЕТНЫЕ ДАННЫЕ ПОЛЬЗОВАТЕЛЯ                                              │
└─────────────────────────────────────────────────────────────────────────┘
  Имя пользователя:   $FTP_USER
  Пароль:             $FTP_PASS

┌─────────────────────────────────────────────────────────────────────────┐
│ ПАРАМЕТРЫ ПОДКЛЮЧЕНИЯ                                                    │
└─────────────────────────────────────────────────────────────────────────┘
  Протокол:           ${protocol^^}
  Адрес сервера:      ${external_ip:-$(hostname -I | awk '{print $1}')}
  Порт:               21
  Пассивные порты:    $PASV_MIN_PORT-$PASV_MAX_PORT
  SSL/TLS:            $([ "$ENABLE_SSL" = "yes" ] && echo "Включен (обязательно)" || echo "Отключен")

┌─────────────────────────────────────────────────────────────────────────┐
│ НАСТРОЙКА В FILEZILLA                                                    │
└─────────────────────────────────────────────────────────────────────────┘
  Хост:       ${external_ip:-$(hostname -I | awk '{print $1}')}
  Протокол:   $([ "$ENABLE_SSL" = "yes" ] && echo "FTPS (явный FTP через TLS)" || echo "FTP")
  Режим:      Пассивный (Passive)
  Имя:        $FTP_USER
  Пароль:     $FTP_PASS
  Порт:       21

┌─────────────────────────────────────────────────────────────────────────┐
│ ВАЖНАЯ ИНФОРМАЦИЯ                                                        │
└─────────────────────────────────────────────────────────────────────────┘

$([ "$ENABLE_SSL" = "yes" ] && echo "  ⚠ ВНИМАНИЕ: Используется самоподписанный сертификат. В FTP-клиенте нужно
     принять сертификат при первом подключении." || echo "  ⚠ ВНИМАНИЕ: SSL/TLS отключен. Данные передаются в открытом виде!")

╔════════════════════════════════════════════════════════════════════════════╗
║  СОХРАНИТЕ ЭТИ ДАННЫЕ В БЕЗОПАСНОМ МЕСТЕ!                                  ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
)
    
    echo "$user_info" > "$user_info_file"
    chmod 600 "$user_info_file"  # Защищаем файл с паролем
    
    print_success "Данные пользователя сохранены в: $user_info_file"
}

show_summary() {
    print_header "Итоговая информация"
    
    local external_ip
    external_ip=$(detect_external_ip)
    
    local protocol="ftp"
    if [ "$ENABLE_SSL" = "yes" ]; then
        protocol="ftps"
    fi
    
    local summary
    summary=$(cat <<EOF
╔════════════════════════════════════════════════════════════════════════════╗
║                   УСТАНОВКА VSFTPD ЗАВЕРШЕНА УСПЕШНО                      ║
╚════════════════════════════════════════════════════════════════════════════╝

Дата установки: $(date)
Версия vsftpd: $(vsftpd -v 2>&1 | head -n1 || echo "Неизвестно")

┌─────────────────────────────────────────────────────────────────────────┐
│ ПАРАМЕТРЫ ПОДКЛЮЧЕНИЯ                                                    │
└─────────────────────────────────────────────────────────────────────────┘
  Протокол:           ${protocol^^}
  Адрес сервера:      ${external_ip:-$(hostname -I | awk '{print $1}')}
  Порт управления:    21
  Пассивные порты:    $PASV_MIN_PORT-$PASV_MAX_PORT
  SSL/TLS:            $([ "$ENABLE_SSL" = "yes" ] && echo "Включен" || echo "Отключен")

┌─────────────────────────────────────────────────────────────────────────┐
│ ФАЙЛЫ И ДИРЕКТОРИИ                                                       │
└─────────────────────────────────────────────────────────────────────────┘
  Конфигурация:       $CONFIG_FILE
  Резервная копия:    $CONFIG_BACKUP
  Список пользователей: $USERLIST_FILE
  Общая директория:   $SHARED_DIR
  Логи vsftpd:        /var/log/vsftpd.log
  Лог установки:      $LOG_FILE
  Данные пользователей: ${FTP_USER:+${FTP_USER}_info.txt} (создается при добавлении пользователя)

┌─────────────────────────────────────────────────────────────────────────┐
│ ПОЛЕЗНЫЕ КОМАНДЫ                                                         │
└─────────────────────────────────────────────────────────────────────────┘
  Статус службы:      sudo systemctl status vsftpd
  Перезапуск:         sudo systemctl restart vsftpd
  Просмотр логов:     sudo tail -f /var/log/vsftpd.log
  Проверка конфига:   sudo vsftpd -olisten=NO $CONFIG_FILE
  Список пользователей: cat $USERLIST_FILE
  Управление:         sudo $SCRIPT_DIR/$SCRIPT_NAME

┌─────────────────────────────────────────────────────────────────────────┐
│ БЕЗОПАСНОСТЬ                                                             │
└─────────────────────────────────────────────────────────────────────────┘
  ⚠ Убедитесь, что открыты необходимые порты в firewall:
    - TCP 20, 21 (FTP)
    - TCP $PASV_MIN_PORT-$PASV_MAX_PORT (пассивный режим)

  ⚠ Для работы через NAT/роутер настройте проброс портов

$([ "$ENABLE_SSL" = "yes" ] && echo "  ✓ SSL/TLS включен - соединение зашифровано" || echo "  ⚠ SSL/TLS отключен - данные передаются в открытом виде")

╔════════════════════════════════════════════════════════════════════════════╗
║  Дополнительная информация: man vsftpd.conf                                ║
║  Поддержка: https://security.appspot.com/vsftpd.html                       ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
)
    
    echo "$summary"
    echo "$summary" > "$INFO_FILE"
    echo
    echo "Запусти скрипт ещё раз для дополнительных настроек и добавления\удаления пользователей."
    echo
    
    # Если создали пользователя, добавляем его данные в отдельный файл
    if [ -n "$FTP_USER" ]; then
        save_user_info
        print_info "Данные пользователя сохранены в: ${FTP_USER}_info.txt"
    fi
    
    print_success "Итоговая информация сохранена в: $INFO_FILE"
}

uninstall_vsftpd() {
    print_header "Удаление vsftpd"
    
    echo
    print_warning "ВНИМАНИЕ! Будут выполнены следующие действия:"
    echo "  1. Остановка и отключение службы vsftpd"
    echo "  2. Удаление пакета vsftpd"
    echo "  3. Удаление конфигурационных файлов"
    read -r -p "Вы уверены, что хотите продолжить? (yes/no): " CONFIRM_UNINSTALL
    if [ "$CONFIRM_UNINSTALL" != "yes" ]; then
        print_info "Удаление отменено"
        return
    fi

    # Остановка и отключение службы
    systemctl stop vsftpd 2>/dev/null || true
    systemctl disable vsftpd 2>/dev/null || true
    print_success "Служба vsftpd остановлена и отключена"

    # Удаление пакета
    apt remove --purge -y vsftpd >> "$LOG_FILE" 2>&1
    print_success "Пакет vsftpd удалён"

    # Удаление конфигурации
    rm -rf /etc/vsftpd /etc/vsftpd.conf* "$USERLIST_FILE" "$LOG_FILE" "$INSTALL_MARKER" 2>/dev/null || true
    print_success "Конфигурационные файлы удалены"

    print_success "vsftpd полностью удалён"
    read -r -p "Нажмите Enter для возврата в меню..."
}

# ============================================================================
# ГЛАВНОЕ МЕНЮ
# ============================================================================

main_menu() {
    check_os
    check_root
    
    # Обработка неинтерактивного режима
    if [ "$AUTO_INSTALL" = "yes" ]; then
        print_header "Неинтерактивная установка"
        install_packages
        configure_pam
        backup_config
        ssl_configure
        create_config
        setup_directories
        restart_service
        touch "$INSTALL_MARKER"
        show_summary
        exit 0
    fi
    
    if [ -n "$FTP_USER" ]; then
        print_header "Неинтерактивное создание пользователя"
        if [ -z "$FTP_PASS" ]; then
            FTP_PASS=$(generate_password)
        fi
        create_ftp_user
        restart_service
        save_user_info
        show_summary
        exit 0
    fi
    
    # интерактивный режим
    
    if ! check_installation; then
        show_main_menu
        echo "VSFTPD не установлен или не запущен"
        echo "Выберите действие:"
        echo "  1) Установить vsftpd"
        echo "  0) Выход"
        echo
        read -r -p "Ваш выбор: " choice
        case "$choice" in
            1) 
                install_packages
                configure_pam  # КРИТИЧЕСКИ ВАЖНО - исправление PAM
                backup_config
                ask_pasv_address
                ssl_configure
                create_config
                setup_directories
                restart_service
                touch "$INSTALL_MARKER"
                show_summary
                ;;
            0) echo "Выход..."; exit 0 ;;
            *) echo "Неверный выбор. Повторите."; sleep 1; main_menu ;;
        esac
    else
while true; do
    clear
    show_main_menu
    echo "VSFTPD уже установлен и запущен"
    echo "Выберите действие:"
    echo "  1) Добавить FTP-пользователя"
    echo "  2) Удалить FTP-пользователя"
    echo "  3) Вывести список пользователей"
    echo "  4) Настроить firewall (UFW)"
    echo "  5) Перезапустить службу vsftpd"
    echo "  6) Показать статус службы"
    echo "  7) Показать логи службы (journalctl)"
    echo "  8) Показать файл логов vsftpd"
    echo "  9) Удалить сервер vsftpd"
    echo "  0) Выход"
    echo

    read -r -p "Ваш выбор: " choice
    case "$choice" in
        1) add_ftp_user_interactive ;;
        2) remove_ftp_user_interactive ;;
        3) list_ftp_users ;;
        4) configure_firewall ;;
        5)
            restart_service
            echo
            read -r -p "Нажмите Enter для возврата в меню..."
            ;;
        6)
            print_header "Статус службы vsftpd"
            systemctl status vsftpd --no-pager
            echo
            read -r -p "Нажмите Enter для возврата в меню..."
            ;;
        7)
            print_header "Логи службы vsftpd (последние 20 записей)"
            journalctl -xeu vsftpd --no-pager -n 20
            echo
            read -r -p "Нажмите Enter для возврата в меню..."
            ;;
        8)
            print_header "Логи vsftpd (последние 20 строк)"
            tail -n 20 /var/log/vsftpd.log
            echo
            read -r -p "Нажмите Enter для возврата в меню..."
            ;;
        9) uninstall_vsftpd ;;
        0) echo "Выход..."; exit 0 ;;
        *) echo "Неверный выбор. Повторите."; sleep 1 ;;
    esac
done
    fi
}

# ЗАПУСК СКРИПТА
main_menu
