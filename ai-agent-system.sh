#!/bin/bash
# ==============================================================================
# AI SRE Auto-Remediator v3.0 Multi-Server Setup Script
# Google Gemini 2.5 AI 기반 실시간 시스템 장애 탐지 및 다중 서버 모니터링 에이전트
# (Slack & Telegram 듀얼 채널 알림 및 자율 복구 지원)
# 지원 OS: Ubuntu 22.04/24.04 (x86_64, aarch64), Oracle Linux 9 / RHEL 계열
# ==============================================================================

set -e

echo "=========================================================="
echo "🚀 AI SRE Auto-Remediator v3.0 Multi-Server 설치를 시작합니다."
echo "=========================================================="

# 0. OS 감지
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_LIKE=${ID_LIKE:-$ID}
else
    OS_ID="unknown"
    OS_LIKE="unknown"
fi
echo "[*] 감지된 OS: $PRETTY_NAME (ID: $OS_ID, LIKE: $OS_LIKE)"

# 1. 설정 입력 (환경 변수가 기설정되어 있으면 비대화형으로 자동 사용)
if [ -z "$GEMINI_API_KEY" ]; then
    read -p "✔ [필수] Gemini API Key: " GEMINI_API_KEY
fi
if [ -z "$GEMINI_API_KEY" ]; then
    echo "❌ Gemini API Key는 필수입니다. 종료합니다."
    exit 1
fi

GEMINI_MODEL=${GEMINI_MODEL:-gemini-2.5-flash}

# 대화형 실행 시 알림 채널 입력 프롬프트 제공
if [ -t 0 ]; then
    if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
        read -p "✔ Telegram Bot Token (없으면 Enter): " INPUT_TG_TOKEN
        TELEGRAM_BOT_TOKEN=${INPUT_TG_TOKEN:-$TELEGRAM_BOT_TOKEN}
    fi
    if [ -z "$TELEGRAM_CHAT_ID" ] && [ -n "$TELEGRAM_BOT_TOKEN" ]; then
        read -p "✔ Telegram Chat ID: " INPUT_TG_CHAT
        TELEGRAM_CHAT_ID=${INPUT_TG_CHAT:-$TELEGRAM_CHAT_ID}
    fi
    if [ -z "$SLACK_WEBHOOK_URL" ]; then
        read -p "✔ Slack Webhook URL (없으면 Enter): " INPUT_SLACK
        SLACK_WEBHOOK_URL=${INPUT_SLACK:-$SLACK_WEBHOOK_URL}
    fi
    if [ -z "$SLACK_SIGNING_SECRET" ] && [ -n "$SLACK_WEBHOOK_URL" ]; then
        read -p "✔ Slack Signing Secret (대화형 버튼 검증용, 없으면 Enter): " INPUT_SLACK_SECRET
        SLACK_SIGNING_SECRET=${INPUT_SLACK_SECRET:-$SLACK_SIGNING_SECRET}
    fi
fi

if [ -z "$SLACK_WEBHOOK_URL" ] && [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "❌ Slack Webhook 또는 Telegram Token 중 최소 하나는 설정되어야 합니다."
    exit 1
fi

SERVICE_PORT=${SERVICE_PORT:-7788}
MONITOR_TYPE=${MONITOR_TYPE:-JOURNAL}
LOG_PATH=${LOG_PATH:-N/A_Journald}

# 서버 식별자 설정 (기본값: 시스템 호스트명)
DEFAULT_HOSTNAME=$(hostname)
if [ -z "$SERVER_NAME" ]; then
    if [ -t 0 ]; then
        read -p "✔ 서버 식별자 (기본값: $DEFAULT_HOSTNAME): " INPUT_SERVER_NAME
        SERVER_NAME=${INPUT_SERVER_NAME:-$DEFAULT_HOSTNAME}
    else
        SERVER_NAME=$DEFAULT_HOSTNAME
    fi
fi

# 텔레그램 Polling 설정 (메인 서버: true, 추가 노드: false 권장)
if [ -z "$ENABLE_TELEGRAM_POLLING" ]; then
    if [ -t 0 ]; then
        read -p "✔ 텔레그램 인라인 버튼 Long Polling 활성화 (메인: true, 추가 노드: false, 기본: false): " INPUT_POLL
        ENABLE_TELEGRAM_POLLING=${INPUT_POLL:-false}
    else
        ENABLE_TELEGRAM_POLLING="false"
    fi
fi

echo ""
echo "--- [설정 요약] ---"
echo " • 대상 서버 식별자: $SERVER_NAME"
echo " • Gemini 모델: $GEMINI_MODEL"
echo " • Telegram 연동: Token=$( [ -n "$TELEGRAM_BOT_TOKEN" ] && echo '설정됨' || echo '미설정' ), Polling=$ENABLE_TELEGRAM_POLLING"
echo " • Slack 연동: $( [ -n "$SLACK_WEBHOOK_URL" ] && echo '설정됨' || echo '미설정' )"
echo " • 모니터링 방식: $MONITOR_TYPE ($LOG_PATH)"
echo "-------------------"

AGENT_USER="ai-agent"
AGENT_DIR="/opt/ai-agent"

# 2. 기존 환경 초기화 (Clean Up)
echo ""
echo "--- [1/6] 기존 환경 초기화 (Cleanup) ---"
sudo systemctl stop ai-remediator.service 2>/dev/null || true
sudo systemctl disable ai-remediator.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/ai-remediator.service
sudo fuser -k ${SERVICE_PORT}/tcp 2>/dev/null || true
sudo rm -rf $AGENT_DIR
sudo userdel -r $AGENT_USER 2>/dev/null || true

# 3. 유저 및 권한 설정
echo "--- [2/6] 전용 시스템 유저 및 권한 설정 ---"
if ! id -u $AGENT_USER &>/dev/null; then
    sudo useradd -m -s /bin/bash $AGENT_USER
fi
sudo usermod -aG adm,systemd-journal $AGENT_USER 2>/dev/null || sudo usermod -aG systemd-journal $AGENT_USER 2>/dev/null || true

# sudo 최소 권한 부여 (에이전트 조치 명령어 전용: systemctl, journalctl, df, free, lsof, ss)
cat << 'EOF' | sudo tee /etc/sudoers.d/ai-agent > /dev/null
# AI SRE Agent 최소 권한 설정 (비파괴적 진단 및 안전 서비스 제어만 허용)
ai-agent ALL=(ALL) NOPASSWD: /bin/systemctl status *, /usr/bin/systemctl status *, \
                             /bin/systemctl restart *, /usr/bin/systemctl restart *, \
                             /bin/journalctl *, /usr/bin/journalctl *, \
                             /bin/df *, /usr/bin/df *, \
                             /bin/free *, /usr/bin/free *, \
                             /bin/lsof *, /usr/bin/lsof *, /usr/sbin/lsof *, /sbin/lsof *, \
                             /bin/ss *, /usr/bin/ss *, /usr/sbin/ss *, /sbin/ss *
EOF
sudo chmod 0440 /etc/sudoers.d/ai-agent

sudo mkdir -p $AGENT_DIR
sudo chown -R $AGENT_USER:$AGENT_USER $AGENT_DIR

# 보안 환경변수 디렉토리 및 파일 격리 (0600 권한)
sudo mkdir -p /etc/ai-agent
sudo chmod 0750 /etc/ai-agent
sudo chown root:$AGENT_USER /etc/ai-agent
sudo tee /etc/ai-agent/agent.env > /dev/null <<EOF
SERVER_NAME=$SERVER_NAME
ENABLE_TELEGRAM_POLLING=$ENABLE_TELEGRAM_POLLING
GEMINI_API_KEY=$GEMINI_API_KEY
GEMINI_MODEL=$GEMINI_MODEL
SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL
SLACK_SIGNING_SECRET=$SLACK_SIGNING_SECRET
TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID
SERVICE_PORT=$SERVICE_PORT
BIND_ADDR=127.0.0.1
MONITOR_TYPE=$MONITOR_TYPE
LOG_PATH=$LOG_PATH
PYTHONUNBUFFERED=1
EOF
sudo chmod 0600 /etc/ai-agent/agent.env
sudo chown root:$AGENT_USER /etc/ai-agent/agent.env

# 4. 필수 시스템 패키지 설치 (OS별 분기)
echo "--- [3/6] 필수 패키지 설치 ---"
if [[ "$OS_ID" =~ (ol|rhel|centos|rocky|almalinux|fedora) ]] || [[ "$OS_LIKE" =~ (rhel|fedora) ]]; then
    echo "[*] RHEL/Oracle Linux 계열 감지: dnf 패키지 설치 중..."
    sudo dnf install -y python3.11 python3.11-pip coreutils psmisc lsof curl git
    PYTHON_BIN="python3.11"
else
    echo "[*] Debian/Ubuntu 계열 감지: apt 패키지 설치 중..."
    sudo apt-get update -y
    sudo apt-get install -y python3-venv python3-pip coreutils psmisc lsof curl git
    PYTHON_BIN="python3"
fi

# 5. 가상환경 및 Python 패키지 설치
echo "--- [4/6] Python 가상환경 구축 ($PYTHON_BIN) 및 의존성 설치 ---"
sudo -u $AGENT_USER $PYTHON_BIN -m venv $AGENT_DIR/venv
sudo -u $AGENT_USER $AGENT_DIR/venv/bin/pip install --upgrade pip
sudo -u $AGENT_USER $AGENT_DIR/venv/bin/pip install flask requests google-genai pydantic

# 6. 설정 파일 및 소스코드 배치
echo "--- [5/6] 소스코드 및 정책 파일 생성 ---"

# prompt.txt
sudo -u $AGENT_USER tee $AGENT_DIR/prompt.txt << 'EOF' > /dev/null
You are a Senior Site Reliability Engineer (SRE) and Linux Systems Architect.
Your task is to analyze Linux system error logs and provide an expert diagnostic and remediation plan.

### Rules & Guidelines:
1. **Accurate Triage (needs_action)**:
   - If the log is normal internet noise, random port scan, routine SSH disconnection (e.g. 'kex_exchange_identification', 'Connection closed by remote host', 'banner line contains invalid characters', 'invalid user'), or harmless informational message, set "needs_action" to false and "command" to "".
   - Only set "needs_action" to true if there is an actual system service failure, disk space exhaustion, memory exhaustion, file descriptor leak, kernel error, or critical daemon crash.

2. **Remediation Command (command)**:
   - Provide a safe, standard, non-destructive Linux bash command.
   - ALWAYS prefer standard built-in Linux utilities:
     - For port/network binding conflict: prefer 'lsof -i :<port>' or 'ss -tulpn'
     - For service diagnostics: prefer 'systemctl status <service>' or 'journalctl -u <service> -n 50 --no-pager'
     - For resource exhaustion: prefer 'df -h', 'free -h', 'uptime'
   - Prefer diagnostic or gentle recovery commands first (e.g. 'systemctl restart nginx', 'docker restart app').
   - NEVER provide dangerous commands like 'rm -rf', 'mkfs', 'dd', raw device writes, or system shutdown/reboot unless strictly diagnostic.
   - NEVER output shell pipeline operators like '|' or chaining like ';', '&&', '&'. Always provide a single native command.
   - If root privileges are required for system services, include 'sudo' in the command.
   - If no action is needed, leave "command" empty ("").

3. **Output Format**:
   - Respond strictly in JSON format according to the schema provided.
EOF

# blacklist.txt
sudo -u $AGENT_USER tee $AGENT_DIR/blacklist.txt << 'EOF' > /dev/null
rm
mkfs
shutdown
reboot
dd
>
EOF

# auto_keywords.txt
sudo -u $AGENT_USER tee $AGENT_DIR/auto_keywords.txt << 'EOF' > /dev/null
DISK FULL
OUT OF MEMORY
EOF

# main.py 배포
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/main.py" ]; then
    sudo cp "$SCRIPT_DIR/main.py" $AGENT_DIR/main.py
    sudo chown $AGENT_USER:$AGENT_USER $AGENT_DIR/main.py
elif [ -f "$AGENT_DIR/main.py" ]; then
    echo "[*] 기존 $AGENT_DIR/main.py를 유지합니다."
else
    echo "❌ main.py 파일을 찾을 수 없습니다. 설치를 중단합니다."
    exit 1
fi

# 7. systemd 서비스 유닛 등록
echo "--- [6/6] systemd 서비스 유닛 등록 및 가동 ---"
sudo tee /etc/systemd/system/ai-remediator.service > /dev/null <<EOT
[Unit]
Description=AI SRE Agent Multi-Server (v3.0)
After=network.target

[Service]
ExecStart=$AGENT_DIR/venv/bin/python3 $AGENT_DIR/main.py
Restart=always
RestartSec=5
User=$AGENT_USER
Group=$AGENT_USER
SupplementaryGroups=systemd-journal adm
EnvironmentFile=/etc/ai-agent/agent.env

[Install]
WantedBy=multi-user.target
EOT

sudo systemctl daemon-reload
sudo systemctl enable ai-remediator.service
sudo systemctl restart ai-remediator.service

PUBLIC_IP=$(curl -s -m 3 ifconfig.me || echo "SERVER_IP")
echo ""
echo "=========================================================="
echo "🎉 AI SRE Auto-Remediator v3.0 [$SERVER_NAME] 설치가 성공적으로 완료되었습니다!"
echo "=========================================================="
echo "[서비스 정보]"
echo " • 대상 서버: $SERVER_NAME ($PUBLIC_IP)"
echo " • 서비스 상태: sudo systemctl status ai-remediator.service"
echo " • 실시간 로그: sudo journalctl -u ai-remediator.service -f"
echo " • 헬스체크: curl http://localhost:${SERVICE_PORT}/health"
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
    if [ "$ENABLE_TELEGRAM_POLLING" == "true" ]; then
        echo " • 텔레그램 연동: 활성화됨 (Long Polling 수신 대기)"
    else
        echo " • 텔레그램 연동: 활성화됨 (알림 푸시 전용 모드 - 409 충돌 방지)"
    fi
else
    echo " • 텔레그램 연동: 미설정"
fi
echo "=========================================================="
