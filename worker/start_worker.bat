@echo off
REM Inicializador rápido do worker local do AegisDAST (Windows).
REM Cria um venv na primeira execução, instala as dependências e roda o worker
REM em loop contínuo. Feche esta janela (ou Ctrl+C) para parar o worker.

cd /d "%~dp0"

if not exist ".venv" (
    echo [start_worker] Criando ambiente virtual em worker\.venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [start_worker] ERRO: nao foi possivel criar o venv. Python 3.9+ esta instalado e no PATH?
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

echo [start_worker] Instalando/atualizando dependencias...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

if not exist ".env" (
    echo [start_worker] AVISO: worker\.env nao encontrado. Copiando .env.example -- edite antes de continuar.
    copy .env.example .env >nul
    echo [start_worker] Edite worker\.env com suas credenciais do Upstash e rode este script de novo.
    pause
    exit /b 1
)

echo [start_worker] Iniciando o worker. Ctrl+C para parar.
python worker.py

pause
