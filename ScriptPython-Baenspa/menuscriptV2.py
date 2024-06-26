import os
import subprocess
import sys
from time import sleep

def check_root():
    if os.geteuid() != 0:
        print("Este script deve ser executado como root (superusuário)")
        sys.exit(1)
    else:
        print("Você está logado como root (superusuário)")

def exibir_cabecalho():
    os.system('clear')
    print("\033[1m\033[34m### SCRIPT DE INSTALAÇÃO ###\033[0m\n")

def pausar():
    input("Pressione ENTER para continuar...")

def executar_comando(comando):
    process = subprocess.run(comando, shell=True, check=True, text=True, capture_output=True)
    return process.stdout

def programaspadroes():
    exibir_cabecalho()
    print("Instalação de Programas Padrões")
    print("-------------------------------")
    print("Trocando repositório de ftp para http no arquivo /etc/apt/sources.list")
    executar_comando("sed -i 's/ftp/http/g' /etc/apt/sources.list")
    print("\nAtualização e Sincronização com Servidor de Hora")
    executar_comando("apt-get install ntp -y")
    executar_comando("apt-get install ntpdate -y")
    executar_comando("service ntp stop")
    executar_comando("ntpdate hora-1dn.mb")
    executar_comando("service ntp restart")
    executar_comando("hwclock -w")
    print("\nAtualização do Sistema")
    executar_comando("apt-get update -y && apt-get upgrade -y")
    print("\nInstalação de Programas Essenciais")
    executar_comando("apt install passwd sudo acl attr systemd x11-xserver-utils policykit-1 zenity lsb-release iproute2 iputils-ping krb5-user libnss-winbind libpam-winbind samba-common-bin samba-dsdb-modules samba-vfs-modules smbclient samba cifs-utils libpam-mount cups-daemon cups-client ntp ntpdate -y")
    print("\nInstalando MB Domínio")
    executar_comando("apt-get install mb-dominio -y")
    print("\nInstalando o NEMO para gerenciar arquivos como root")
    executar_comando("apt-get install nemo -y")
    print("\nConfigurando o arquivo /etc/resolvconf/resolv.conf.d/head")
    with open("/etc/resolvconf/resolv.conf.d/head", "a") as resolv_file:
        resolv_file.write("search banspa.mb\n")
        resolv_file.write("domain banspa.mb\n")
        resolv_file.write("nameserver 127.0.0.53\n")
    print("\nInstalando CURL")
    executar_comando("apt install curl -y")
    print("\nMovendo arquivos de configuração do Sigdem")
    executar_comando("mv -f mozilla.cfg /usr/lib/firefox")
    executar_comando("mv -f local-settings.js /usr/lib/firefox/defaults/pref")
    print("\nScript Concluído")
    pausar()

def SincronizarHora():
    exibir_cabecalho()
    print("Sincronização de Hora")
    print("---------------------")
    print("Trocando repositório de ftp para http no arquivo /etc/apt/sources.list")
    executar_comando("sed -i 's/ftp/http/g' /etc/apt/sources.list")
    print("\nAtualização e Sincronização com Servidor de Hora")
    executar_comando("apt-get install ntp -y")
    executar_comando("apt-get install ntpdate -y")
    executar_comando("service ntp stop")
    executar_comando("ntpdate hora-1dn.mb")
    executar_comando("service ntp restart")
    executar_comando("hwclock -w")
    print("\nSincronização de Hora concluída")
    pausar()

def installOffice():
    exibir_cabecalho()
    print("Instalação do LibreOffice")
    print("-------------------------")
    os.chdir("libre/DEBS")
    executar_comando("sudo dpkg -i *.deb")
    print("\nInstalação do LibreOffice concluída")
    pausar()

def InstalaAntivirus():
    exibir_cabecalho()
    print("Instalação do Antivírus")
    print("------------------------")
    print("Baixando e instalando Kaspersky Antivirus")
    executar_comando("curl -k https://www.ctim.mb/sites/default/files/aplicacoes/kspLinuxRecim.tar.gz -o kspLinuxRecim.tar.gz")
    executar_comando("tar -zxvf kspLinuxRecim.tar.gz")
    executar_comando("chmod +x akinstall.sh && ./akinstall.sh")
    print("\nInstalação do Antivírus concluída")
    pausar()

def VrfAntivirus():
    exibir_cabecalho()
    print("Verificação de Antivírus")
    print("------------------------")
    print("Verificando status do Kaspersky Antivirus")
    print(executar_comando("service klnagent64 status"))
    print(executar_comando("service kesl status"))
    pausar()

def progcid():
    exibir_cabecalho()
    print("Instalação do CID (Close In Directory)")
    print("---------------------------------------")
    os.chdir("cid")
    executar_comando("chmod +x INSTALL.sh && ./INSTALL.sh")
    print("\nIniciando CID-GTK")
    executar_comando("cid-gtk")
    print("\nInstalação do CID concluída")
    pausar()

def instalarfusioninventory():
    exibir_cabecalho()
    print("Instalação do Plugin Fusion Inventory")
    print("------------------------------------")
    print("Instalando pacotes necessários para o Fusion Inventory")
    executar_comando("apt -y install dmidecode hwdata ucf hdparm perl libuniversal-require-perl libwww-perl libparse-edid-perl libproc-daemon-perl libfile-which-perl libhttp-daemon-perl libxml-treepp-perl libyaml-perl libnet-cups-perl libnet-ip-perl libdigest-sha-perl libsocket-getaddrinfo-perl libtext-template-perl libxml-xpath-perl libyaml-tiny-perl libnet-snmp-perl libcrypt-des-perl libnet-nbname-perl libdigest-hmac-perl libfile-copy-recursive-perl libparallel-forkmanager-perl libwrite-net-perl")
    executar_comando("apt --fix-broken install")
    print("\nInstalando Fusion Inventory")
    os.chdir("fusion")
    executar_comando("dpkg -i fusioninventory-agent-task-collect_2.5.2-1_all.deb")
    executar_comando("dpkg -i fusioninventory-agent_2.5.2-1_all.deb")
    print("\nConfigurando arquivo agent.cfg do Fusion Inventory")
    executar_comando("curl --insecure https://siscsrecim.ctim.mb/agents-fusion/2.5.1/agent_tux.cfg -o /etc/fusioninventory/agent.cfg")
    print("\nIniciando serviço Fusion Inventory")
    executar_comando("systemctl restart fusioninventory-agent")
    executar_comando("systemctl reload fusioninventory-agent")
    executar_comando("pkill -USR1 -f -P 1 fusioninventory-agent")
    print(executar_comando("systemctl status fusioninventory-agent"))
    executar_comando("systemctl start fusioninventory-agent")
    print("\nInstalação do Fusion Inventory concluída")
    pausar()

def ImpressoraKyocera():
    def prompt_user_input(prompt, title):
        result = subprocess.run(['whiptail', '--inputbox', prompt, '8', '78', '--title', title, '3>&1', '1>&2', '2>&3'], text=True, capture_output=True)
        return result.stdout.strip()

    if os.geteuid() != 0:
        subprocess.run(['whiptail', '--msgbox', 'Por favor, execute este script como root.', '8', '78'])
        sys.exit(1)

    PRINTERS = {
        "DiactaCorredor": ("10.30.51.96", "KyoceraAlpha.ppd"),
        "Secom": ("10.30.49.7", "KyoceraAlpha.ppd"),
        "Movimentacao": ("10.30.49.8", "KyoceraAlpha.ppd"),
        "SuprimentosLicitacoesecontratos": ("10.30.49.22", "KyoceraAlpha.ppd"),
        "NFRN": ("10.30.49.17", "KyoceraAlpha.ppd"),
        "SecPrefeitura": ("10.30.51.18", "KyoceraAlpha.ppd"),
        "EstacaoRadio": ("10.30.49.33", "KyoceraAlpha.ppd"),
        "Dape": ("10.30.49.43", "KyoceraAlpha.ppd"),
        "SecretariaDiacta": ("10.30.49.211", "KyoceraAlpha.ppd"),
        "PessoalMilitar": ("10.30.49.74", "KyoceraAlpha.ppd"),
        "Pecunio": ("10.30.49.72", "KyoceraAlpha.ppd"),
        "PessoalCivil": ("10.30.49.248", "KyoceraAlpha.ppd"),
        "GAB": ("10.30.49.12", "KyoceraAlpha.ppd")
    }

    exibir_cabecalho()
    print("Instalação de Impressoras Kyocera")
    print("-------------------------------")

    printer_choice = prompt_user_input("Escolha a impressora para instalar (opções: DiactaCorredor, Secom, Movimentacao, SuprimentosLicitacoesecontratos, NFRN, SecPrefeitura, EstacaoRadio, Dape, SecretariaDiacta, PessoalMilitar, Pecunio, PessoalCivil, GAB):", "Instalação de Impressoras Kyocera")

    if printer_choice not in PRINTERS:
        print(f"Escolha inválida: {printer_choice}")
        sys.exit(1)

    ip_address, driver_file = PRINTERS[printer_choice]

    try:
        print(f"Baixando o driver da impressora {printer_choice}...")
        executar_comando(f"curl -k https://siscsrecim.ctim.mb/drivers/{driver_file} -o /usr/share/cups/model/{driver_file}")

        print(f"Instalando a impressora {printer_choice} com IP {ip_address}...")
        executar_comando(f"lpadmin -p {printer_choice} -E -v socket://{ip_address} -P /usr/share/cups/model/{driver_file}")
        executar_comando(f"cupsenable {printer_choice}")
        executar_comando(f"cupsaccept {printer_choice}")
        print(f"Impressora {printer_choice} instalada com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Ocorreu um erro durante a instalação: {e}")
        sys.exit(1)

    print("\nInstalação de Impressoras Kyocera concluída")
    pausar()

def exibir_menu():
    while True:
        exibir_cabecalho()
        print("Selecione uma opção:")
        print("1 - Programas Padrões")
        print("2 - Sincronizar Hora")
        print("3 - Instalar LibreOffice")
        print("4 - Instalar Antivírus")
        print("5 - Verificar Antivírus")
        print("6 - Instalar CID (Close In Directory)")
        print("7 - Instalar Plugin Fusion Inventory")
        print("8 - Instalar Impressoras Kyocera")
        print("0 - Sair")

        try:
            opcao = int(input("Digite sua opção: "))
            if opcao == 1:
                programaspadroes()
            elif opcao == 2:
                SincronizarHora()
            elif opcao == 3:
                installOffice()
            elif opcao == 4:
                InstalaAntivirus()
            elif opcao == 5:
                VrfAntivirus()
            elif opcao == 6:
                progcid()
            elif opcao == 7:
                instalarfusioninventory()
            elif opcao == 8:
                ImpressoraKyocera()
            elif opcao == 0:
                break
            else:
                print("Opção inválida.")
                pausar()
        except ValueError:
            print("Entrada inválida. Por favor, insira um número.")
            pausar()

if __name__ == "__main__":
    check_root()
    exibir_menu()