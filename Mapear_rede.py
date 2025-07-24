import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import socket


# RRRR     EEEEE   GGGG   IIIII   SSSS    CCCCC   AAAAA   N   N
# R   R    E      G          I    S       C       A   A   NN  N
# RRRR     EEEE   G  G       I     SSS    C       AAAAA   N N N
# R R      E      G   G      I        S   C       A   A   N  NN
# R  RR    EEEEE   GGGG   IIIII   SSSS    CCCCC   A   A   N   N

###################################################################

def ping_and_get_hostname(ip):
    """Executa um ping e tenta obter o hostname para o IP fornecido."""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1000', str(ip)]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        success = 'TTL=' in output or '1 packets transmitted, 1 received' in output
        
        hostname = ''
        if success:
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except socket.herror:
                hostname = 'Hostname não encontrado'
        
        return {
            'ip': str(ip),
            'success': success,
            'hostname': hostname,
            'output': output.strip()
        }
    except subprocess.CalledProcessError as e:
        return {
            'ip': str(ip),
            'success': False,
            'hostname': '',
            'output': str(e.output).strip()
        }

def scan_ips(start_ip, end_ip):
    """Escaneia um intervalo de IPs fornecido e retorna uma lista de resultados."""
    results = []
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    with ThreadPoolExecutor(max_workers=20) as executor:
        ip_range = [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end) + 1)]
        futures = {executor.submit(ping_and_get_hostname, str(ip)): ip for ip in ip_range}
        for future in as_completed(futures):
            results.append(future.result())
    return results

def on_scan_button_click():
    """Função chamada quando o botão de escaneamento é clicado."""
    try:
        start_ip = entry_start_ip.get()
        end_ip = entry_ip_final.get()

        if ipaddress.IPv4Address(end_ip) < ipaddress.IPv4Address(start_ip):
            messagebox.showerror('Erro', 'O IP final deve ser maior ou igual ao IP inicial.')
            return
        
        if int(ipaddress.IPv4Address(end_ip)) - int(ipaddress.IPv4Address(start_ip)) > 256:
            messagebox.showwarning('Aviso', 'O intervalo de IPs é grande. Isso pode levar um tempo considerável.')
        
        messagebox.showinfo('Info', 'Iniciando o escaneamento. Pode levar um tempo dependendo da faixa de IPs.')

        results = scan_ips(start_ip, end_ip)
        
        result_text.delete('1.0', tk.END)
        active_ips = [r for r in results if r['success']]
        
        if active_ips:
            result_text.insert(tk.END, 'IPs ativos encontrados:\n')
            for r in active_ips:
                result_text.insert(tk.END, f"IP: {r['ip']}, Hostname: {r['hostname']}\n")
            result_text.insert(tk.END, '\n')
        else:
            result_text.insert(tk.END, 'Nenhum IP ativo encontrado.\n\n')
        
        result_text.insert(tk.END, 'Detalhes do scan:\n')
        for r in results:
            result_text.insert(tk.END, f"IP: {r['ip']}, Status: {'Ativo' if r['success'] else 'Inativo'}\n")
            if r['success']:
                result_text.insert(tk.END, f"Hostname: {r['hostname']}\n")
            result_text.insert(tk.END, f"Saída: {r['output']}\n\n")
        
    except ValueError as e:
        messagebox.showerror('Erro', f'Entrada inválida: {e}')

# Configura a interface gráfica
root = tk.Tk()
root.title('Scanner de Rede - regiscan')

tk.Label(root, text='IP Inicial (ex: 192.168.1.1)').grid(row=0, column=0, padx=10, pady=5)
entry_start_ip = tk.Entry(root)
entry_start_ip.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text='IP Final (ex: 192.168.1.254)').grid(row=1, column=0, padx=10, pady=5)
entry_ip_final = tk.Entry(root)
entry_ip_final.grid(row=1, column=1, padx=10, pady=5)

scan_button = tk.Button(root, text='Escanear', command=on_scan_button_click)
scan_button.grid(row=2, column=0, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20)
result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=5)


def shutdown_machine(ip):
    """Tenta desligar uma máquina remota."""
    try:
        if platform.system().lower() == 'windows':
            # Sintaxe ajustada para incluir o parâmetro /m para o computador remoto
            subprocess.run(['shutdown', '/s', '/f', '/m', f'\\\\{ip}', '/t', '0'], check=True)
        else:
            # Para sistemas Unix/Linux, você precisaria de SSH configurado e usar um comando como:
            # subprocess.run(['ssh', ip, 'sudo', 'shutdown', '-h', 'now'], check=True)
            raise NotImplementedError("Desligamento remoto não implementado para sistemas não-Windows")
        return True
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Erro", f"Falha ao desligar {ip}: {str(e)}")
        return False
    except NotImplementedError as e:
        messagebox.showerror("Erro", str(e))
        return False

def on_shutdown_button_click():

    """Função chamada quando o botão de desligamento é clicado."""
    ip_to_shutdown = entry_shutdown_ip.get()
    if ip_to_shutdown:
        try:
            ipaddress.ip_address(ip_to_shutdown)  # Valida se é um IP válido
            confirmation = messagebox.askyesno("Confirmar Desligamento", 
                                               f"Tem certeza que deseja desligar a máquina {ip_to_shutdown}?\n"
                                               "Esta ação não pode ser desfeita.")
            if confirmation:
                if shutdown_machine(ip_to_shutdown):
                    messagebox.showinfo("Sucesso", f"Comando de desligamento enviado para {ip_to_shutdown}")
                else:
                    messagebox.showerror("Erro", f"Falha ao enviar comando de desligamento para {ip_to_shutdown}")
        except ValueError:
            messagebox.showerror("Erro", "IP inválido. Por favor, insira um endereço IP válido.")
    else:
        messagebox.showerror("Erro", "Por favor, insira um endereço IP para desligar.")



def restart_machine(ip):
    """Tenta reiniciar uma máquina remota."""
    try:
        if platform.system().lower() == 'windows':
            subprocess.run(['shutdown', '/r', '/f', '/m', f'\\\\{ip}', '/t', '0'], check=True)
        else:
            raise NotImplementedError("Reinício remoto não implementado para sistemas não-Windows")
        return True
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Erro", f"Falha ao reiniciar {ip}: {str(e)}")
        return False
    except NotImplementedError as e:
        messagebox.showerror("Erro", str(e))
        return False

def on_restart_button_click():
    """Função chamada quando o botão de reinício é clicado."""
    ip_to_restart = entry_shutdown_ip.get()
    if ip_to_restart:
        try:
            ipaddress.ip_address(ip_to_restart)  # Valida se é um IP válido
            confirmation = messagebox.askyesno("Confirmar Reinício", 
                                               f"Tem certeza que deseja reiniciar a máquina {ip_to_restart}?\n"
                                               "Esta ação não pode ser desfeita.")
            if confirmation:
                restart_button.config(state='disabled')  # Desabilita o botão
                if restart_machine(ip_to_restart):
                    messagebox.showinfo("Sucesso", f"Comando de reinício enviado para {ip_to_restart}")
                else:
                    messagebox.showerror("Erro", f"Falha ao enviar comando de reinício para {ip_to_restart}")
                restart_button.config(state='normal')  # Reabilita o botão
        except ValueError:
            messagebox.showerror("Erro", "IP inválido. Por favor, insira um endereço IP válido.")
    else:
        messagebox.showerror("Erro", "Por favor, insira um endereço IP para reiniciar.")



#campo e botão para desligamento
tk.Label(root, text='IP para desligar:').grid(row=4, column=0, padx=10, pady=5)
entry_shutdown_ip = tk.Entry(root)
entry_shutdown_ip.grid(row=4, column=1, padx=10, pady=5)

shutdown_button = tk.Button(root, text='Desligar Máquina', command=on_shutdown_button_click, bg='red', fg='white')
shutdown_button.grid(row=5, column=0, columnspan=2, pady=10)

restart_button = tk.Button(root, text='Reiniciar Máquina', command=on_restart_button_click, bg='blue', fg='white')
restart_button.grid(row=6, column=0, columnspan=2, pady=10)


root.mainloop()