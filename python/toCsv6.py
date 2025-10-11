import os
import glob
import json
import ipaddress
import pandas as pd
import subprocess

# === CONFIGURAÇÃO ===
PASTA_CAP = ""  # pasta onde estão os arquivos captura_*.cap
CAMINHO_EVE_JSON = "logs_benignos_2/eve.json"
ARQUIVO_SAIDA = "logs_2.0_benigno_sem_tcp.csv"

# === LISTA DE FEATURES NB15 ===
features_nb15 = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
    'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat'
]

# === FUNÇÕES DE APOIO ===
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except:
        return 0

def processar_eve_json():
    eventos = []
    with open(CAMINHO_EVE_JSON, 'r') as f:
        for linha in f:
            try:
                evento = json.loads(linha)
                eventos.append(evento)
            except json.JSONDecodeError:
                continue
    df = pd.json_normalize(eventos)
    if df.empty:
        return pd.DataFrame()

    df['timestamp'] = pd.to_datetime(df.get('timestamp'), errors='coerce')
    df['flow.start'] = pd.to_datetime(df.get('flow.start'), errors='coerce')
    df['flow.end'] = pd.to_datetime(df.get('flow.end'), errors='coerce')
    df['dur'] = (df['flow.end'] - df['flow.start']).dt.total_seconds()
    df['smeansz'] = df['flow.bytes_toserver'] / df['flow.pkts_toserver'].replace(0, 1)
    df['dmeansz'] = df['flow.bytes_toclient'] / df['flow.pkts_toclient'].replace(0, 1)
    df['Sload'] = df['flow.bytes_toserver'] / df['dur'].replace(0, 1)
    df['Dload'] = df['flow.bytes_toclient'] / df['dur'].replace(0, 1)
    df['rate'] = (df['flow.bytes_toserver'] + df['flow.bytes_toclient']) / df['dur'].replace(0, 1)
    df['Label'] = df.get('flow.alerted', False).fillna(False).astype(int)
    df['is_sm_ips_ports'] = ((df['src_ip'] == df['dest_ip']) & (df['src_port'] == df['dest_port'])).astype(int)
    df['srcip_num'] = df['src_ip'].apply(ip_to_int)
    df['dstip_num'] = df['dest_ip'].apply(ip_to_int)

    renomear = {
        'src_ip': 'srcip', 'src_port': 'sport', 'dest_ip': 'dstip', 'dest_port': 'dsport',
        'proto': 'proto', 'app_proto': 'service', 'flow.state': 'state',
        'flow.bytes_toserver': 'sbytes', 'flow.bytes_toclient': 'dbytes',
        'flow.pkts_toserver': 'Spkts', 'flow.pkts_toclient': 'Dpkts',
        'flow.start': 'Stime', 'flow.end': 'Ltime',
        'tcp.syn': 'synack', 'tcp.ack': 'ackdat', 'tcp.state': 'ct_state_ttl',
        'http.http_method': 'trans_depth', 'http.url': 'res_bdy_len'
    }
    df.rename(columns=renomear, inplace=True)
    return df

def extrair_com_tshark(arquivo_cap):
    campos = [
        'frame.time_epoch', 'ip.src', 'ip.dst', 'ip.ttl', 'ip.proto',
        'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.ack', 'tcp.window_size', 'tcp.len',
        'tcp.flags.syn', 'tcp.flags.ack', 'frame.len', 'frame.number'
    ]
    cmd = ["tshark", "-r", arquivo_cap, "-T", "fields"]
    for c in campos:
        cmd += ["-e", c]
    cmd += ["-E", "separator=,", "-E", "quote=d", "-E", "header=y"]

    saida_csv = arquivo_cap + ".tmp.csv"
    with open(saida_csv, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

    try:
        df = pd.read_csv(saida_csv)
        os.remove(saida_csv)
        df.columns = [col.replace('.', '_') for col in df.columns]  # normaliza nomes
        df.rename(columns={
            'ip_src': 'srcip', 'ip_dst': 'dstip', 'ip_proto': 'proto', 'ip_ttl': 'sttl',
            'tcp_srcport': 'sport', 'tcp_dstport': 'dsport', 'frame_time_epoch': 'Stime',
            'tcp_len': 'sbytes', 'tcp_flags_syn': 'synack', 'tcp_flags_ack': 'ackdat',
            'tcp_window_size': 'swin', 'tcp_seq': 'stcpb', 'tcp_ack': 'dtcpb', 'frame_len': 'pktlen'
        }, inplace=True)
        df['Ltime'] = df['Stime']
        df['dur'] = 0
        df['smeansz'] = df['sbytes']
        df['dmeansz'] = 0
        df['Sload'] = 0
        df['Dload'] = 0
        df['Spkts'] = 1
        df['Dpkts'] = 0
        df['state'] = 0
        df['is_sm_ips_ports'] = ((df['srcip'] == df['dstip']) & (df['sport'] == df['dsport'])).astype(int)
        df['Label'] = 0
        return df
    except:
        print(f"❌ Erro ao processar {arquivo_cap} com tshark")
        return pd.DataFrame()

# === PROCESSAMENTO ===
print("🔍 Lendo arquivos .cap...")
arquivos_cap = glob.glob(os.path.join(PASTA_CAP, "captura_*.cap"))
df_tcp_list = [extrair_com_tshark(arquivo) for arquivo in arquivos_cap]
df_tcp = pd.concat(df_tcp_list, ignore_index=True) if df_tcp_list else pd.DataFrame()
print(f"✅ Total de registros do tcpdump: {len(df_tcp)}")

print("🔍 Lendo eve.json...")
df_eve = processar_eve_json()
print(f"✅ Total de registros do Suricata: {len(df_eve)}")

print("🔗 Sincronizando ambos...")
if not df_eve.empty and not df_tcp.empty:
    # converte timestamps
    df_eve['Stime'] = pd.to_datetime(df_eve['Stime'], errors='coerce')
    df_tcp['Stime'] = pd.to_datetime(df_tcp['Stime'], unit='s', errors='coerce')

    # ordena para merge_asof
    df_eve = df_eve.sort_values('Stime')
    df_tcp = df_tcp.sort_values('Stime')

    # merge aproximado com tolerância de 5ms
    df_unificado = pd.merge_asof(
        df_eve, df_tcp,
        on='Stime',
        by=['srcip','dstip','sport','dsport','proto'],
        tolerance=pd.Timedelta('5ms'),
        direction='nearest',
        suffixes=('_eve','_tcp')
    )
else:
    df_unificado = pd.concat([df_eve, df_tcp], ignore_index=True)

# mantém apenas colunas NB15 válidas
df_final = df_unificado[[col for col in features_nb15 if col in df_unificado.columns]]
df_final.to_csv(ARQUIVO_SAIDA, index=False)

print(f"📁 CSV final salvo em: {ARQUIVO_SAIDA} com {len(df_final)} linhas e {len(df_final.columns)} colunas válidas.")