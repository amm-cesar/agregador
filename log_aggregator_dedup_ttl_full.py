#!/usr/bin/env python3
import os,re,time,json,uuid,random,requests
from io import StringIO
from hashlib import sha1
from datetime import datetime
import numpy as np,pandas as pd
from lxml import etree
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from scipy.sparse import hstack,csr_matrix

FEATURE_COLS=['source_type','event_category','process_source','text_content']
ALERT_SUPPRESS_TTL=int(os.getenv("ALERT_SUPPRESS_TTL","300"))
TFIDF_MAX_FEATURES=int(os.getenv("TFIDF_MAX_FEATURES","5000"))
RANDOM_SEED=int(os.getenv("RANDOM_SEED","42"))
CONTAMINATION=float(os.getenv("CONTAMINATION","0.05"))
TOP_TFIDF_TERMS=int(os.getenv("TOP_TFIDF_TERMS","5"))
TOTAL_SIM_EVENTS=int(os.getenv("TOTAL_SIM_EVENTS","20"))
SLEEP_BETWEEN_EVENTS=float(os.getenv("SLEEP_BETWEEN_EVENTS","0.1"))
FORCE_ANOMALOUS_IF_FOUND=True
INCIDENTS_DIR="./incidents"
VIRUSTOTAL_API_KEY=os.getenv("VIRUSTOTAL_API_KEY","")
MISP_URL=os.getenv("MISP_URL","")
MISP_API_KEY=os.getenv("MISP_API_KEY","")
os.makedirs(INCIDENTS_DIR,exist_ok=True)
random.seed(RANDOM_SEED);np.random.seed(RANDOM_SEED)

RANSOM_KEYWORDS=["ransomware","ransom","ransomware_encrypted_files","encrypted_files","evil.exe","readme","restore","lockbit","blackcat","ryuk","conti","revil","sodinokibi","doppelpaymer","clop","wannacry","cerber","maze","netwalker","seemless","cryxos","petya","notpetya","cryptolocker"]
KNOWN_FAMILIES={'lockbit':'LockBit','blackcat':'BlackCat','ryuk':'Ryuk','conti':'Conti','revil':'REvil','sodinokibi':'Sodinokibi','doppelpaymer':'DoppelPaymer','clop':'Clop','wannacry':'WannaCry','petya':'Petya/NotPetya','cryptolocker':'CryptoLocker','maze':'Maze','netwalker':'NetWalker'}
HASH_RE=re.compile(r'\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b')
IPV4_RE=re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')
DOMAIN_RE=re.compile(r'\b((?![A-Za-z]:\\)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})\b')

def safe_lower(s): return (s or "").lower()
def sanitize_path_like_domain(t): return t.strip().strip(".,;:()[]\"'")

def query_virustotal_hash(h):
    if not VIRUSTOTAL_API_KEY: return None
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/files/{h}",headers={"x-apikey":VIRUSTOTAL_API_KEY},timeout=10)
        if r.status_code==200:
            d=r.json();stats=d.get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
            positives=sum(stats.get(k,0) for k in stats) if stats else None
            total=sum(stats.values()) if isinstance(stats,dict) else None
            ratio=(positives/total) if positives is not None and total else None
            return {"found":True,"positives":positives,"total":total,"ratio":ratio,"raw":d}
        return {"found":False} if r.status_code==404 else {"error":f"vt_status_{r.status_code}","text":r.text}
    except Exception as e: return {"error":str(e)}

def query_misp_ioc(ioc):
    if not (MISP_URL and MISP_API_KEY): return None
    try:
        url=f"{MISP_URL.rstrip('/')}/attributes/restSearch"
        headers={'Authorization':MISP_API_KEY,'Accept':'application/json'}
        r=requests.post(url,json={"value":ioc},headers=headers,timeout=10,verify=False)
        return {"found":True,"raw":r.json()} if r.status_code==200 else {"error":f"misp_status_{r.status_code}","text":r.text}
    except Exception as e: return {"error":str(e)}

def extract_iocs(text):
    t=text or ""
    hashes=HASH_RE.findall(t);ips=IPV4_RE.findall(t);domains_raw=DOMAIN_RE.findall(t)
    domains=[sanitize_path_like_domain(d) for d in domains_raw if not re.search(r'[\\/:]',d)]
    return {"hashes":sorted(set(hashes)),"ips":sorted(set(ips)),"domains":sorted(set(domains))}

def guess_family_and_confidence(text,iocs):
    t=safe_lower(text)
    for k,n in KNOWN_FAMILIES.items():
        if k in t: return n,0.9,"local_keyword"
    if iocs.get("hashes") and VIRUSTOTAL_API_KEY:
        h=iocs["hashes"][0];vt=query_virustotal_hash(h)
        if vt and vt.get("found"):
            ratio=vt.get("ratio") or 0.0;fam=None
            try:
                engines=vt['raw'].get('data',{}).get('attributes',{}).get('last_analysis_results',{})
                for eng,info in engines.items():
                    res=info.get('result') or ""
                    if res:
                        for key,name in KNOWN_FAMILIES.items():
                            if key in safe_lower(res):
                                fam=KNOWN_FAMILIES[key];break
                    if fam: break
            except Exception: fam=None
            return fam or "vt_malware",float(ratio or 0.0),"virustotal"
    if (iocs.get("hashes") or iocs.get("ips") or iocs.get("domains")) and MISP_URL and MISP_API_KEY:
        ioc=(iocs.get("hashes") or iocs.get("ips") or iocs.get("domains"))[0];m=query_misp_ioc(ioc)
        if m and m.get("found"): return "misp_match",0.8,"misp"
    if "ransomware" in t or "encrypted_files" in t or "ransom" in t: return "unknown_ransomware",0.5,"local_keyword"
    return None,0.0,"none"

def extract_username(text,log_entry):
    t=text or ""
    m=re.search(r'c:\\\\users\\\\([^\\\/\s:]+)',t,flags=re.I)
    if m: return m.group(1)
    m=re.search(r'Account Name[:=]\s*([^\s,;\\\/]+)',text,flags=re.I)
    if m: return m.group(1)
    m=re.search(r'\buser(?:name)?[:=]\s*([^\s,;\\\/]+)',t,flags=re.I)
    if m: return m.group(1)
    m=re.search(r'\buid[:=]\s*([^\s,;\\\/]+)',t,flags=re.I)
    if m: return m.group(1)
    m=re.search(r'\bby\s+([a-zA-Z0-9\-_\.]+)\b',t,flags=re.I)
    if m: return m.group(1)
    proc=log_entry.get('process_source') or "";m=re.search(r'\\Users\\([^\\\/\s:]+)',proc,flags=re.I)
    if m: return m.group(1)
    return None

def extract_hostname(text,log_entry):
    m=re.search(r'\\\\([A-Z0-9\-_\.]{2,100})',log_entry.get('process_source','') or "",flags=re.I)
    if m: return m.group(1)
    m=DOMAIN_RE.search(text or ""); 
    if m: return m.group(1)
    ps=log_entry.get('process_source','') or ""
    return ps if ps else None

def determine_gravity(confidence_family,iocs,username,num_hosts=1):
    score=4
    if confidence_family>=0.8: score+=3
    if iocs.get("hashes"): score+=2
    score+=min(2,len(iocs.get("ips") or []))
    if username and re.search(r'^(admin|administrator|root|svc_|system)$',username,flags=re.I): score+=1
    if num_hosts and num_hosts>1: score+=1
    return max(1,min(10,int(round(score))))

def _parse_eventlog_csv(fp):
    try: df=pd.read_csv(fp,dtype=str)
    except FileNotFoundError:
        print(f"EventLog CSV not found: {fp}"); return pd.DataFrame(columns=FEATURE_COLS)
    for c in FEATURE_COLS:
        if c not in df.columns: df[c]=''
    df=df[FEATURE_COLS].fillna(''); df['source_type']='eventlog'; return df

def _parse_splunk_log(fp):
    logs=[]
    try:
        with open(fp,'r',encoding='utf-8') as f: content=f.read()
    except FileNotFoundError:
        print(f"Splunk log not found: {fp}"); return pd.DataFrame(columns=FEATURE_COLS)
    tree=etree.parse(StringIO(f"<root>{content}</root>"),etree.XMLParser(recover=True))
    evs=tree.xpath("//*[local-name() = 'Event']")
    for e in evs:
        d={};ids=e.xpath(".//*[local-name() = 'System']/*[local-name() = 'EventID']/text()")
        d['event_category']=ids[0] if ids else ''
        data_nodes=e.xpath(".//*[local-name() = 'EventData']/*[local-name() = 'Data']")
        data_elements={n.get('Name'):(n.text or '') for n in data_nodes}
        d['process_source']=data_elements.get('Image','') or data_elements.get('Process','') or ''
        d['text_content']=(data_elements.get('TargetFilename','') or data_elements.get('CommandLine','') or data_elements.get('Message','') or '')
        d['source_type']='splunk'; logs.append(d)
    if not logs: return pd.DataFrame(columns=FEATURE_COLS)
    df=pd.DataFrame(logs)
    for c in FEATURE_COLS:
        if c not in df.columns: df[c]=''
    return df[FEATURE_COLS].fillna('')

def create_feature_pipeline(df_train):
    v=TfidfVectorizer(max_features=TFIDF_MAX_FEATURES); v.fit(df_train['text_content'].fillna(''))
    enc={}
    for c in ['source_type','event_category','process_source']:
        le=LabelEncoder(); le.fit(df_train[c].fillna('')); enc[c]=le
    return v,enc

def transform_data(df,vectorizer,encoders):
    X_text=vectorizer.transform(df['text_content'].fillna('')); cats=[]
    for c in ['source_type','event_category','process_source']:
        vals=df[c].fillna('').astype(str).values;codes=encoders[c].transform(vals); cats.append(csr_matrix(codes.reshape(-1,1)))
    return hstack([X_text]+cats).tocsr()

def transform_single(log_entry,vectorizer,encoders):
    return transform_data(pd.DataFrame([{k:log_entry.get(k,'') for k in FEATURE_COLS}]),vectorizer,encoders)

def build_incident(log_entry,score,vectorizer=None,X_entry=None):
    tid=uuid.uuid4().hex;ts=datetime.utcnow().isoformat()+"Z"
    text=(log_entry.get('text_content') or "")+" "+(log_entry.get('process_source') or "")
    iocs=extract_iocs(text);family,conf,source=guess_family_and_confidence(text,iocs)
    hostname=extract_hostname(text,log_entry);username=extract_username(text,log_entry)
    action='file_encryption' if re.search(r'encrypt|encrypted',text,flags=re.I) else ('execution' if '.exe' in (text or '').lower() else 'unknown')
    severity=determine_gravity(conf or 0.0,iocs,username,1)
    incident={"id_evento":tid,"timestamp_detectado":ts,"fonte_deteccao":log_entry.get('source_type'),"nome_ransomware":family or ("detected_by_pattern" if any(k in safe_lower(text) for k in RANSOM_KEYWORDS) else None),"familia_ransomware":family,"confidence_familia":float(conf if conf is not None else 0.0),"hash_arquivo":iocs['hashes'][0] if iocs['hashes'] else None,"hostname_afetado":hostname or log_entry.get('process_source'),"ip_origem":iocs['ips'][:1] if iocs['ips'] else [],"ip_destino":[],"usuario_afetado":username,"acao_realizada":action,"status_incidente":"em_investigacao","fase_nist":"Deteccao","orientacao_nist":"Isolar host, coletar artefatos, preservar logs, bloquear hashes/IPs, acionar playbook","acao_recomendada":["Isolar o host da rede","Coletar memory dump e logs","Bloquear IOC (hash/IP/dominio)","Restaurar de backup confiável"],"iocs_relacionados":iocs,"gravidade":int(severity),"fonte_cti":source or "local_heuristic","resumo_evento_rag":f"Detected possible ransomware ({family or 'unknown'}) on {hostname or log_entry.get('process_source')} with hash {iocs['hashes'][0] if iocs['hashes'] else 'n/a'}","link_evidencias":f"{INCIDENTS_DIR}/{tid}.log","created_at":ts,"created_by":"log_aggregator_enriched","raw_log":text}
    try:
        with open(os.path.join(INCIDENTS_DIR,f"{tid}.json"),"w",encoding="utf-8") as f: json.dump(incident,f,ensure_ascii=False,indent=2)
        with open(os.path.join(INCIDENTS_DIR,f"{tid}.log"),"w",encoding="utf-8") as f: f.write(text)
    except Exception as e: print(f"Erro ao salvar incidente: {e}")
    return incident

def print_enriched_alert(incident,score=None,vectorizer=None,X_entry=None):
    print("\n"+"#"*60);print("!!! ALERTA DE COMPORTAMENTO MALICIOSO (ENRIQUECIDO) !!!")
    print(f" ID: {incident.get('id_evento')}");print(f" Detectado em: {incident.get('timestamp_detectado')}");print(f" Fonte: {incident.get('fonte_deteccao')}")
    print(f" Ransomware provável: {incident.get('nome_ransomware')} (conf={incident.get('confidence_familia')})");print(f" Gravidade: {incident.get('gravidade')}")
    print(f" Host afetado: {incident.get('hostname_afetado')}");print(f" Usuário: {incident.get('usuario_afetado')}")
    print(f" Hash detectado: {incident.get('hash_arquivo')}");print(f" IPs: {', '.join(incident.get('ip_origem') or [])}")
    print(f" Ação: {incident.get('acao_realizada')}"); 
    if score is not None: print(f" Modelo score (decision_function): {score:.6f}")
    print(" Ações recomendadas (resumo):"); 
    for a in incident.get('acao_recomendada',[])[:3]: print(f"  - {a}")
    print(f" Evidências (raw log): {incident.get('link_evidencias')}")
    if vectorizer is not None and X_entry is not None:
        try:
            n_text_feats=len(vectorizer.get_feature_names_out()); x_text=X_entry[:,:n_text_feats]; arr=x_text.toarray().ravel()
            if arr.sum()>0:
                top_idx=np.argsort(arr)[-TOP_TFIDF_TERMS:][::-1]; terms=vectorizer.get_feature_names_out(); top=[(terms[i],arr[i]) for i in top_idx if arr[i]>0]
                if top:
                    print(" Top TF-IDF terms:")
                    for t,v in top: print(f"   {t}: {v:.4f}")
        except Exception: pass
    print("#"*60+"\n")

def log_generator(df,total=20,force_indices=None):
    records=df.to_dict(orient='records'); n=len(records); idxs=[]; forced=list(force_indices) if force_indices else []
    for i in range(total):
        if forced and random.random()<0.2: idxs.append(forced.pop(0)); continue
        idxs.append(random.randrange(n))
    i=0
    while forced and i<len(idxs): idxs[i]=forced.pop(0); i+=1
    for ix in idxs: yield ix,records[ix]

def _event_key_hash(log_entry):
    key=(str(log_entry.get('process_source','')).strip().lower(),str(log_entry.get('text_content','')).strip().lower(),str(log_entry.get('source_type','')).strip().lower(),str(log_entry.get('event_category','')).strip().lower())
    return sha1('||'.join(key).encode('utf-8')).hexdigest()

def main():
    print(">> 1. Carregando e Agregando Logs...")
    df_event=_parse_eventlog_csv('eventlog_expanded.csv'); df_splunk=_parse_splunk_log('splunk_expanded.log')
    df_all=pd.concat([df_event,df_splunk],ignore_index=True); df_all=df_all[FEATURE_COLS].fillna('')
    print(f"   Logs carregados: {len(df_all)} (EventLog: {len(df_event)}, Splunk: {len(df_splunk)})")

    print(">> 3. Treinando Vectorizers e Encoders...")
    vectorizer,encoders=create_feature_pipeline(df_all); X_train=transform_data(df_all,vectorizer,encoders)
    print("   Matriz de Features de Treino criada. Shape:",X_train.shape)

    print(f">> 4. Treinando Isolation Forest (contamination={CONTAMINATION})...")
    model=IsolationForest(contamination=CONTAMINATION,random_state=RANDOM_SEED); model.fit(X_train); print("   Modelo treinado com sucesso.")
    train_scores=model.decision_function(X_train); n_samples=X_train.shape[0]; n_outliers=max(1,int(np.ceil(CONTAMINATION*n_samples))); sorted_scores=np.sort(train_scores)
    threshold=sorted_scores[n_outliers-1] if n_outliers<=len(sorted_scores) else sorted_scores[-1]
    print(f"   Train scores: mean={train_scores.mean():.6f}, std={train_scores.std():.6f}"); print(f"   Samples: {n_samples}, contamination={CONTAMINATION}, n_outliers (forced)={n_outliers}")
    print(f"   Threshold set to score at position {n_outliers-1}: {threshold:.6f}")

    train_preds=model.predict(X_train); diag_rows=[]
    for idx,(row_pred,row_score) in enumerate(zip(train_preds,train_scores)):
        diag_rows.append({'idx':idx,'source_type':df_all.iloc[idx]['source_type'],'process_source':df_all.iloc[idx]['process_source'],'text_snippet':str(df_all.iloc[idx]['text_content'])[:80].replace('\n',' '),'score':float(row_score),'pred':int(row_pred),'anomaly_by_threshold':bool(row_score<threshold)})
    anomalous_indices=[r['idx'] for r in diag_rows if (r['pred']==-1 or r['anomaly_by_threshold'])]
    print(f"\n   Detected anomalous indices in training: {anomalous_indices}" if anomalous_indices else "\n   No anomalies detected in training.")

    print("\n"+"="*50); print(">> 5. SIMULAÇÃO DE DETECÇÃO EM TEMPO REAL INICIADA"); print("   Pressione Ctrl+C para parar."); print("="*50)
    print(f"   Iniciando gerador com {len(df_all)} logs únicos...\n")
    force_list=anomalous_indices if (FORCE_ANOMALOUS_IF_FOUND and anomalous_indices) else None
    if force_list: print(f"   Generator will force inclusion of indices: {force_list} (at least once during simulation)")

    recent_alerts={}; gen=log_generator(df_all,total=TOTAL_SIM_EVENTS,force_indices=force_list); ctr=0
    try:
        for orig_idx,log_entry in gen:
            ctr+=1; X_entry=transform_single(log_entry,vectorizer,encoders); score=model.decision_function(X_entry)[0]; pred=model.predict(X_entry)[0]
            print(f"[evento #{ctr}] origem_idx={orig_idx} pred={pred} score={score:.6f} process={log_entry.get('process_source')[:60]}")
            is_anomaly_pred=(pred==-1); is_anomaly_threshold=(score<threshold)
            if is_anomaly_pred or is_anomaly_threshold:
                key=_event_key_hash(log_entry); now=time.time(); last=recent_alerts.get(key,0)
                if now-last>=ALERT_SUPPRESS_TTL:
                    recent_alerts[key]=now
                    text_for_check=(log_entry.get('text_content','') or '')+' '+(log_entry.get('process_source','') or '')
                    if any(k in safe_lower(text_for_check) for k in RANSOM_KEYWORDS) or any(kw in safe_lower(text_for_check) for kw in RANSOM_KEYWORDS):
                        incident=build_incident(log_entry,score,vectorizer=vectorizer,X_entry=X_entry); print_enriched_alert(incident,score=score,vectorizer=vectorizer,X_entry=X_entry)
                    else:
                        log_entry['_alert_reasons']=','.join(r for r in (('predict==-1' if is_anomaly_pred else ''),('score<threshold' if is_anomaly_threshold else '')) if r)
                        print("\n"+"#"*60); print("!!! ALERTA DE COMPORTAMENTO MALICIOSO !!!"); print(f"   Fonte: {log_entry.get('source_type','')}"); print(f"   Categoria: {log_entry.get('event_category','')}"); print(f"   Processo Suspeito: {log_entry.get('process_source','')}"); print(f"   Conteúdo: {log_entry.get('text_content','')}"); print(f"   Modelo score (decision_function): {score:.6f}"); print(f"   Alert reasons: {log_entry.get('_alert_reasons')}"); print("#"*60+"\n")
                else:
                    print(f"[suprimido] evento duplicado (hash) — origem_idx={orig_idx}")
            time.sleep(SLEEP_BETWEEN_EVENTS)
    except KeyboardInterrupt:
        print("\nSimulação interrompida pelo usuário.")
    print(f"Simulação concluída após {ctr} logs.")

if __name__=="__main__": main()
