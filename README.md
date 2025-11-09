
# 🧩 Azure Functions Tools Suite — SSH, Kubernetes, Atlas CLI e MongoDB

## Sommario esecutivo
Questa soluzione implementa una **Azure Function App** (Python 3.10+) che espone un set di **API sicure** per l’esecuzione di attività operative su infrastrutture enterprise, con **gestione centralizzata dei segreti** tramite **Azure Key Vault** e **tracciabilità completa** per audit e compliance:

- 🟢 **SSH Exec**: esecuzione di comandi remoti su host Linux.
- 🔵 **Kubernetes Exec**: esecuzione di comandi `kubectl`/`oc` contro cluster Kubernetes/OpenShift.
- 🟣 **Atlas Exec**: amministrazione **MongoDB Atlas** via Atlas CLI.
- 🟠 **Mongo Exec**: query e operazioni su database **MongoDB** (find, distinct, aggregate, CRUD ove consentito).

La piattaforma è pensata per team **IT Operations**, **DBA**, **DevOps** e **LLM Agents** che necessitano di eseguire diagnosi e cambi controllati in ambienti **prod**/**non‑prod**, garantendo **sicurezza**, **governance** e **osservabilità**.

---

## Scopo, contesto d’uso e principi
**Chi**: SOC/NOC, SRE/DevOps, DBA, Platform/Infra Engineers, LLM Agents orchestrati.  
**Cosa**: Automazione sicura di comandi su Linux, cluster Kubernetes/OpenShift, risorse Atlas e database MongoDB.  
**Dove**: Azure Functions Premium v3, con rete aziendale e Key Vault della stessa subscription/tenant.  
**Come**: API REST con autenticazione **Function Key** e risoluzione credenziali **via Key Vault** (Managed Identity).  
**Quando**: Incident/diagnostica, Change controllati, attività programmate e runbook, integrazione con API Management o agenti LLM.  
**Perché**: Ridurre rischio operativo, standardizzare procedure, massimizzare auditabilità e separazione dei segreti dal piano di esecuzione.

**Principi**
- **Zero secrets in transit**: nessuna credenziale nei payload; i segreti sono letti runtime da Key Vault tramite Managed Identity. 
- **Minimo privilegio**: credenziali e token con scope limitato; RBAC/Sudo dove applicabile. 
- **Tracciabilità**: ogni richiesta ha `request_id`; log strutturati e misure di timing. 
- **Sicurezza by design**: TLS/HTTPS, gestione versioni client (kubectl/atlas), output controllato.

---

## Architettura di alto livello
```
┌────────────────────────────────────────────┐
│               Azure Function App           │
│         (Python 3.10+ — Premium v3)        │
│                                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│   │  SSH     │  │  K8s     │  │  Atlas   │ │  → Azioni operative
│   └──────────┘  └──────────┘  └──────────┘ │
│           └──────────┐                     │
│              Mongo   │                     │
│              (PyMongo)                     │
│                                            │
│ ⇄ Azure Key Vault (Secrets)                │
│ ⇄ Azure Monitor / App Insights             │
└────────────────────────────────────────────┘
```
**Persistenza binari client**
- `kubectl` → `/home/site/tools/kubectl` (fallback `/tmp`) 
- `atlas`/`mongocli` → `/home/site/tools/mongodb-atlas-cli` (fallback `/tmp`)

---

## Sicurezza e compliance
- **Autenticazione API**: Function Key tramite header `x-functions-key` (raccomandato) o query `?code=`. 
- **Gestione segreti**: tutti i secret (SSH, Kubernetes, Atlas API Keys, Mongo creds/URI) sono in **Azure Key Vault**; l’app legge solo ciò che serve (`get`/`list`). 
- **Cifratura in transito**: HTTPS obbligatorio. 
- **Logging**: log strutturati con `request_id`, durata e codici di uscita; integrazione con Application Insights. 
- **Conformità**: best practice **ISO 27001**, **NIST**, **ITIL Change**. 

> Nota: Evitare di stampare URI o credenziali nei log/report. Le risposte non includono mai segreti.

---

## Endpoint e semantica operativa
Tutti gli endpoint accettano `POST` con `Content-Type: application/json` e supportano l’header di sicurezza `x-functions-key`.

### 1) SSH Exec
**Endpoint**  
`POST /ssh/exec?code=<FUNCTION_KEY>`

**Payload**
```json
{
  "host": "192.168.1.10",
  "command": "df -h",
  "timeout_sec": 20
}
```

**Esempio curl**
```bash
curl -X POST "https://<APP>.azurewebsites.net/ssh/exec?code=<FUNCTION_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.1.10","command":"df -h","timeout_sec":20}'
```

**Note**
- Credenziali SSH (username/password o chiave) risolte da Key Vault. 
- `AUTH_PREFERENCE`: `auto` (default), `key`, `password`.

---

### 2) Kubernetes Exec
**Endpoint**  
`POST /k8s/exec?code=<FUNCTION_KEY>`

**Payload**
```json
{
  "api_server": "https://cluster.company.net:6443",
  "auth_method": "token",
  "command": "get pods -A",
  "timeout_sec": 30
}
```

**Esempio curl**
```bash
curl -X POST "https://<APP>.azurewebsites.net/k8s/exec?code=<FUNCTION_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"api_server":"https://cluster.company.net:6443","auth_method":"token","command":"get pods -A","timeout_sec":30}'
```

**Note**
- Autenticazione: `kubeconfig` | `token` | `userpass` | `auto` (priorità: kubeconfig > token > userpass). 
- Il servizio scarica `kubectl` al primo uso e imposta `KUBECONFIG` temporaneo. 
- Il campo `command` può essere passato **senza** prefisso `kubectl` (es. `get pods -A`); il servizio normalizza.

---

### 3) Atlas Exec
**Endpoint**  
`POST /atlas/exec?code=<FUNCTION_KEY>`

**Payload**
```json
{
  "command": "clusters list",
  "auth_method": "auto",
  "timeout_sec": 120
}
```

**Esempio curl**
```bash
curl -X POST "https://<APP>.azurewebsites.net/atlas/exec?code=<FUNCTION_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"command":"clusters list","auth_method":"auto","timeout_sec":120}'
```

**Note**
- Autenticazione: `api_key` | `profile` | `auto` (preferenza API Key). 
- API Keys e profili sono risolti in ambiente/Key Vault; nessuna credenziale nel payload.

---

### 4) Mongo Exec
**Endpoint**  
`POST /mongo/exec?code=<FUNCTION_KEY>`

**Payload**
```json
{
  "database": "appdb",
  "script": "{\"collection\":\"users\",\"operation\":\"find\",\"filter\":{\"active\":true}}",
  "auth_method": "auto",
  "timeout_sec": 120
}
```

**Esempio curl**
```bash
curl -X POST "https://<APP>.azurewebsites.net/mongo/exec?code=<FUNCTION_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"database":"appdb","script":"{\"collection\":\"users\",\"operation\":\"find\",\"filter\":{\"active\":true}}","auth_method":"auto","timeout_sec":120}'
```

**Script JSON (stringa) — esempi**
- **find**
  ```json
  {"collection":"users","operation":"find","filter":{"active":true}}
  ```
- **distinct**
  ```json
  {"collection":"users","operation":"distinct","field":"country","filter":{}}
  ```
- **aggregate**
  ```json
  {"collection":"orders","operation":"aggregate","pipeline":[{"$match":{"status":"closed"}},{"$group":{"_id":"$product","qty":{"$sum":"$qty"}}},{"$sort":{"qty":-1}},{"$limit":5}]}
  ```

**Note**
- Autenticazione: `userpass` | `uri` | `auto` (preferenza **userpass** con host/credenziali da Key Vault). 
- L’URI finale non viene loggato né restituito.

---

## Configurazione applicativa (App Settings)
> I valori che terminano in `_SECRET_NAME` sono **nomi di secret** in Key Vault (non i contenuti).

**Core**
- `KEY_VAULT_URL` — es. `https://<kv>.vault.azure.net/`

**SSH**
- `SSH_USERNAME_SECRET_NAME`, `SSH_PASSWORD_SECRET_NAME` (opz.)  
- `SSH_PRIVATE_KEY_SECRET_NAME`, `SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME` (opz.)  
- `AUTH_PREFERENCE` = `auto` | `key` | `password`  
- `ALLOW_UNKNOWN_HOSTS` = `true`/`false`

**Kubernetes**
- `KUBE_CONFIG_SECRET_NAME`, `KUBE_TOKEN_SECRET_NAME` (opz.), `KUBE_USERNAME_SECRET_NAME` (opz.), `KUBE_PASSWORD_SECRET_NAME` (opz.)  
- `K8S_AUTH_PREFERENCE` = `auto` | `kubeconfig` | `token` | `userpass`
- `DEFAULT_KUBECTL_VERSION`, `KUBECTL_DOWNLOAD_URL_TEMPLATE`

**Atlas**
- `ATLAS_PUBLIC_KEY_SECRET_NAME`, `ATLAS_PRIVATE_KEY_SECRET_NAME`  
- `ATLAS_AUTH_PREFERENCE` = `auto` | `api_key` | `profile`  
- `ATLAS_DEFAULT_PROFILE` (opz.)

**Mongo**
- `MONGO_AUTH_PREFERENCE` = `auto` | `userpass` | `uri`  
- `MONGO_USERNAME_SECRET_NAME`, `MONGO_PASSWORD_SECRET_NAME`  
- `MONGO_HOST` **o** `MONGO_HOST_SECRET_NAME`  
- `MONGO_URI_SECRET_NAME` (fallback)  
- `MONGO_SCHEME` (`mongodb+srv` di default), `MONGO_AUTH_DB` (`admin`), `MONGO_OPTIONS`, `MONGO_TLS`

---

## Distribuzione (indicazioni sintetiche)
1. **Provisioning risorse** (RG, Storage, Function App, Key Vault).  
2. **Managed Identity**: abilita l’identità della Function App.  
3. **IAM Key Vault**: assegna ruolo **Key Vault Secrets User**.  
4. **Secrets**: popola i secret necessari (SSH/K8s/Atlas/Mongo).  
5. **App Settings**: imposta tutte le variabili di configurazione.  
6. **Publish**: `func azure functionapp publish <APP> --python`.  

---

## Logging, osservabilità e auditing
- **request_id** in risposta e nei log per correlazione end‑to‑end. 
- **Durate** e **exit code** restituiti in ogni chiamata. 
- Integrazione con **Application Insights** per metriche, tracce e query Kusto. 
- Raccomandato: centralizzare i report esito e i log operativi in uno storage dedicato.

---

## Troubleshooting (selezione)
| Sintomo | Possibile causa | Azione correttiva |
|---|---|---|
| `kubectl: not found` | Download fallito / path non scrivibile | Verifica permessi su `/home/site/tools` o usa fallback `/tmp` |
| 403 Key Vault | MI senza permessi | Assegna **Key Vault Secrets User** alla Function App |
| 401/403 Cluster | Token scaduto / credenziali errate | Aggiorna secret in Key Vault |
| `TimeoutExpired` | Comando troppo lungo | Aumenta `timeout_sec` per la singola invocazione |
| SSH `AuthFailed` | Credenziali/key non valide | Verifica secret e preferenza `AUTH_PREFERENCE` |

---

## Dipendenze (requirements)
```txt
azure-functions==1.21.3
pydantic==1.10.17
paramiko==3.5.0
azure-identity==1.17.1
azure-keyvault-secrets==4.9.0
PyYAML>=6.0
pymongo>=4.8.0
```

---

## FAQ essenziali
- **Posso passare le credenziali nel payload?** No. I segreti sono sempre risolti dal Key Vault.  
- **Devo includere `kubectl` nel campo `command`?** Non necessario; il servizio normalizza. 
- **L’URI Mongo è esposto?** No, non viene mai restituito né loggato.
- **Atlas CLI supporta login username/password?** In automazione si usano **API Keys** o **profile**.
