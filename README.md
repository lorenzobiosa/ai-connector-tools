# 🧩 README.md — Azure Function SSH & Kubernetes Exec Tool

## 📖 Introduzione

Questa applicazione è una **Azure Function** sviluppata in **Python 3.10+**, progettata per eseguire in modo sicuro e tracciabile:

- 🟢 **Comandi SSH** remoti su server Linux enterprise  
- 🔵 **Comandi Kubernetes/OpenShift** (tramite `kubectl_exec`) su cluster remoti

L’obiettivo è fornire un **tool di automazione e diagnostica controllata**, utilizzabile da sistemi IT Ops, LLM Agent o API Management, nel rispetto di policy **ITIL**, **ISO 27001**, e **NIST**.

La funzione integra **Azure Key Vault** per la gestione sicura delle credenziali e produce **log e report dettagliati** per audit, CMDB e post-mortem.

---

## ⚙️ Architettura generale

```text
┌────────────────────────────────────────────┐
│              Azure Function App            │
│        (Python 3.10+ – Premium v3)         │
│                                            │
│  ┌──────────────────────┐   ┌────────────┐  │
│  │ SSH Command Handler  │ → │ Linux Host │  │
│  ├──────────────────────┤   └────────────┘  │
│  │ K8s Command Handler  │ → │ K8s Cluster│  │
│  └──────────────────────┘   └────────────┘  │
│                                            │
│  ⇄ Azure Key Vault (Secrets)               │
│  ⇄ Azure Monitor / Application Insights    │
└────────────────────────────────────────────┘
```

Il componente **Kubernetes** scarica automaticamente il binario `kubectl` al primo avvio e lo conserva in:

```
/home/site/tools/kubectl
```

Questo percorso è **persistente** su **App Service Plan Premium v3 (P0V3 o superiore)**, assicurando che il client rimanga disponibile anche dopo riavvii o aggiornamenti.

---

## 📦 Struttura del pacchetto

```
app_k8s_premium.zip
├── function_app.py       # logica SSH + Kubernetes
├── openapi.json          # specifica OpenAPI 3.0 per integrazione API
├── requirements.txt      # dipendenze Python
└── README.md             # questo documento
```

---

## 🚀 Installazione e Deploy

### 1️⃣ Prerequisiti

- Azure Function App su **App Service Plan Premium v3 (P0V3 o superiore)**  
- Runtime: **Python 3.10+**  
- Un **Azure Key Vault** configurato nella stessa subscription  

### 2️⃣ Configurazione iniziale

Nel **Portale Azure** → *Function App → Configuration → Application Settings*, aggiungi:

| Nome variabile | Esempio valore | Descrizione |
|----------------|----------------|--------------|
| `APP_NAME` | `ai-foundry-ssh-tool` | Nome logico dell’app |
| `KEY_VAULT_URL` | `https://myvault.vault.azure.net/` | URL completo del Key Vault |
| `KUBE_CONFIG_SECRET_NAME` | `my-kubeconfig` | Nome del secret contenente il kubeconfig |
| `KUBE_TOKEN_SECRET_NAME` | `my-k8s-token` | (opz.) Token JWT Kubernetes |
| `KUBE_USERNAME_SECRET_NAME` | `my-k8s-user` | (opz.) Username |
| `KUBE_PASSWORD_SECRET_NAME` | `my-k8s-pass` | (opz.) Password |
| `DEFAULT_KUBECTL_VERSION` | `v1.30.0` | Versione `kubectl` predefinita |
| `KUBECTL_DOWNLOAD_URL_TEMPLATE` | `https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl` | Template URL di download |

> 💡 **Suggerimento**: conserva le credenziali nel **Key Vault**, non direttamente nelle variabili d’ambiente.

### 3️⃣ Assegnazione permessi a Key Vault

Nel **Key Vault** → *Access control (IAM)*:

- assegna all’identità gestita della Function App il ruolo **Key Vault Secrets User**  
  (permette la lettura dei secret senza privilegi di scrittura).

### 4️⃣ Deploy del pacchetto

#### Tramite Azure CLI
```bash
func azure functionapp publish <NOME_FUNZIONE> --python
```

#### Oppure tramite portale
*Function App → Deployment Center → Manual Upload*  
→ carica `app_k8s_premium.zip`.

---

## ⚡ Funzionalità supportate

### 🟢 1. Esecuzione SSH remota

Endpoint:
```
POST /ssh/command?code=<FUNCTION_KEY>
```

Esegue un comando su un host remoto via **SSH**.

#### Esempio richiesta
```json
{
  "host": "10.10.0.5",
  "username": "azureuser",
  "password": "mypassword",
  "command": "uname -a"
}
```

#### Esempio risposta
```json
{
  "command_executed": "uname -a",
  "exit_status": 0,
  "stdout": "Linux host01 5.15.0-1061-azure ...",
  "stderr": "",
  "duration_ms": 842,
  "request_id": "1730900450012"
}
```

#### Esempio con `curl`
```bash
curl -X POST   -H "Content-Type: application/json"   -d '{"host":"10.10.0.5","username":"azureuser","password":"mypassword","command":"df -h"}'   "https://<FUNCTION_APP>.azurewebsites.net/api/ssh/command?code=<FUNCTION_KEY>"
```

---

### 🔵 2. Esecuzione Kubernetes (kubectl_exec)

Endpoint:
```
POST /k8s/exec?code=<FUNCTION_KEY>
```

Esegue comandi `kubectl` o `oc` (OpenShift) su un cluster remoto.  
Supporta autenticazione tramite **token**, **username/password**, o **kubeconfig**.

#### Esempio richiesta
```json
{
  "api_server": "https://10.0.0.1:6443",
  "auth_method": "token",
  "command": "kubectl get pods -A",
  "timeout_sec": 20
}
```

#### Esempio risposta
```json
{
  "command_executed": "kubectl get pods -A",
  "exit_status": 0,
  "stdout": "NAMESPACE   NAME   READY   STATUS   RESTARTS   AGE\nkube-system coredns-7d7f6b8fbd-hx4v2 1/1 Running 0 10d",
  "stderr": "",
  "duration_ms": 1489,
  "request_id": "1730900500012"
}
```

#### Esempio `curl`
```bash
curl -X POST   -H "Content-Type: application/json"   -d '{"api_server":"https://10.0.0.1:6443","auth_method":"token","command":"kubectl get pods -A"}'   "https://<FUNCTION_APP>.azurewebsites.net/api/k8s/exec?code=<FUNCTION_KEY>"
```

---

## 🧭 Workflow operativo

### 1️⃣ Analisi della richiesta
- Interpreta la richiesta in linguaggio naturale.  
- Identifica:
  - 🔹 tipo di attività: *Incident*, *Change*, *Inquiry*  
  - 🔹 target: host Linux o cluster Kubernetes  
  - 🔹 comando da eseguire.  
- Se i dati non sono completi → chiedi conferma o chiarimenti prima di procedere.

### 2️⃣ Raccolta evidenze (Incident / Diagnosi)
Per Kubernetes/OpenShift:
```bash
kubectl get pods -A -o wide
kubectl get nodes -o wide
kubectl describe pod <pod> -n <ns>
kubectl logs <pod> -n <ns> --tail=50
kubectl get svc,ingress,networkpolicy -A
```

Per SSH/Linux:
```bash
df -h
systemctl status
top -b -n1 | head -20
journalctl -n 50
```

### 3️⃣ Pianificazione dell’azione (Change / Fix)
- Definisci:
  - motivo e obiettivo
  - comando da eseguire
  - piano di rollback
  - impatto previsto
- Chiedi conferma per azioni impattanti o irreversibili  
  (es.: `kubectl delete`, `scale`, `apply`, `systemctl restart`).

### 4️⃣ Esecuzione controllata
Costruisci il payload (esempio K8s):

```json
{
  "api_server": "https://cluster.company.net:6443",
  "auth_method": "token",
  "command": "kubectl rollout restart deployment/web -n prod",
  "timeout_sec": 30
}
```

Invoca la funzione **solo dopo conferma**.  
Non includere credenziali → sono recuperate dal Key Vault.

### 5️⃣ Post-esecuzione e verifica
- Valida l’esito (`Ready` / `Running` / `Completed`)  
- Se si tratta di un *change*, verifica rollback e stato finale.  
- Registra il risultato:
  ```
  SUCCESS / WARNING / ERROR
  ```

### 6️⃣ Report e logging
Ogni attività genera:
- descrizione e contesto  
- timestamp UTC  
- comandi eseguiti  
- output significativo  
- stato finale  
- eventuale rollback plan  
- Ticket / RFC ID  

I file vengono salvati in:
```
logs_dir/   → log tecnici
reports_dir/ → report sintetici
```

---

## ⚙️ Regole operative e sicurezza

- 🔒 **Nessuna credenziale in chiaro** — usa solo Key Vault  
- 🚫 **Niente comandi distruttivi**, come:
  ```
  kubectl delete namespace
  kubectl delete pvc --all
  rm -rf /
  mkfs, dd, reboot, shutdown
  ```
- ⏱️ **Timeout predefinito:** 20 s  
- ⚖️ **Principio del minimo privilegio:** RBAC o sudo controllato  
- 🌐 **Compatibilità cross-environment:** Kubernetes, OpenShift, EKS, AKS, GKE  
- 🧾 **Audit e tracciabilità:** ogni operazione è loggata con request_id  
- ❓ **Incertezza = stop:** se mancano parametri critici, fermati e chiedi conferma

---

## 🔐 Sicurezza e compliance

- Tutte le connessioni sono **HTTPS/SSH sicure**  
- Secret e token provengono da **Azure Key Vault**  
- Nessun secret viene mai stampato o memorizzato nei log  
- Conformità con **ISO 27001**, **NIST**, **ITIL Change Control**  
- Per ambienti di produzione, imposta CA certificate valido nel kubeconfig  
  (sostituisci `insecure-skip-tls-verify: true`).

---

## 🩺 Troubleshooting

| Problema | Possibile causa | Soluzione |
|-----------|----------------|------------|
| `kubectl: not found` | Download fallito o path errato | Verifica che `/home/site/tools` sia scrivibile |
| 403 da Key Vault | Mancanza permessi IAM | Assegna il ruolo `Key Vault Secrets User` |
| 401 Unauthorized dal cluster | Token scaduto | Aggiorna il secret nel Key Vault |
| `TimeoutExpired` | Comando troppo lungo | Aumenta `timeout_sec` nel payload |
| `Permission denied` SSH | Credenziali o chiavi errate | Controlla secret e autorizzazioni utente |

---

## 📜 Dipendenze principali

`requirements.txt`
```txt
azure-functions
azure-identity
azure-keyvault-secrets
paramiko
PyYAML>=6.0
```

---

## 🧩 Note finali

- ✅ Testato su **Azure Functions Premium v3 – Python 3.10+**  
- ✅ Compatibile con **Azure API Management** e **GitHub Actions CI/CD**  
- ✅ Kubectl viene memorizzato persistentemente in `/home/site/tools` (fallback: `/tmp`)  
- ✅ Logging dettagliato e report JSON strutturati  
- 🧠 Può essere integrato con agenti LLM o automazioni operative aziendali  





# Azure Function — SSH Exec Tool (LLM-driven, API Key via query)

Espone `POST /ssh/exec` per eseguire comandi SSH su host Linux.  
Le credenziali sono recuperate da **Azure Key Vault** tramite **Managed Identity**.  
**Autenticazione HTTP**: query param `?code=<FUNCTION_KEY>` (Azure Functions).

## Caratteristiche
- 🔐 Nessuna credenziale nel payload: username/password/chiave sono in Key Vault.
- 🔁 Supporto password e chiave (preferenza via `AUTH_PREFERENCE`).
- 🖧 Host sconosciuti accettati automaticamente (`ALLOW_UNKNOWN_HOSTS=true`, default).
- ⏱️ Timeout/limit output per robustezza.
- 📈 Log strutturati con `request_id` (Application Insights).

## Variabili d'ambiente (App Settings)
> I valori indicano **nomi di secret** in Key Vault (non i contenuti).

- `KEY_VAULT_URL` → `https://<kv>.vault.azure.net/`
- `SSH_USERNAME_SECRET_NAME` → es. `ssh-username-pippo` **(obbl.)**
- `SSH_PASSWORD_SECRET_NAME` → es. `ssh-password-pippo` (opz.)
- `SSH_PRIVATE_KEY_SECRET_NAME` → es. `ssh-key-pippo` (opz., PEM plain o base64 del PEM)
- `SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME` → es. `ssh-key-passphrase-pippo` (opz.)
- `AUTH_PREFERENCE` → `auto` (default) \| `key` \| `password`
- `ALLOW_UNKNOWN_HOSTS` → `true` (default) \| `false`
- `SSH_DEFAULT_PORT` (22), `SSH_CONNECT_TIMEOUT_SEC` (10), `SSH_COMMAND_TIMEOUT_SEC` (30), `MAX_OUTPUT_BYTES` (262144)

## Deploy rapido (CLI)
```bash
RG=rg-ai-tools
LOC=westeurope
APP=func-ssh-tool-prod
KV=kv-ai-tools-prod

az group create -n $RG -l $LOC
az storage account create -n ${APP//-/}sa -g $RG -l $LOC --sku Standard_LRS --kind StorageV2
az functionapp create -n $APP -g $RG -s ${APP//-/}sa \
  --consumption-plan-location $LOC --runtime python --runtime-version 3.10 --functions-version 4 --os-type Linux

az functionapp identity assign -g $RG -n $APP
PRINCIPAL_ID=$(az functionapp identity show -g $RG -n $APP --query principalId -o tsv)

az keyvault create -n $KV -g $RG -l $LOC --enable-purge-protection true --enable-soft-delete true
az keyvault set-policy -n $KV --object-id $PRINCIPAL_ID --secret-permissions get list

# Secret di esempio
az keyvault secret set -n ssh-username-pippo --vault-name $KV --value "pippo"
az keyvault secret set -n ssh-password-pippo --vault-name $KV --value "pluto"
# oppure chiave:
# az keyvault secret set -n ssh-key-pippo --vault-name $KV --value "$(cat id_rsa)"
# az keyvault secret set -n ssh-key-passphrase-pippo --vault-name $KV --value "mypass"

# App settings (nomi dei secret)
az functionapp config appsettings set -g $RG -n $APP --settings \
  "KEY_VAULT_URL=https://$KV.vault.azure.net/" \
  "SSH_USERNAME_SECRET_NAME=ssh-username-pippo" \
  "SSH_PASSWORD_SECRET_NAME=ssh-password-pippo" \
  "SSH_PRIVATE_KEY_SECRET_NAME=" \
  "SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME=" \
  "AUTH_PREFERENCE=auto" \
  "ALLOW_UNKNOWN_HOSTS=true"
```

## Ottenere la Function Key (x-functions-key)
```bash
# Recupera la default function key (host key) a livello app
az functionapp function keys list -g $RG -n $APP --function-name ssh_exec
# In alternativa (host keys):
az rest --method post \
  --url "https://management.azure.com/subscriptions/<SUB_ID>/resourceGroups/$RG/providers/Microsoft.Web/sites/$APP/host/default/listkeys?api-version=2022-03-01"
```

> Usa il valore "default" o la key specifica della function. Questa key va messa nell’header x-functions-key.

## Come integrare in Azure AI Foundry

1. **Importa `openapi.yaml`** nel tuo progetto AI Foundry come **Tool HTTP**.
2. Configura la sicurezza:
   - Tipo: **API Key**
   - Location: **Query**
   - Parameter name: `code`
   - Value: incolla la **Function Key** della funzione `ssh_exec`:
     ```bash
     az functionapp function keys list -g <RG> -n <APP> --function-name ssh_exec
     ```
3. Salva il Tool.
4. Testa il Tool con:
   ```json
   {
     "host": "192.168.1.1",
     "command": "df -h",
     "timeout_sec": 20
   }

## Integrazione con Azure AI Foundry

1. Importa openapi.yaml nel tuo progetto AI Foundry come Tool HTTP.
2. Configura l’autenticazione del Tool:
   - Tipo: **API Key** (Header)
   - **Header name**: x-functions-key
   - **API Key value**: <i>incolla la Function Key</i> (meglio tramite secret store del progetto).
3. Uso nel tuo agente (esempio flusso):
   - Prompt utente: “Dammi lo spazio libero su 192.168.1.1”
   - L’LLM genera la chiamata al tool sshExec:
     ```bash
     {
       "host": "192.168.1.1",
       "command": "df -h",
       "timeout_sec": 20
     }
     ```
   - AI Foundry invia HTTP POST `/ssh/exec` con header `x-functions-key: <FUNCTION_KEY>`.
   - L’LLM legge la risposta JSON e presenta l’output all’utente.

## Esecuzione locale
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
func start
```

## Esempio di chiamata manuale
```bash
curl -X POST "https://<APP>.azurewebsites.net/ssh/exec?code=<FUNCTION_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.1.1","command":"df -h","timeout_sec":20}'
```

## Troubleshooting
- 401 → chiave errata/mancante oppure autenticazione SSH fallita: verifica header x-functions-key e i secret in KV.
- 207 con exit_status != 0 → il comando è andato in errore; controlla stderr.
- 408 → aumenta SSH_COMMAND_TIMEOUT_SEC o verifica la raggiungibilità dell’host.
