🧩 README.md — SSH & Kubernetes Exec Function (Azure Functions)
📖 Introduzione

Questa applicazione è una Azure Function scritta in Python che consente di eseguire:

Comandi SSH remoti su server Linux.

Comandi Kubernetes (kubectl) su un cluster remoto, tramite API o kubeconfig.

Il progetto è pensato per essere general purpose e sicuro, con integrazione diretta con Azure Key Vault per la gestione delle credenziali sensibili.

⚙️ Architettura generale
┌─────────────────────────────┐
│        Azure Function       │
│ (Python 3.11 - Premium v3)  │
│                             │
│  ┌──────────────────────┐   │
│  │ SSH Command Handler  │──▶│ Esegue comandi SSH
│  ├──────────────────────┤   │
│  │ K8s Command Handler  │──▶│ Esegue comandi kubectl
│  └──────────────────────┘   │
│                             │
│  ⇄ Azure Key Vault (Secrets)│
│  ⇄ Azure Monitor / Logs     │
└─────────────────────────────┘


Il componente Kubernetes scarica automaticamente il client kubectl al primo avvio e lo salva in una cartella persistente:

/home/site/tools/kubectl


Questo percorso è persistente su un App Service Plan Premium v3, quindi il binario rimane disponibile anche dopo i riavvii o aggiornamenti.

📂 Struttura del pacchetto
app_k8s_premium.zip
├── function_app.py       # codice principale con logica SSH + Kubernetes
├── openapi.json          # descrizione API OpenAPI 3.0
├── requirements.txt      # dipendenze Python
└── README.md             # questo file

🚀 Installazione e Deploy
1️⃣ Prerequisiti

Un’Azure Function App su App Service Plan Premium v3 (P0V3 o superiore)

Runtime Python 3.11

Un Azure Key Vault configurato nella stessa subscription

2️⃣ Configurazione iniziale

Nel portale Azure:

Vai alla tua Function App
→ Configuration → Application Settings

Aggiungi le seguenti variabili d’ambiente:

Nome variabile	Esempio valore	Descrizione
APP_NAME	ai-foundry-ssh-tool	Nome logico dell’app
KEY_VAULT_URL	https://myvault.vault.azure.net/	URL completo del Key Vault
KUBE_CONFIG_SECRET_NAME	my-kubeconfig	Nome del secret che contiene il kubeconfig
KUBE_TOKEN_SECRET_NAME	my-k8s-token	(opzionale) Secret contenente il token
KUBE_USERNAME_SECRET_NAME	my-k8s-user	(opzionale) Username
KUBE_PASSWORD_SECRET_NAME	my-k8s-pass	(opzionale) Password
DEFAULT_KUBECTL_VERSION	v1.30.0	Versione di kubectl da scaricare
KUBECTL_DOWNLOAD_URL_TEMPLATE	https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl	URL base per il download

🔒 Suggerimento: tieni i veri valori delle credenziali dentro Key Vault, non nelle variabili d’ambiente.

3️⃣ Assegna permessi a Key Vault

Vai al tuo Key Vault

Sezione Access control (IAM)

Assegna all’identità gestita della Function App il ruolo:

Key Vault Secrets User


(permette lettura dei secret ma non modifica).

4️⃣ Deploy del pacchetto

Puoi caricare il pacchetto con Azure CLI:

func azure functionapp publish <NOME_FUNZIONE> --python


Oppure dal portale Azure → “Deployment Center” → “Manual Upload”.

⚡ Funzionalità supportate
🟢 1. Esecuzione SSH

Endpoint:

POST /ssh/command?code=<FUNCTION_KEY>


Esegue un comando remoto su server SSH.

Esempio richiesta:

{
  "host": "10.10.0.5",
  "username": "azureuser",
  "password": "mypassword",
  "command": "uname -a"
}

🔵 2. Esecuzione Kubernetes (kubectl)

Endpoint:

POST /k8s/command?code=<FUNCTION_KEY>


Esempio richiesta:

{
  "api_server": "https://10.0.0.1:6443",
  "auth_method": "token",
  "command": "kubectl get pods -A"
}


Esempio risposta:

{
  "command_executed": "kubectl get pods -A",
  "exit_status": 0,
  "stdout": "NAMESPACE   NAME   READY   STATUS...",
  "stderr": "",
  "duration_ms": 1489,
  "request_id": "1730900500012"
}

🧠 Dettagli interni

Al primo avvio, se kubectl non è presente, viene scaricato in:

/home/site/tools/kubectl


Se questa directory non è scrivibile (caso raro), viene usato il fallback:

/tmp/kubectl


Il kubeconfig viene costruito dinamicamente in base a:

il file YAML completo (auth_method = kubeconfig)

token (auth_method = token)

coppia username/password (auth_method = userpass)

Il file temporaneo kubeconfig viene creato in /tmp ed eliminato al termine dell’esecuzione.

🔐 Sicurezza e Best Practice

✅ Non salvare mai credenziali in chiaro
→ usa solo secret Key Vault e variabili d’ambiente con i nomi dei secret.

✅ Evita comandi kubectl distruttivi
→ questa funzione è potente; puoi limitare i comandi permessi a livello API Management.

✅ Monitoraggio e auditing
→ tutte le esecuzioni vengono loggate (senza credenziali), con request_id univoco.

✅ TLS e certificati
→ di default il kubeconfig usa insecure-skip-tls-verify: true.
Per ambienti di produzione, sostituisci con CA certificate valido e imposta certificate-authority-data.

🩺 Troubleshooting
Problema	Possibile causa	Soluzione
kubectl: not found	Download fallito	Verifica che /home/site/tools sia scrivibile
Forbidden (403) da Key Vault	Permessi mancanti	Aggiungi ruolo Key Vault Secrets User all’identità gestita
Unauthorized dal cluster	Token scaduto o credenziali errate	Aggiorna i secret nel Key Vault
TimeoutExpired	Comando troppo lungo	Aumenta timeout_sec nel corpo della richiesta
📜 Dipendenze principali

requirements.txt:

azure-functions
azure-identity
azure-keyvault-secrets
paramiko
PyYAML>=6.0

🧩 Note finali

Testato su Azure Functions Premium v3 - Python 3.10
Compatibile con Azure API Management (grazie a openapi.json)
