# Local AI Assistant Setup — LM Studio (Privacy-First)

The SIEM dashboard ships with an **AI Assistant** page powered entirely by a
local model running in **LM Studio**. No data ever leaves your machine. No
OpenAI, no cloud APIs, no API keys.

The assistant only sees recent alerts and logs from your own `siem.db`.

---

## 1. Install LM Studio

Download from <https://lmstudio.ai> and install for Windows.

## 2. Download the model

Inside LM Studio, search and download:

```
qwen3-4b-instruct-2507
```

(A ~3–4 GB quantized GGUF build is fine for most laptops.)

## 3. Load the model

In LM Studio, go to the **Chat** or **My Models** view and click **Load** on
`qwen3-4b-instruct-2507`. Wait until the status shows "Loaded".

## 4. Open the Developer / Local Server panel

In LM Studio, open the **Developer** tab (sometimes labeled **Local Server**).

## 5. Start the server on http://localhost:1234

- Server port: `1234`
- Server host: `localhost`
- OpenAI-compatible endpoint must be enabled (it is by default).

Click **Start Server**. You should see the green "Running" indicator.

## 6. Confirm LM Studio is reachable

Open PowerShell and run:

```powershell
curl.exe http://localhost:1234/v1/models
```

The response must list `qwen3-4b-instruct-2507` in the `data` array.

## 7. Start the SIEM dashboard

From the project folder:

```powershell
pip install -r requirements.txt
python siem_web.py
```

## 8. Open the dashboard

<http://localhost:5000>

Log in (default: `admin / admin123`), then click **AI Assistant** in the
sidebar.

The status card should turn green with **"Local AI Online"**. Type a question
or click one of the suggested prompts, then press **Ask**.

---

## Important — this is local only

The AI will **NOT** work on another computer unless that computer:

1. Has **LM Studio installed**.
2. Has the **`qwen3-4b-instruct-2507` model downloaded**.
3. Has the **Local Server running on port 1234**.

There is no fallback to any cloud provider. That is by design — the assistant
is privacy-first and air-gapped from the public internet.

---

## Troubleshooting

| Symptom on the AI Assistant page                 | What to do                                                                                     |
|--------------------------------------------------|------------------------------------------------------------------------------------------------|
| "Local AI Offline" / "Cannot reach LM Studio"    | Open LM Studio → Developer → **Start Server**. Confirm port `1234`.                            |
| "LM Studio is running but model … is not loaded" | In LM Studio, load the **exact** model id `qwen3-4b-instruct-2507`.                            |
| "Local AI timed out"                             | The model is too large or system is busy. Try a smaller quant or close other heavy programs.   |
| `curl` to `/v1/models` returns nothing           | The Local Server is not running, or another app is using port `1234`.                          |

---

## Endpoints used by the dashboard

| Method | Route               | Purpose                                              |
|--------|---------------------|------------------------------------------------------|
| GET    | `/api/ai/status`    | Check whether LM Studio is online + model is loaded. |
| GET    | `/api/ai/context`   | Returns the SIEM context (last 10 alerts + 10 logs). |
| POST   | `/api/ai/ask`       | Sends the question + SIEM context to LM Studio.      |

All three require login. None of them call any external service.
