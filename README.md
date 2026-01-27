# PVE Middle API

這是一個專為 Proxmox VE (PVE) 設計的中介服務 API，核心目標是實現 GPU 資源的「動態調度」與「虛擬機自動化管理」。

本系統作為 PVE 與上層計費/管理系統之間的中介層，提供規格同步、資源隔離、與多租戶權限管理功能。

## 核心機制

### 1. GPU 資源動態調度 (Dynamic GPU Attachment)
- **非持久化掛載**：虛擬機 (VM) 在建立時並不佔用物理 GPU 資源。
- **開機時掛載**：僅在接收到開機請求時，系統會掃描 PVE 叢集中的 GPU 資源池，尋找符合需求的可用裝置並動態寫入 VM 設定。
- **關機時釋放**：VM 關機後自動移除 HostPCI 設定，將 GPU 釋放回資源池，最大化硬體利用率。

### 2. 規格同步 (Specification Synchronization)
- **資料庫優先**：資料庫作為規格的「單一事實來源」(Source of Truth)。
- **自動修正**：每次開機前，系統會自動比對資料庫與 PVE 的設定。若 CPU、記憶體或 GPU 數量不符，系統會自動更新 PVE 設定後再行啟動。

### 3. 安全性與隱私
- **無硬編碼憑證**：所有敏感資訊（PVE Token, DB 密碼, API URL）均透過環境變數管理。
- **外部驗證整合**：支援轉發 `Authorization` Header 與 Cookies 至上游驗證系統 (如 Billing System) 進行身份確認。

---

## 快速開始

### 1. 環境設定

請複製 `.env.example` 為 `.env` 並填入您的設定：

```ini
# Proxmox 連線
PROXMOX_HOST=10.2.x.x
PROXMOX_TOKEN_VALUE=your-token-value
# ...

# 外部驗證系統
AUTH_API_URL="https://billing.example.com/api/auth/me"
```

### 2. 啟動服務

```bash
docker-compose up --build -d
```

API 文件預設位於：`http://localhost:8000/docs` (需登入)
- **預設文件帳號**: `admin`
- **預設文件密碼**: 請參考 `.env` 中的 `DOCS_PASSWORD`

---

## API 接口使用說明

以下範例假設服務運行於 `http://localhost:8000`，且您已獲取合法的 `Authorization: Bearer <token>`。

### 1. 系統配置 (System Config)

**GET /system/config**
取得全域設定，包括可用的 VM 規格模板 (Profiles) 與作業系統模板 (OS Templates)。

```bash
curl -X GET http://localhost:8000/system/config \
  -H "Authorization: Bearer <your_token>"
```

### 2. 虛擬機管理 (VM Management)

**GET /vms**
列出虛擬機。
- **Admin**: 列出所有 VM。
- **User**: 僅列出屬於自己的 VM。
- 回傳資料會自動合併 PVE 的即時狀態 (Status, Node, IP) 與 DB 中的規格 (CPU, RAM, GPU)。

```bash
curl -X GET http://localhost:8000/vms \
  -H "Authorization: Bearer <your_token>"
```

**POST /vms**
建立新的虛擬機。此操作僅會在 PVE 建立 VM 實體並寫入 DB 紀錄，**不會**立即分配 GPU。

```bash
curl -X POST http://localhost:8000/vms \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{
    "vm_name": "gpu-lab-01",
    "username": "user123",           # VM 擁有者
    "password": "StrongPassword!",   # 系統初始密碼 (Cloud-init)
    "storage_size": 100,             # Disk Size (GB)
    "vm_profile": 2,                 # 1=1GPU, 2=2GPU, 4=4GPU (參照 System Config)
    "vm_template": 1000,             # 來源 Template ID
    "required_ib": false,
    "creator_username": "admin",     # 建立者
    "creator_role": "admin"
  }'
```

**DELETE /vms/{vmid}**
刪除虛擬機。同步刪除 PVE 實體與 DB 紀錄。

```bash
curl -X DELETE http://localhost:8000/vms/105 \
  -H "Authorization: Bearer <your_token>"
```

### 3. 電源與資源控制 (Power Control)

**POST /vms/{vmid}/start**
**啟動 VM (核心功能)**。
- 自動同步 CPU/RAM 規格。
- 掃描並鎖定可用的 GPU 資源。
- 若 VM 不在資源充足的節點，自動執行遷移 (Migrate)。
- 掛載 GPU 後開機。

```bash
curl -X POST http://localhost:8000/vms/105/start \
  -H "Authorization: Bearer <your_token>"
```

**POST /vms/{vmid}/stop**
關閉 VM。
- 關機後自動執行資源清理，將 GPU/IB 裝置從設定檔移除，釋放給其他人使用。

```bash
curl -X POST http://localhost:8000/vms/105/stop \
  -H "Authorization: Bearer <your_token>"
```

**POST /vms/{vmid}/reboot**
重啟 VM。

```bash
curl -X POST http://localhost:8000/vms/105/reboot \
  -H "Authorization: Bearer <your_token>"
```

**GET /vms/{vmid}/status**
查詢單一 VM 的詳細狀態。

```bash
curl -X GET http://localhost:8000/vms/105/status \
  -H "Authorization: Bearer <your_token>"
```

### 4. IP 資源池管理 (IP Pools)

**GET /ip-pools**
查看內部 IP 使用狀況。

```bash
curl -X GET http://localhost:8000/ip-pools \
  -H "Authorization: Bearer <your_token>"
```

---

## 開發者指南

### 資料庫 Schema (UserVM)
主要欄位說明：
- `vmid`: Proxmox VM ID (Primary Key)
- `username`: 綁定的使用者帳號
- `gpu_count`: 該 VM 獲准使用的 GPU 數量 (規格來源)
- `cpu_cores`: CPU 核心數 (規格來源)
- `memory_mb`: 記憶體大小 (規格來源)

### 錯誤處理
API 會回傳標準 HTTP Status Code：
- `200 OK`: 成功
- `400 Bad Request`: 參數錯誤或資源不足 (如無可用 GPU)
- `401 Unauthorized`: 未登入或 Token 無效
- `403 Forbidden`: 權限不足 (如 User 嘗試刪除他人的 VM)
- `500 Internal Server Error`: PVE 連線失敗或伺服器錯誤