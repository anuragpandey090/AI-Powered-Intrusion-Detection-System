# Dataset Inspection, Integrity Audit & Methodology

## 1. Raw Dataset Verification

The system was trained, evaluated, and verified using the **CIC-IDS2017 (MachineLearningCVE)** benchmark dataset produced by the Canadian Institute for Cybersecurity (University of New Brunswick).

- **Raw Directory:** `E:\IILM\Major Project\raw\MachineLearningCVE`
- **Total Files:** 8 CSV files
- **Total Uncompressed Size:** 884.2 MB
- **Total Network Flow Records:** **2,830,743 flows**
- **Canonical Feature Count:** **78 flow statistical features** + 1 Label column

### Audited File Manifest & Checksums

The integrity audit was executed non-destructively via `scripts/inspect_dataset.py` using chunked reading. Results are persisted in `data/manifests/dataset_audit_manifest.json`:

| CSV File Name | File Size | Total Rows | NaNs Found | Infs Found | SHA-256 Checksum (Prefix) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 73.55 MB | 225,745 | 4 | 149 | `f174c85116773a97...` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 73.34 MB | 286,467 | 15 | 87 | `9e38d38ebc517f69...` |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 55.62 MB | 191,033 | 25 | 114 | `1f33ee66567ef730...` |
| `Monday-WorkingHours.pcap_ISCX.csv` | 168.73 MB | 529,918 | 57 | 108 | `72b7f039363d6f1a...` |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 79.25 MB | 288,602 | 37 | 78 | `b7829871510e402b...` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 49.61 MB | 170,366 | 27 | 72 | `d1b702ec4051a8d9...` |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 128.82 MB | 445,909 | 201 | 370 | `f8819aaec3323087...` |
| `Wednesday-workingHours.pcap_ISCX.csv` | 214.74 MB | 692,703 | 992 | 1,908 | `99d4ca9cf63c78ad...` |

---

## 2. Aggregated Class Distribution

The raw dataset exhibits significant class imbalance typical of real-world enterprise traffic:

| Traffic Class / Attack Category | Record Count | Percentage | Canonical Mapping |
| :--- | :--- | :--- | :--- |
| **BENIGN** | 2,273,097 | 80.30% | `BENIGN` |
| **DoS Hulk** | 231,073 | 8.16% | `DoS` |
| **PortScan** | 158,930 | 5.61% | `PortScan` |
| **DDoS** | 128,027 | 4.52% | `DDoS` |
| **DoS GoldenEye** | 10,293 | 0.36% | `DoS` |
| **FTP-Patator** | 7,938 | 0.28% | `Brute_Force` |
| **SSH-Patator** | 5,897 | 0.21% | `Brute_Force` |
| **DoS slowloris** | 5,796 | 0.20% | `DoS` |
| **DoS Slowhttptest** | 5,499 | 0.19% | `DoS` |
| **Bot** | 1,966 | 0.07% | `Botnet` |
| **Web Attack - Brute Force** | 1,507 | 0.05% | `Web_Attack` |
| **Web Attack - XSS** | 652 | 0.02% | `Web_Attack` |
| **Infiltration** | 36 | 0.001% | `Infiltration` |
| **Web Attack - Sql Injection**| 21 | 0.0007% | `Web_Attack` |
| **Heartbleed** | 11 | 0.0004% | `Heartbleed` |

---

## 3. Data Cleaning Decisions & Auditable Policies

### Decision 1: Header Whitespace & Duplicate Remediation
- **Observation:** In the original CIC-IDS2017 files, column headers contain irregular leading/trailing spaces (e.g. `' Destination Port'`, `' Label'`). Furthermore, the column header `'Fwd Header Length'` appears twice in raw headers.
- **Remediation:** All column names are trimmed via `normalize_column_names()`. The second occurrence of `'Fwd Header Length'` is preserved under Pandas' deterministic indexing as `'Fwd Header Length.1'`.

### Decision 2: Malformed Characters in Attack Labels
- **Observation:** In `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, byte offsets in labels contain non-ASCII em-dashes and replacement characters (`Web Attack \ufffd Brute Force`).
- **Remediation:** The preprocessor maps these strings cleanly to canonical attack categories (`Web_Attack`, `Brute_Force`, `DoS`) using regex and dictionary resolution.

### Decision 3: Infinite Values in Flow Rates
- **Observation:** Across the 8 files, 2,886 records contain `+Infinity` or `-Infinity` in `Flow Bytes/s` and `Flow Packets/s`. This occurs when `Flow Duration` is 0 microseconds, causing division by zero during ISCX flow feature calculation.
- **Remediation:** All positive and negative infinities are explicitly replaced with `np.nan`, then imputed with the feature's median learned strictly on the training partition.

### Decision 4: Prevention of Data Leakage
- **Observation:** Computing imputation statistics (means, medians, scales) across the entire dataset leaks test-set distributions into the training pipeline.
- **Remediation:** The `IDSPreprocessor` fits medians and schema boundaries **exclusively on the training split**. During test evaluation and live inference, the preprocessor uses the saved medians.

---

## 4. Sampling & Memory Management Policy

To train a robust model within the 12 GB RAM boundary without saturating the system:
1. Data is ingested using a chunk size of **50,000 records**.
2. Training pools are balanced across all categories: taking up to **15,000 samples per attack class** and **50,000 benign samples**, yielding a 70,016-flow balanced dataset.
3. This guarantees representation of rare attacks (e.g., Infiltration, Web Attacks) while preventing benign samples from dominating the tree loss function.
