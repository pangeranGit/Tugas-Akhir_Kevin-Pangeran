# Rubrik M-2 (AI Summary Fidelity)

Rumus: M-2 = (1/n) × Σ((D1 + D2 + D3) / 3), skala 1–3.
Implementasi: `src/evaluator.py`, fungsi `calc_m2_fidelity()`.

M-2 adalah **proksi fidelitas terstruktur**. Rubrik memverifikasi kemunculan
entitas faktual tertentu, kelengkapan dua komponen keluaran, serta kesesuaian
kode taktik dan terminologi C2. Rubrik **tidak** memverifikasi seluruh proposisi
semantik dalam narasi.

## D1 — Factual Accuracy

Diperiksa kemunculannya di dalam gabungan teks Behavior + Threat Context:
destination IP, source IP, abuseConfidenceScore (kecuali bernilai -1), dan
maksimal tiga kata kunci dari signature (panjang > 3 karakter, mengecualikan
kata umum: malware, alert, activity, detected, generic).

| Rasio kecocokan | Skor |
|---|---|
| ≥ 0,75 | 3 |
| ≥ 0,40 dan < 0,75 | 2 |
| < 0,40, atau tidak ada entitas yang dapat diperiksa | 1 |

## D2 — Completeness

| Kondisi | Skor |
|---|---|
| Behavior dan Threat Context keduanya terisi lebih dari 10 karakter | 3 |
| Hanya salah satu yang terisi | 2 |
| Keduanya kosong atau terlalu pendek | 1 |

## D3 — Relevance

Diperiksa kehadiran kode taktik yang benar-benar dipetakan pada alert tersebut
(`mitre.tactic_ids`, bukan nilai tetap TA0011) dan terminologi C2, yaitu salah
satu dari: command and control, c2, cnc, c&c, beacon, callback.

| Kondisi | Skor |
|---|---|
| Kode taktik terpetakan dan terminologi C2 keduanya muncul | 3 |
| Hanya salah satu yang muncul | 2 |
| Keduanya tidak muncul | 1 |

## Catatan validitas konstruk

Entitas yang diperiksa D1 dan format yang diperiksa D2 merupakan elemen yang
diwajibkan oleh prompt. Karena itu skor yang mendekati nilai maksimum sebagian
mencerminkan kepatuhan terhadap format dan data yang diwajibkan, bukan bukti
kesetiaan semantik menyeluruh. Validasi oleh penilai manusia independen belum
dilakukan dan menjadi pekerjaan lanjutan.
