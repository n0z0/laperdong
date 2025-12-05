# laperdong

Local Aggressive Protocol Exploitation and Resource Denial Onslaught Network Generator

## Prasyarat PENTING untuk Windows

Sebelum kode Go bisa berjalan, Anda wajib menginstal Npcap. Ini adalah driver yang memungkinkan aplikasi (seperti program Go kita) untuk mengakses lalu lintas jaringan tingkat rendah.

Unduh Npcap: Kunjungi situs resmi Npcap dan unduh installer terbaru.
Link Unduh: <https://npcap.com/#download>
Instal Npcap dengan Benar:
Jalankan installer yang sudah diunduh.
PENTING: Saat instalasi, pastikan Anda mencentang opsi "Install Npcap in WinPcap API-compatible Mode". Ini memastikan kompatibilitas dengan library gopacket yang kita gunakan.
Jalankan sebagai Administrator: Karena program kita akan mengirim paket jaringan khusus, ia memerlukan hak akses administrator. Anda harus menjalankan Command Prompt atau PowerShell "As Administrator".

Yersinia atau Scapy
