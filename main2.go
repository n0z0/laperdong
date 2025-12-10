package main

import (
    "fmt"
    "log"
    "os"
    "os/exec"
    "strings"
)

func changeMacWithNetsh(adapterName, newMac string) error {
    // 1. Temukan path registri adapter. Ini adalah bagian yang sulit.
    //    Untuk kesederhanaan, kita asumsikan kita sudah mengetahuinya.
    //    Pathnya biasanya: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\<NNNN>
    //    di mana <NNNN> adalah sub-key untuk adapter Anda.
    //    Anda perlu melakukan iterasi untuk menemukan yang cocok dengan `adapterName`.

    // Karena menemukan path registri secara dinamis juga rumit,
    // contoh ini akan fokus pada langkah disable/enable setelah perubahan manual.
    // Untuk mengubah registri, Anda bisa menggunakan:
    // cmd := exec.Command("reg", "add", `HKLM\...\NetworkAddress`, /v, "NetworkAddress", /t, "REG_SZ", /d, newMac, /f)
    
    // Kita akan asumsikan perubahan registri sudah dilakukan.
    // Sekarang, fokus pada restart adapter.

    fmt.Printf("Menonaktifkan adapter '%s'...\n", adapterName)
    cmdDisable := exec.Command("netsh", "interface", "set", "interface", fmt.Sprintf(`name="%s"`, adapterName), "admin=disable")
    if err := cmdDisable.Run(); err != nil {
        return fmt.Errorf("gagal menonaktifkan adapter: %w", err)
    }

    fmt.Printf("Mengaktifkan kembali adapter '%s'...\n", adapterName)
    cmdEnable := exec.Command("netsh", "interface", "set", "interface", fmt.Sprintf(`name="%s"`, adapterName), "admin=enable")
    if err := cmdEnable.Run(); err != nil {
        return fmt.Errorf("gagal mengaktifkan adapter: %w", err)
    }

    return nil
}

func main() {
    if len(os.Args) < 3 {
        fmt.Printf("Usage: %s <\"Adapter Name\"> <NewMAC>\n", os.Args[0])
        fmt.Println("Example:", os.Args[0], "\"Wi-Fi\" \"001122AABBCC\"")
        fmt.Println("Catatan: Metode ini tidak mengubah registri. Anda harus melakukannya secara manual atau dengan perintah 'reg add'.")
        return
    }

    adapterName := os.Args[1] // Nama adapter yang terlihat di "ncpa.cpl"
    newMac := os.Args[2]

    // Langkah untuk mengubah registri (harus dijalankan sebagai Admin)
    // Anda harus mencari sub-key yang benar terlebih dahulu.
    // registryPath := `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0012` // CONTOH SAJA
    // cmd := exec.Command("reg", "add", registryPath, "/v", "NetworkAddress", "/t", "REG_SZ", "/d", newMac, "/f")
    // if err := cmd.Run(); err != nil {
    //     log.Fatalf("Gagal menulis ke registri: %v", err)
    // }
    // fmt.Println("Berhasil menulis alamat MAC ke registri.")

    err := changeMacWithNetsh(adapterName, newMac)
    if err != nil {
        log.Fatalf("Error: %v", err)
    }

    fmt.Println("Adapter berhasil di-restart. Periksa perubahan dengan 'ipconfig /all'.")
}