package main
import ("os"; "os/exec"; "fmt")
func main() {
    python := os.Getenv("QMIGRATE_PYTHON")
    if python == "" { python = "python" }
    cmd := exec.Command(python, "crypto_adapter.py", "--selftest")
    cmd.Stdout = os.Stdout; cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
}
