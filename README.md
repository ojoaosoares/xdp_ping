# xdp_ping

Gerador de pacotes UDP/Ping em alta velocidade utilizando **eBPF/XDP** e a syscall `bpf_prog_test_run_opts` com o modo **Live Frames** (`BPF_F_TEST_XDP_LIVE_FRAMES`).

---

## 🎯 Objetivo

Permitir o teste, validação e benchmarking do recurso de injeção de pacotes via `BPF_PROG_RUN` (`bpf_test_run`) do Linux sem precisar de drivers externos ou módulos de kernel.

---

## 🏗️ Como Compilar

Requisitos:
- `clang` ($\ge 14$)
- `bpftool`
- `libbpf-dev`
- `libelf-dev`
- `zlib1g-dev`

Para compilar tudo:
```bash
make
```

O binário será gerado em `bin/xdp_ping`.

---

## 🚀 Como Testar

### Modo 1: Teste com Interfaces Virtuais (`veth`) — *Recomendado (Zero Hardware)*

As interfaces `veth` do Linux possuem suporte completo e nativo a `BPF_F_TEST_XDP_LIVE_FRAMES` em qualquer kernel $\ge 5.18$.

1. **Crie o par `veth0 <-> veth1`**:
   ```bash
   make setup-veth
   ```

2. **Terminal 1 (Receptor / Captura)**:
   ```bash
   sudo tcpdump -i veth1 -nnvvXX 'udp port 9999'
   ```
   *(Ou escute os dados com Netcat: `nc -u -l 10.10.10.2 9999`)*

3. **Terminal 2 (Injetor XDP)**:
   ```bash
   sudo ./bin/xdp_ping -i veth0 -d 10.10.10.2 -p 9999 -c 5
   ```

4. **Para remover as interfaces virtuais após o teste**:
   ```bash
   make teardown-veth
   ```

---

### Modo 2: Teste em Interface Física (`enp3s0` / `eth0`)

```bash
sudo ./bin/xdp_ping -i enp3s0 -d 150.164.2.81 -m e0:d5:5e:84:d3:7c -p 9999 -c 10
```

---

## ⚙️ Opções do CLI

| Opção | Descrição | Padrão |
| :--- | :--- | :--- |
| `-i <ifname>` | Nome da interface de rede | `enp3s0` |
| `-d <ip>` | Endereço IPv4 de destino | `150.164.2.81` |
| `-s <ip>` | Endereço IPv4 de origem | Auto-detectado |
| `-m <mac>` | Endereço MAC de destino | Broadcast (`ff:ff:...`) |
| `-p <port>` | Porta UDP de destino | `9999` |
| `-c <count>` | Quantidade de pacotes (`0` = infinito) | `10` |
| `-r <repeat>` | Repetições por chamada de `test_run` | `1` |
| `-t <ms>` | Intervalo entre disparos em ms | `1000` |
| `-b <msg>` | Mensagem de payload UDP customizada | `"PING from XDP BPF_TEST"` |
| `-h` | Exibe o menu de ajuda | - |

---

## 🔬 Como Funciona

1. **Kernel XDP (`src/xdp_ping.bpf.c`)**:
   - Programa minimalista que retorna `XDP_TX`.
   - Quando acionado com `BPF_F_TEST_XDP_LIVE_FRAMES`, o kernel faz a reflexão do frame e o entrega na fila TX da interface.

2. **Userspace (`src/xdp_ping.c`)**:
   - Constrói o frame completo (Ethernet + IPv4 + UDP + Payload).
   - Calcula os checksums de IPv4 e UDP.
   - Invoca `bpf_prog_test_run_opts(prog_fd, &topts)` com `BPF_F_TEST_XDP_LIVE_FRAMES`.
