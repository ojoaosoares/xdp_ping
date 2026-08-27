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

### Modo 2: Teste em Interface Física (`enp1s0np1` / Fibra Ótica)

```bash
# Ping Padrão ICMP Echo (igual ao comando ping):
sudo ./bin/xdp_ping -i enp1s0np1 -d 192.168.0.2 -c 10

# Ou em modo UDP na porta 9999:
sudo ./bin/xdp_ping -i enp1s0np1 -d 192.168.0.2 -u -p 9999 -c 10
```

---

## ⚙️ Opções do CLI

| Opção | Descrição | Padrão |
| :--- | :--- | :--- |
| `-i <ifname>` | Nome da interface de rede | `enp1s0np1` |
| `-d <ip>` | Endereço IPv4 de destino | `192.168.0.2` |
| `-s <ip>` | Endereço IPv4 de origem | Auto-detectado da interface |
| `-m <mac>` | Endereço MAC de destino | Auto-resolvido via ARP (`/proc/net/arp`) |
| `-u` | Usa protocolo UDP em vez do padrão ICMP Echo Ping | ICMP Echo Ping |
| `-p <port>` | Porta UDP de destino (apenas com `-u`) | `9999` |
| `-c <count>` | Quantidade de pacotes (`0` = infinito) | `10` |
| `-r <repeat>` | Repetições por chamada de `test_run` | `1` |
| `-t <ms>` | Intervalo entre disparos em ms | `1000` |
| `-b <msg>` | Mensagem de payload customizada (modo UDP) | `"PING from XDP BPF_TEST"` |
| `-h` | Exibe o menu de ajuda | - |

---

## 🔬 Como Funciona

1. **Kernel XDP (`src/xdp_ping.bpf.c`)**:
   - Programa XDP acoplado no modo **DRIVER / NATIVE** (`XDP_FLAGS_DRV_MODE`).
   - Retorna `XDP_TX` para reflexão e transmissão direta pela fila de TX do driver de rede.

2. **Userspace (`src/xdp_ping.c`)**:
   - Resolve automaticamente o endereço MAC de destino através da tabela ARP do sistema.
   - Anexa o programa BPF à interface de rede usando o modo **DRIVER** (`bpf_xdp_attach` com `XDP_FLAGS_DRV_MODE`) e confirma via `bpf_xdp_query_id`.
   - Constrói o frame completo idêntico ao `ping` do Linux (Ethernet + IPv4 + ICMP Echo Request + Timestamp + Payload).
   - Injeta os frames no hook XDP via `bpf_prog_test_run_opts` com a flag `BPF_F_TEST_XDP_LIVE_FRAMES`.
   - Desanexa o programa XDP de forma limpa ao finalizar (via `bpf_xdp_detach`).
