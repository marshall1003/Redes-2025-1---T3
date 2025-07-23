from iputils import *
import ipaddress


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        # Garante que meu_ip está definido corretamente
        if self.meu_endereco is None:
            meu_ip = None
        elif isinstance(self.meu_endereco, ipaddress.IPv4Address):
            meu_ip = self.meu_endereco
        else:
            meu_ip = ipaddress.IPv4Address(self.meu_endereco)

        dst_ip = ipaddress.IPv4Address(dst_addr)

        # Atua como host se o destino for o próprio endereço
        if meu_ip is not None and dst_ip == meu_ip:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
            return  # NÃO encaminha se o destino for o próprio host

        # Atua como roteador
        next_hop = self._next_hop(str(dst_ip))

        # Encaminha apenas para o melhor next_hop (prefixo mais longo)
        if ttl > 1:
            novo_ttl = ttl - 1
            novo_datagrama = montar_ipv4_header(
                dscp, ecn, identification, flags, frag_offset,
                novo_ttl, proto, src_addr, dst_addr, payload
            )
            self.enlace.enviar(novo_datagrama, next_hop)
        elif ttl <= 1:
            # TTL chegou a zero: gera ICMP Time Exceeded
            icmp_type = 11  # Time Exceeded
            icmp_code = 0
            icmp_checksum = 0
            unused = 0
            # ICMP payload: cabeçalho IP original + primeiros 8 bytes do payload
            original_header = datagrama[:20]
            original_payload = datagrama[20:28]
            icmp_payload = original_header + original_payload
            icmp_header = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, unused)
            icmp_datagrama = icmp_header + icmp_payload
            # Calcula checksum ICMP
            icmp_checksum = calc_checksum(icmp_datagrama)
            icmp_header = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, unused)
            icmp_datagrama = icmp_header + icmp_payload
            # Monta datagrama IP para ICMP
            ip_icmp = montar_ipv4_header(
                0, 0, 0, 0, 0, 64, IPPROTO_ICMP, str(self.meu_endereco), src_addr, icmp_datagrama
            )
            # Envia ICMP para o remetente
            next_hop_icmp = self._next_hop(src_addr)
            if next_hop_icmp is not None:
                self.enlace.enviar(ip_icmp, next_hop_icmp)
        # Caso contrário, descarta silenciosamente

    def definir_endereco_host(self, meu_endereco):
        """
        Define o endereço IPv4 deste host.
        """
        self.meu_endereco = ipaddress.IPv4Address(meu_endereco)

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato:
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        """
        self.tabela_encaminhamento = [
            (ipaddress.IPv4Network(cidr), next_hop)
            for cidr, next_hop in tabela
        ]

    def _next_hop(self, dest_addr):
        """
        Retorna o next_hop para o endereço de destino,
        escolhendo o prefixo mais longo da tabela.
        """
        ip_dest = ipaddress.IPv4Address(dest_addr)
        melhor_prefixo = -1
        melhor_next_hop = None
        for rede, next_hop in self.tabela_encaminhamento:
            if ip_dest in rede and rede.prefixlen > melhor_prefixo:
                melhor_next_hop = next_hop
                melhor_prefixo = rede.prefixlen
        return melhor_next_hop

    def registrar_recebedor(self, callback):
        """
        Registra função que será chamada quando dados chegarem à camada IP.
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento TCP para dest_addr via roteamento IP.
        """
        next_hop = self._next_hop(dest_addr)
        if next_hop is None:
            return  # Não envia se não houver rota

        # Monta o cabeçalho IP
        dscp = 0
        ecn = 0
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = IPPROTO_TCP
        src_addr = str(self.meu_endereco)
        dst_addr = dest_addr

        datagrama = montar_ipv4_header(
            dscp, ecn, identification, flags, frag_offset, ttl,
            proto, src_addr, dst_addr, segmento
        )
        self.enlace.enviar(datagrama, next_hop)


def montar_ipv4_header(dscp, ecn, identification, flags, frag_offset,
                       ttl, proto, src_addr, dst_addr, payload):
    version = 4
    ihl = 5  # Cabeçalho padrão de 20 bytes
    vihl = (version << 4) + ihl
    dscpecn = (dscp << 2) + ecn
    total_len = 20 + len(payload)
    flagsfrag = (flags << 13) + frag_offset

    src_addr_int = int.from_bytes(str2addr(src_addr), 'big')
    dst_addr_int = int.from_bytes(str2addr(dst_addr), 'big')

    checksum = 0
    header = struct.pack(
        '!BBHHHBBHII',
        vihl, dscpecn, total_len, identification, flagsfrag,
        ttl, proto, checksum, src_addr_int, dst_addr_int
    )
    checksum = calc_checksum(header)
    header = struct.pack(
        '!BBHHHBBHII',
        vihl, dscpecn, total_len, identification, flagsfrag,
        ttl, proto, checksum, src_addr_int, dst_addr_int
    )
    return header + payload
