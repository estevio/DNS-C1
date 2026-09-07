import socket
import dnslib
from dnslib import DNSRecord, QTYPE

# test 2
# dig -p8000 @IP_VM example.com
# dig -p8000 @10.0.2.15 example.com

# Variables
IP_VM = "10.0.2.15" # magda
# IP_VM = "192.168.1.18" # matias
buff_size = 4096
debug = True

# arreglo a lo más 3 tuplas (dominio, ip)
cache = []
# cola de dominios
historial = []

def parse_dns_msg(msg):
    """Parsea un mensaje DNS
    Args:
        msg (bin): El mensaje DNS a parsear

    Returns:
        dict: Un diccionario con la informacion necesaria
            - qname: nombre del dominio solicitado
            - ancount: el numero de respuestas en el mensaje
            - nscount: numero de registros de servidores en la seccion de autoridad
            - arcount: numero de registros de servidores en la seccion adicional
            - answer: las respuestas recibidas
            - authority: señala los servidores que tienen autoridad
            - additional: informacion extra, de servidores sin autoridad
    """

    d = DNSRecord.parse(msg)
    msg_dict = {
        "qname": d.q.qname,
        "ancount": len(d.rr),
        "nscount": len(d.auth),
        "arcount": len(d.ar),
        "answer": d.rr,
        "authority": d.auth,
        "additional": d.ar
    }

    return msg_dict

def resolver_a(msg, ip_addr="198.41.0.4"):
    server_address = (ip_addr, 53)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # PARTE A
    try:
        # lo enviamos, hacemos cast a bytes de lo que resulte de la función pack() sobre el mensaje
        sock.sendto(msg, server_address)
        # En data quedará la respuesta a nuestra consulta
        data, _ = sock.recvfrom(buff_size)
        # le pedimos a dnslib que haga el trabajo de parsing por nosotros
    finally:
        sock.close()
    return data

def resolver_c(msg, response):
    if response["arcount"]>0:
        for add in response["additional"]:
            if add.rtype == QTYPE.A:
                if debug:
                    pdebug(msg, str(add.rname), str(add.rdata))
                return resolver(msg, str(add.rdata))
    for r in response["authority"]:
        if r.rtype == QTYPE.NS:
            ns = r.rdata
            q = DNSRecord.question(str(ns)).pack()
            if debug:
                pdebug(q, ".")
            ip_ns = resolver(q)
            if debug:
                pdebug(msg, str(r.rname), ip_ns)
            return resolver(msg, ip_ns)


def resolver(mensaje_consulta: bytes, ip_addr="198.41.0.4"):
    """"""
    data = resolver_a(mensaje_consulta, ip_addr)
    response = parse_dns_msg(data)
    # PARTE B
    if (response["ancount"]>0 and response["answer"][0].rtype == QTYPE.A):
        return data
    elif (response["nscount"]>0):
        return resolver_c(mensaje_consulta, response)
    else:
        if debug:
            print("consulta inmanejable\n")

def pdebug(msg, ns, ip_ns="198.41.0.4"):
    data_consulta = parse_dns_msg(msg)
    dominio = data_consulta["qname"]
    print(f"(debug) Consultando {dominio} a {ns} con dirección {ip_ns}")

def consultar_en_cache(msg):
    data = parse_dns_msg(msg)
    dominio = data["qname"]
    if len(cache) > 0:
        for c in cache:
            if c[0] == dominio:
                return c[1]
    

def actualizar_cache(dominio):
    global cache
    # calcular top 3 del historial
    cnt = {}
    if len(historial) > 19:
        historial.pop(0)
    historial.append(dominio)
    for dom in historial:
        cnt[dom] = cnt.get(dom, 0) + 1
    top3 = set([t[0] for t in sorted(cnt.items(), key=lambda item: item[1], reverse=True)[:3]])
    # verificamos que el top 3 este en el cache
    if len(cache) < 3:
        q = DNSRecord.question(dominio).pack()
        ip_new = resolver(q)
        cache.append((dominio, ip_new))
    else:
        cache_set = set([d[0] for d in cache])
        dif_cache = cache_set - top3
        # si no, tomamos el distinto y reemplazamos
        if dif_cache:
            dif_top3 = (top3 - cache_set).pop()
            cache = [t for t in cache if t[0] != dif_cache]
            q = DNSRecord.question(dif_top3).pack()
            ip_new = resolver(q)
            cache.append((dif_top3, ip_new))
    
if __name__ == "__main__":

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP_VM, 8000))

    while True:
        print("while")
        msg, client = sock.recvfrom(buff_size)
        cach = consultar_en_cache(msg)
        if cach:
            if(debug):
                print("Dominio en caché")
            sock.sendto(cach, client)
        else:
            print(cache)
            if debug:
                pdebug(msg, ".")
            res = resolver(msg)
            if res:
                sock.sendto(res, client)
        data_consulta = parse_dns_msg(msg)
        dominio = data_consulta["qname"]
        actualizar_cache(dominio)