import socket
import dnslib
from dnslib import DNSRecord, QTYPE, RR, A

# Variables
IP_VM = "10.0.2.15" # magda
# IP_VM = "192.168.1.18" # matias
buff_size = 10000
debug = True

# arreglo a lo más 3 tuplas (dominio, ip)
cache = []
# cola de dominios
historial = []

def parse_dns_msg(msg):
    """Parsea un mensaje DNS.
    El tipo RR es la estructura RR de dnslib
    Args:
        msg (bin): El mensaje DNS a parsear

    Returns:
        dict: Un diccionario con la informacion necesaria
            - qname (str): nombre del dominio solicitado
            - ancount (int): el numero de respuestas en el mensaje
            - nscount (int): numero de registros de servidores en la seccion de autoridad
            - arcount (int): numero de registros de servidores en la seccion adicional
            - answer (RR): las respuestas recibidas
            - authority (RR): señala los servidores que tienen autoridad
            - additional (RR): informacion extra, de servidores sin autoridad
    """

    d = DNSRecord.parse(msg)
    msg_dict = {
        "qname": str(d.q.qname),
        "ancount": len(d.rr),
        "nscount": len(d.auth),
        "arcount": len(d.ar),
        "answer": d.rr,
        "authority": d.auth,
        "additional": d.ar
    }

    return msg_dict

def resolver_a(msg, ip_addr="198.41.0.4"):
    """Envía un mensaje DNS a la IP especificada y retorna el mensaje DNS recibido
    Args:
        msg (bin): La consulta DNS a enviar.
        ip_addr (str): La dirección IP por consultar. 
            El valor por default es "198.41.0.4", una IP root.

    Returns:
        bin: el mensaje de respuesta de la consulta enviada a la dirección IP.
    """
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
    """Recibe un mensaje DNS y el diccionario que le representa. 
    Busca respuestas de tipo A o bien NS y retorna la respuesta 
    """
    if response["arcount"]>0:
        for add in response["additional"]:
            if add.rtype == QTYPE.A:
                if debug:
                    pdebug(msg, str(add.rname), str(add.rdata))
                cach = consultar_en_cache(msg)
                if cach:
                    if(debug):
                        print("Dominio en caché")
                    return cach
                return resolver(msg, str(add.rdata))
    for r in response["authority"]:
        if r.rtype == QTYPE.NS:
            ns = r.rdata
            q = DNSRecord.question(str(ns)).pack()
            if debug:
                pdebug(q, ".")
            ip_ns = parse_dns_msg(resolver(q))
            for i in ip_ns["answer"]:
                if i.rtype == QTYPE.A:
                    ip_ns = str(i.rdata)
                    if debug:
                        pdebug(msg, str(r.rname), ip_ns)
                    cach = consultar_en_cache(msg)
                    if cach:
                        if(debug):
                            print("Dominio en caché")
                        return cach
                    return resolver(msg, ip_ns)


def resolver(mensaje_consulta: bytes, ip_addr="198.41.0.4"):
    """"""
    data = resolver_a(mensaje_consulta, ip_addr)
    response = parse_dns_msg(data)
    # PARTE B
    if (response["ancount"] > 0 and any(r.rtype == QTYPE.A for r in response["answer"])):
        return data
    if (response["nscount"]>0):
        return resolver_c(mensaje_consulta, response)
    else:
        if debug:
            print("respuesta inmanejable\n")

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
                res = DNSRecord.parse(msg).reply()
                res.add_answer(RR(rname=dominio, rtype=QTYPE.A, rdata=A(c[1])))
                return res.pack()    

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
    if len(cache) < 3 and dominio not in [d[0] for d in cache]:
        q = DNSRecord.question(dominio).pack()
        resp = parse_dns_msg(resolver(q))
        for r in resp["answer"]:
            if r.rtype == QTYPE.A:
                ip_new = str(r.rdata)
        cache.append((dominio, ip_new))
    else:
        cache_set = set([d[0] for d in cache])
        dif_cache = cache_set - top3
        # si no, tomamos el distinto y reemplazamos
        if dif_cache:
            dif_cache = dif_cache.pop()
            dif_top3 = (top3 - cache_set)
            dif_top3 = dif_top3.pop()
            cache = [t for t in cache if t[0] != dif_cache]
            q = DNSRecord.question(dif_top3).pack()
            resp = parse_dns_msg(resolver(q))
            for r in resp["answer"]:
                if r.rtype == QTYPE.A:
                    ip_new = str(r.rdata)
            cache.append((dif_top3, ip_new))
    
if __name__ == "__main__":

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP_VM, 8000))

    while True:
        print("Esperando un nuevo cliente\n")
        msg, client = sock.recvfrom(buff_size)
        cach = consultar_en_cache(msg)
        if cach:
            if(debug):
                print("Dominio en caché")
            sock.sendto(cach, client)
        else:
            if debug:
                pdebug(msg, ".")
            res = resolver(msg)
            if res:
                sock.sendto(res, client)
        actualizar_cache(parse_dns_msg(msg)["qname"])
        print(f"cache actualizado: {cache}\n")