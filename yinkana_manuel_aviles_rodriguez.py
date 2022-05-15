#!/usr/bin/python3

import array
import base64
import hashlib
from os import sep
import socket
import struct
import sys
import threading

#----------------------------------------------RETO 0----------------------------------------------#
def reto0():
    sock = socket.socket()
    sock.connect(("rick", 2000))

    msg = sock.recv(1024)
    print(msg.decode())

    sock.sendall("agitated_dubinsky".encode())
    msg, server = sock.recvfrom(1024)
    print(msg.decode())
    codigo = msg.decode()
    clave = codigo[11:31]
    sock.close()
    reto1(clave)
#----------------------------------------------RETO 1: UDP----------------------------------------------#
def reto1(clave):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 1231))
    mensaje = f"{1231} {clave}"
    sock.sendto(mensaje.encode(), ('rick', 4000))
    msg, server = sock.recvfrom(1024)
    clave1 = clave.upper()
    sock.sendto(clave1.encode(), server)
    msg, server = sock.recvfrom(1024)
    print(msg.decode())
    clave = conseguirIdentificador(msg)
    sock.close()
    reto2(clave)
#----------------------------------------------RETO 2: Words len----------------------------------------------#
def reto2(clave):
    index = 0
    counter = 0
    leng = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('rick', 3010))

    msg = ''
    message = clave + ' '
    sock.settimeout(1)
    while 1:
        try:
            msg += sock.recv(2048).decode()
        except:
            break

    while counter < 1000 and index < len(msg):
        if msg[index] == ' ':
            message = message + str(leng) + ' '
            counter = counter + leng
            leng = 0
        else:
            leng += 1
        index += 1

    if leng != 0:
        message = message + str(leng) + ' '

    message = message + '--'
    sock.send(message.encode())
    msg = b''
    while True:
        aux = sock.recv(1024)
        if len(aux) <= 0:
            break
        msg += aux

    print(msg.decode())
    clave = conseguirIdentificador(msg)
    reto3(clave)
    sock.close()
#----------------------------------------------RETO 3: Initial-D----------------------------------------------#
def reto3(clave):
    numeros = ""
    i = 0
    n = 0
    z = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('rick', 3005))
    condition = True
    msg = ""
    iniciales = ""
    numeros = ""
    aux = sock.recv(128).decode()
    msg += aux
    numeros = msg.split()

    while condition:
        if numeros[i].isdigit():
            n = numeros[i]
            condition = False
            break
        else:
            i += 1
            numeros = ""
            aux = sock.recv(128).decode()
            msg += aux
            numeros = msg.split()
    cadena = msg.split()
    i = 0
    while (i < int(n) and z < len(cadena)):
        if i == int(n):
            break
        if cadena[z].isdigit() == False:
            iniciales += cadena[z][0] + " "
            i += 1
            z += 1
        elif cadena[z].isalpha() == False:
            z += 1

    iniciales = iniciales.upper()
    msgEnvio = clave + ":"
    msgEnvio = msgEnvio.strip()
    msgEnvio += iniciales
    msgEnvio = msgEnvio.rstrip()
    msgEnvio = msgEnvio.lstrip()
    sock.send(msgEnvio.encode())
    msgrec = b''
    msgaux = b''
    while True:
        msgaux = sock.recv(1024)
        if len(msgaux) <= 0:
            break
        msgrec += msgaux

    print(msgrec.decode())
    identificador = ""
    puntosIden = False
    msg = msgrec.decode()
    n = 0
    for n in range(len(msg)):
        if((puntosIden == True) and (msg[n] == '\n')):
            break

        if puntosIden == True:
            identificador += msg[n]

        if msg[n] == ':':
            puntosIden = True
    print(identificador)
    reto4(identificador)
    sock.close()
#----------------------------------------------RETO 4:SHA1----------------------------------------------#
def reto4(clave):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('rick', 9003))
    sock.send(clave.encode())
    dots = False
    tamano = ""

    while dots == False:
        aux = sock.recv(1)
        if aux.decode() == ":":
            dots = True
        elif aux.decode() != "[":
            tamano += aux.decode('ascii')
    archivo = b''
    archivo_tamano = int(tamano)

    while archivo_tamano > len(archivo):
        archivo += sock.recv(archivo_tamano)

    archivo = archivo[:archivo_tamano]
    solucion = hashlib.sha1(archivo).digest()
    sock.send(solucion)

    msgrec = b''
    msgaux = b''
    while True:
        msgaux = sock.recv(1024)
        if len(msgaux) <= 0:
            break
        msgrec += msgaux

    print(msgrec.decode())
    identificador = ""
    puntosIden = False
    msg = msgrec.decode()
    for n in range(len(msg)):
        if((puntosIden == True) and (msg[n] == '\n')):
            break

        if puntosIden == True:
            identificador += msg[n]

        if msg[n] == ':':
            puntosIden = True

    reto5(identificador)
    sock.close()
#----------------------------------------------RETO 5:WYP----------------------------------------------#
def reto5(identificador):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 6572))
    payload = base64.b64encode(identificador.encode())
    WYP = b'WYP'
    tipo = 0
    codigo = 0
    checksum = 0
    data = struct.pack(f'!3shBHh', WYP, tipo, codigo, checksum, 1)
    paquete = data + payload
    checksum = cksum(paquete)
    data = struct.pack(f'!3shBHh', WYP, tipo, codigo, checksum, 1)
    paquete = data + payload
    sock.sendto(paquete, ('rick', 6000))
    info = sock.recv(4096)
    if(info[3] == 1 and info[4] == 0):
        info = base64.b64decode(info[10:])
        print(info.decode())
    elif info[4] == 1:
        print("Error: Wrong-code")
    elif info[4] == 2:
        print("Error: Wrong-format")
    elif info[4] == 3:
        print("Error: Wrong-challenge")
    elif info[4] == 4:
        print("Error: Wrong-checksum")
    elif info[4] == 5:
        print("Error: Bad-sequence-number")
    sock.close()

def conseguirIdentificador(msg):
    mensaje_lineas = msg.decode().splitlines()
    identificador = mensaje_lineas[0]
    codigo_identificador = identificador[11:len(identificador)]
    return codigo_identificador

def conseguirIdentificador2(msg):
    i = 0
    mensaje_lineas = msg.decode()
    print(mensaje_lineas)
    codigo = ""
    while i <= len(mensaje_lineas):
        if mensaje_lineas[i] == ":":
            codigo = conseguirIdentificadorv2(mensaje_lineas[i+1:len(mensaje_lineas)])
            break
        else:
            i += 1
    return codigo

def conseguirIdentificadorv2(msg):
    i = 0
    mensaje = ""
    while i < len(msg):
        mensaje += msg[i]
        i += 1
    return mensaje

"Internet checksum algorithm RFC-1071"
# from scapy:
# https://github.com/secdev/scapy/blob/master/scapy/utils.py

import sys
import struct
import array


def cksum(pkt):
    # type: (bytes) -> int
    if len(pkt) % 2 == 1:
        pkt += b'\0'
    s = sum(array.array('H', pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s

    if sys.byteorder == 'little':
        s = ((s >> 8) & 0xff) | s << 8

    return s & 0xffff



reto0()
