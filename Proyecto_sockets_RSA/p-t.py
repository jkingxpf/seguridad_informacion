import f_aes, f_asim, socket_class, json
from datetime import datetime

#1 creamos clave publica y privada de TTP
keyT = f_asim.crear_RSAKey()
f_asim.guardar_RSAKey_Publica("KpubT.bin",keyT)

#2 creamos clave KAB-
BKAB = f_aes.crear_AESKey()

#Lo mismo con Bernardo

print("escuchando B...")
radioB = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 5552)
radioB.escuchar()
cifrado = None

while cifrado is None:
    cifrado = radioB.recibir()

print("Mensaje de B recibido")

cifrado.decode("utf-8")
mensajeB = json.loads(cifrado)
nombre, EKBTH, firmaH = mensajeB
print(nombre)
EKBT = bytes.fromhex(EKBTH)
firma = bytes.fromhex(firmaH)

# comprobamos la firma
KpubB = f_asim.cargar_RSAKey_Publica("KpubB.bin")
if f_asim.comprobarRSA_PSS(EKBT,firma,KpubB) :
    print("La firma corresponde a B")
else:
    raise RuntimeError("La firma no corresponde a B")

KBT = f_asim.descifrarRSA_OAEP_BIN(EKBT,keyT)
radioB.cerrar()


#3 Creamos el servidor para A
print("escuchando A...")
radioA = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 5551)
radioA.escuchar()
cifrado = None

while cifrado is None:
    cifrado = radioA.recibir()

print("Mensaje de A recibido")

cifrado.decode("utf-8")
mensajeA = json.loads(cifrado)
nombre, EKATH, firmaH, EcadenaH = mensajeA
print(nombre)
EKAT = bytes.fromhex(EKATH)
firma = bytes.fromhex(firmaH)
Ecadena = bytes.fromhex(EcadenaH)

cadena = f_asim.descifrarRSA_OAEP(Ecadena,keyT)
print(cadena)

# comprobamos la firma
KpubA = f_asim.cargar_RSAKey_Publica("KpubA.bin")

if f_asim.comprobarRSA_PSS(EKAT,firma,KpubA) :
    print("La firma corresponde a A")
else:
    raise RuntimeError("La firma no corresponde a A")

KAT = f_asim.descifrarRSA_OAEP_BIN(EKAT,keyT)


#iniciamos la transmision de la clave KAB

cadena = None
print("Esperando llamada...")

while cadena is None:
    cadena = radioA.recibir()


jMensaje = cadena.decode("utf-8")
mensaje = json.loads(jMensaje)
usu1, usu2 = mensaje

#Comprobamos que son los usuarios esperados

if usu1 != "Alicia" or usu2 != "Bernardo":
    raise RuntimeError("Usuarios mencionados no existen")

print(usu1)
print(usu2)

#Formamos los mensajes y los ciframos

ini_KBT = f_aes.iniciarAES_GCM(KBT)

ini_KAT = f_aes.iniciarAES_GCM(KAT)


dt = datetime.now()
t  = datetime.timestamp(dt)

mensajeB = []
mensajeB.append(t)
mensajeB.append(BKAB.hex())
jB = json.dumps(mensajeB)
eMensajeB = f_aes.cifrarAES_GCM(ini_KBT, jB.encode("utf-8"))
eB1,eB2,eB3 = eMensajeB

mensajeA = []
mensajeA.append(t)
mensajeA.append(BKAB.hex())
mensajeA.append(eB1.hex())
mensajeA.append(eB2.hex())
mensajeA.append(eB3.hex())
jA = json.dumps(mensajeA)

eMensajeA = f_aes.cifrarAES_GCM(ini_KAT,jA.encode("utf-8"))
m1,m2,m3 = eMensajeA
#Se envian los mensajes en tres cachos
radioA.enviar(m1)
radioA.enviar(m2)
radioA.enviar(m3)
print("Mensaje Enviado")
print("Se termino la transmisión")
radioA.cerrar()






"""
EAKAB = f_aes.cifrarAES_GCM(KAB,KAT)
E1, E2 ,E3 = EAKAB

mensajeTA = []
mensajeTA.append(E1.hex())
mensajeTA.append(E2.hex())
mensajeTA.append(E3.hex())
jStr = json.dumps(mensajeTA)

"""




