import f_asim, f_aes, socket_class, json
from Crypto.Hash import SHA256 

cadena = "comprobación"

#1 creamos clave privada y publica y guardamos la publica
keyA = f_asim.crear_RSAKey()
f_asim.guardar_RSAKey_Publica("KpubA.bin",keyA)
keyA.publickey()


#2 creamos clave KAT
KAT = f_aes.crear_AESKey()

#3 inicializar sockets
radio = socket_class.SOCKET_SIMPLE_TCP('127.0.0.1',5551)
radio.conectar()
#4 ciframos la KAT
KpubT = f_asim.cargar_RSAKey_Publica("KpubT.bin")
EKAT = f_asim.cifrarRSA_OAEP_BIN(KAT,KpubT)
Ecadena = f_asim.cifrarRSA_OAEP(cadena,KpubT)

#hacemos la firma de EKAT y la añadimos al json
firma = f_asim.firmarRSA_PSS(EKAT,keyA)

mensaje = []
mensaje.append("Alicia")
mensaje.append(EKAT.hex())
mensaje.append(firma.hex())
mensaje.append(Ecadena.hex())
jStr = json.dumps(mensaje)
#5 enviamos el json a TTP
radio.enviar(jStr.encode("utf-8"))

#Ahora iniciaremos la transmisión para iniciar conversación con B
mensaje = []
mensaje.append("Alicia")
mensaje.append("Bernardo")
jStr = json.dumps(mensaje) 
radio.enviar(jStr.encode("utf-8"))
c1 = radio.recibir()
c2 = radio.recibir()
c3 = radio.recibir()
radio.cerrar()

criptograma = c1,c2,c3
print("Mensaje recibido de TTP")



#Decodificamos el mensaje
descifradoB = f_aes.descifrarAES_GCM(KAT,c3,c1,c2)
descifrado = descifradoB.decode("utf-8")
mensaje = json.loads(descifrado)
t,KABH,EB1,EB2,EB3 = mensaje

#creamos y mandamos mensaje a B
KAB = bytes.fromhex(KABH)
ini_KAB = f_aes.iniciarAES_GCM(KAB)
mensajeAB = []
mensajeAB.append(t)
mensajeAB.append("Alicia")
jAB = json.dumps(mensajeAB)
cifAB  =  f_aes.cifrarAES_GCM(ini_KAB,jAB.encode("utf-8"))
jAB1, jAB2, jAB3 = cifAB


mensajeB = []
mensajeB.append(EB1)
mensajeB.append(EB2)
mensajeB.append(EB3)
mensajeB.append(jAB1.hex())
mensajeB.append(jAB2.hex())
mensajeB.append(jAB3.hex())

jB = json.dumps(mensajeB)

#Iniciamos comunicaciones con B
radioAB = socket_class.SOCKET_SIMPLE_TCP('127.0.0.1',5553)
radioAB.conectar()
print("enviado mensaje de TTP a B")
radioAB.enviar(jB.encode("utf-8"))

#Recibimos desafio respuesta
mensaje = radioAB.recibir()
desafio = json.loads(mensaje.decode("utf-8"))

#Comprobamos el desafio
if t != desafio-1:
    raise RuntimeError("El desafio no ha sido contestado correctamente")

print("Desafio de B correcto mandando DNI")
#Mandamos DNI cifrado con una firma
DNI = '77186201H'
firmaDNI = f_asim.firmarRSA_PSS(DNI.encode("utf-8"),keyA)
iKAB = f_aes.iniciarAES_GCM(KAB)
CDNI   = f_aes.cifrarAES_GCM(iKAB,DNI.encode("utf-8"))
d1,d2,d3 = CDNI

MDNI = []
MDNI.append(d1.hex())
MDNI.append(d2.hex())
MDNI.append(d3.hex())
MDNI.append(firmaDNI.hex())
jD = json.dumps(MDNI)

radioAB.enviar(jD.encode("utf-8"))
print("DNI enviado")

#Recibimos el mensaje de B con los apellidos
mAp = radioAB.recibir()
# y lo desciframos
jAp = mAp.decode("utf-8")
cAp = json.loads(jAp)
ca1H,ca2H,ca3H,firmaH = cAp
ca1,ca2,ca3, firmaA = bytes.fromhex(ca1H),bytes.fromhex(ca2H),bytes.fromhex(ca3H),bytes.fromhex(firmaH)

apellido = f_aes.descifrarAES_GCM(KAB,ca3,ca1,ca2).decode("utf-8")

#Comprobamos la firma
KpubB = f_asim.cargar_RSAKey_Publica("KpubB.bin")
if f_asim.comprobarRSA_PSS(apellido.encode("utf-8"),firmaA,KpubB):
    print("la firma se a auntentificado")
else:
    raise RuntimeError("No se autentifico la firma")
print(apellido)

radioAB.cerrar()



