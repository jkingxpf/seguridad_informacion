import f_aes, f_asim, socket_class,json

#1 creamos clave privada y publica y guardamos la publica
keyB = f_asim.crear_RSAKey()
f_asim.guardar_RSAKey_Publica("KpubB.bin",keyB)

#2 Clave KBT
KBT = f_aes.crear_AESKey()

#3 Inicializar socket conectar con TTP
radio = socket_class.SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
radio.conectar()
#4 cifrar KBT
kpubT = f_asim.cargar_RSAKey_Publica("KpubT.bin")
EKBT = f_asim.cifrarRSA_OAEP_BIN(KBT,kpubT)
#realizamos la firma
firma = f_asim.firmarRSA_PSS(EKBT,keyB)
#5 mandar mensaje
mensaje = []
mensaje.append("Bernardo")
mensaje.append(EKBT.hex())
mensaje.append(firma.hex())
jStr = json.dumps(mensaje)
radio.enviar(jStr.encode("utf-8"))
radio.cerrar()

#Comunicaciones con A

radioAB = socket_class.SOCKET_SIMPLE_TCP('127.0.0.1',5553)
radioAB.escuchar()
eMAB = radioAB.recibir()
if eMAB is not None:
    print("llego el mensaje de A")

#sacamos la información del mensaje
mensaje = json.loads(eMAB.decode("utf-8"))
E1H,E2H,E3H,AB1,AB2,AB3 = mensaje
E1,E2,E3 = bytes.fromhex(E1H),bytes.fromhex(E2H),bytes.fromhex(E3H)

descifradoE = f_aes.descifrarAES_GCM(KBT,E3,E1,E2)
jB = descifradoE.decode("utf-8")
mensajeDT = json.loads(jB)
tt, KABH    = mensajeDT

KAB    = bytes.fromhex(KABH)
#ahora desciframos los datos de A
dAB1,dAB2,dAB3  = bytes.fromhex(AB1), bytes.fromhex(AB2), bytes.fromhex(AB3)
jAB             = f_aes.descifrarAES_GCM(KAB,dAB3,dAB1,dAB2)
mensaje = json.loads(jAB.decode("utf-8"))
ta, nombre  = mensaje
print(nombre)
#Comprobamos el ta y el tt para aceptar el mensaje
if ta != tt:
    raise RuntimeError("los tiempos no coinciden")
print("los tiempos coinciden")

#enviamos el desafio a A
desafio = tt+1
jDes    = json.dumps(desafio)
radioAB.enviar(jDes.encode("utf-8"))

#Recibimos el DNI
correo = radioAB.recibir()
mensaje = json.loads(correo.decode("utf-8"))
d1H,d2H,d3H,firmaH = mensaje
firma = bytes.fromhex(firmaH)
d1,d2,d3 = bytes.fromhex(d1H),bytes.fromhex(d2H),bytes.fromhex(d3H)

#desciframos el mensaje
DNIB = f_aes.descifrarAES_GCM(KAB,d3,d1,d2)
DNI = DNIB.decode("utf-8")
print(DNI)

#verificar la firma
KpubA = f_asim.cargar_RSAKey_Publica("KpubA.bin")

if f_asim.comprobarRSA_PSS(DNI.encode("utf-8"),firma,KpubA):
    print("Este mensaje no esta modificado y es de Alicia")
else:
    raise RuntimeError("Este mensaje no coincide con la firma")

#Mandamos el apellido a Alicia

apellidos = "Fernández Suárez"
firmaApellido = f_asim.firmarRSA_PSS(apellidos.encode("utf-8"),keyB)
iKAB  = f_aes.iniciarAES_GCM(KAB)
cApellidos = f_aes.cifrarAES_GCM(iKAB,apellidos.encode("utf-8"))
ca1,ca2,ca3 = cApellidos

mA = []
mA.append(ca1.hex())
mA.append(ca2.hex())
mA.append(ca3.hex())
mA.append(firmaApellido.hex())
jAp = json.dumps(mA)

radioAB.enviar(jAp.encode("utf-8"))


radioAB.cerrar()


