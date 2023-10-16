import f_asim

cadena = "Hola mundo"
candado = f_asim.RSA_OBJECT
candado.create_KeyPair(candado)
#candado.cargar_RSAKey_Publica(candado,"KpubT.pub")
cifrado = candado.cifrar(candado,cadena.encode("utf-8"))
print(cifrado)
limpio = candado.descifrar(candado,cifrado)
print(limpio.decode("utf-8"))
