const { createCipheriv, createECDH } = require("crypto");
const args = require("yargs").argv;
const fs = require("fs");

if (!args.public || !args.private || !args.data) {
    console.log("Faltan argumentos");
    exit(0)
}

const origen= createECDH("secp521r1")

// Leer y establecer clave privada
const key = fs.readFileSync("./data/" + args.private + ".key").toString()
origen.setPrivateKey(key, "hex")

// Leer clave pública
const pub = fs.readFileSync("./data/" + args.public + ".pb").toString()

// Obtener clave secreta compartida con la que encriptar el fichero
const secret = Uint8Array.from(origen.computeSecret(pub, "hex", "binary"))

// Cifrado del fichero
const algoritmo = "aes-256-cbc"
var cifrador = createCipheriv(algoritmo, secret.slice(0,32), secret.slice(0,16))

const texto = fs.readFileSync("./data/" + args.data)

let encriptado = cifrador.update(texto, 'utf-8', 'hex')
encriptado += cifrador.final("hex")

console.log(encriptado)

// Guardar fichero encriptado
fs.writeFileSync("./data/" + args.public + "-" + args.data + ".enc", encriptado)