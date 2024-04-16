const { createECDH, createDecipheriv } = require("crypto");
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

// Descifrado del fichero
const algoritmo = "aes-256-cbc"
var descifrador = createDecipheriv(algoritmo, secret.slice(0,32), secret.slice(0,16))

const inputFile = "./data/" + args.private + "-" + args.data + ".enc";

// Datos encriptados convertidos en texto
const texto = fs.readFileSync(inputFile).toString()

let desencriptado = descifrador.update(texto, 'hex', 'utf-8')
desencriptado += descifrador.final("utf-8")

console.log(desencriptado)

const outputFile = "./data/" + args.private + "-" + args.data + ".des";
fs.writeFileSync(outputFile, desencriptado)