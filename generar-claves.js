const { createECDH } = require("crypto");
const { exit } = require("process");
const fs = require("fs")
const args = require("yargs").argv;

console.log(args.name);

if (!args.name) {
    console.log("Falta el argumento name");
    exit(0)
}

const parejaClaves = createECDH("secp521r1")
const clavePublica = parejaClaves.generateKeys("hex")
const clavePrivada = parejaClaves.getPrivateKey("hex")

fs.writeFileSync("./data/"+args.name+".pb", clavePublica)
fs.writeFileSync("./data/"+args.name+".key", clavePrivada)