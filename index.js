import dotenv from "dotenv";

dotenv.config({
    path: "./.env"
})

let myusername = process.env.database;
console.log("value" , myusername);

console.log("eshu");
