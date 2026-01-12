import express from "express";
import cors from "cors"
const app = express();

//basic express configurations
app.use(express.json({limit: "16kb"}))
app.use(express.urlencoded({extended: true , limit: "16kb"}))
app.use(express.static("public"))

//cors configurations
app.use(cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET" , "POST" , "PUT" , "PATCH" , "DELETE" , "OPTIONS"],
    allowedHeaders: ["Authorization" , "Content-Type"],
}),
);

// import the routes

import healthCheckRouter from "./routes/healthcheck.routes.js"
app.use("/api/v1/healthcheck" , healthCheckRouter)

app.get("/" , (req, res) => {
res.send("WELCOME!")
});

export default app;