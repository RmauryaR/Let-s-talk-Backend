import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import cors from "cors";
import { Server } from "socket.io";
import http from "http";

import roomHandler from "./socket/roomHandler.js";

import authRoutes from "./routes/auth.js";
import dotenv from "dotenv";
dotenv.config();

const app = express();

app.use(express.json());
app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(cors());

app.use("/auth", authRoutes);

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "https://let-s-talk-frontend-eight.vercel.app",
    methods: ["GET", "POST", "PUT", "DELETE"],
  },
});

io.on("connection", (socket) => {
  console.log("User connected");

  roomHandler(socket);

  socket.on("disconnect", () => {
    console.log("user disconnected");
  });
});
const PORT = 6001;
mongoose
  .connect(
    "mongodb+srv://myAtlasDBUser:Rahul9716@myatlasclusteredu.jcen9dh.mongodb.net/meet-app",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Running @ ${PORT}`);
    });
  })
  .catch((err) => {
    console.log("Error: ", err);
  });
