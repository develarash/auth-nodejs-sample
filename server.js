const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const userRoute = require("./routes/userRoutes");
const errorHandler = require("./middleWare/errorMiddlewware");
const cookieParser = require("cookie-parser");

const app = express();
// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());
// Routes Middlewares
app.use("/api/users", userRoute);

// Routes
app.get("/", (req, res) => {
  res.send("Home Page");
});
const PORT = process.env.PORT || 5000;
// Error Middleware
app.use(errorHandler);
// Connect to DB and start server
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(5000, () => {
      console.log(`server Running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.log("there are an error Arash " + err);
  });
