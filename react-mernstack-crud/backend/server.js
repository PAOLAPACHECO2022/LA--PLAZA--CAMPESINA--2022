
let express = require("express");
let mongoose = require("mongoose");
let cors = require("cors");
let bodyParser = require("body-parser");
const createError = require("http-errors");

const userRoute = require("../backend/routes/user.route");
const pruductRoute = require("../backend/routes/product.route");

mongoose.Promise = global.Promise;
// eslint-disable-next-line no-undef
mongoose.connect('mongodb+srv://laplaza:laplaza2022@cluster0.qpcdev0.mongodb.net/reactdb?retryWrites=true&w=majority', { useNewUrlParser: true, useUnifiedTopology: true }).then(
  () => {
    console.log("Database sucessfully connected!");
  },
  (error) => {
    console.log("Could not connect to database : " + error);
  }
);
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({}));
app.use("/users", userRoute);
app.use("/products", pruductRoute);

// PORT
const port = process.env.PORT || 4000;
const server = app.listen(port, () => {
  console.log("Connected to port " + port);
});

app.use((req, res, next) => {
  next(createError(404));
});

app.use(function (err, req, res, next) {
  console.error(err.message);
  if (!err.statusCode) err.statusCode = 500;
  res.status(err.statusCode).send(err.message);
});

