const mongoose = require("mongoose");
const Schema = mongoose.Schema;
var uniqueValidator = require("mongoose-unique-validator");

let UserSchema = new Schema(
  {
    foto: { type: String },
    nombres: {
      type: String,
      required: [true, "El nombre completo es necesario"],
    },
    apellidos: {
      type: String,
      required: [true, "Los apellidos son necesarios"],
    },
    cedula: {
      type: Number,
      required: [true, "El npumero de cédula es necesario"],
    },
    nacimiento: {
      type: String,
      required: [true, "La fecha de nacimiento es necesaria"],
    },
    celular: {
      type: Number,
      required: [true, "El número de celular es necesario"],
    },
    telfijo: { type: Number },
    direccion: { type: String },
    eps: {
      type: String,
      required: [true, "La eps donde está afiliado es necesaria"],
    },
    departamento: {
      type: String,
      required: [true, "El departamento es necesario"],
    },
    municipio: { type: String, required: [true, "El municipio es necesario"] },
    email: {
      type: String,
      required: [true, "El correo electrónico es necesario"],
    },
    password: { type: String, required: [true, "La contraseña es necesaria"] },
  },
  {
    collection: "users",
  }
);

// elimina la key password del objeto que retorna al momento de crear un usuario
UserSchema.methods.toJSON = function () {
  let user = this;
  let userObject = user.toObject();
  delete userObject.password;
  return userObject;
};

UserSchema.plugin(uniqueValidator, {
  message: "{PATH} debe de ser único",
});

module.exports = mongoose.model("User", UserSchema);
