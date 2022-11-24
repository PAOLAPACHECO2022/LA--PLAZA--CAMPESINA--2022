let express = require("express");
let router = express.Router();
let userSchema = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

router.route("/login").post((req, res, next) => {
  let body = req.body;
  userSchema.findOne({ email: body.email }, (erro, usuarioDB) => {
    if (erro) {
      return next(erro);
    }
    // Verifica que exista un usuario con el mail escrita por el usuario.
    if (!usuarioDB) {
      return res.status(404).json({
        ok: false,
        err: {
          message: "Usuario o contraseña incorrectos",
        },
      });
    }
    // Valida que la contraseña escrita por el usuario, sea la almacenada en la db
    if (!bcrypt.compareSync(body.password, usuarioDB.password)) {
      return res.status(404).json({
        ok: false,
        err: {
          message: "Usuario o contraseña incorrectos",
        },
      });
    }

    // Genera el token de autenticación
    let token = jwt.sign({ id: usuarioDB._id }, "secretkey", {
      expiresIn: "24h",
    });

    res.header("auth-token", token).json({
      ok: true,
      id: usuarioDB._id,
      token,
    });
  });
});

router.route("/register").post((req, res, next) => {
  let {
    foto,
    nombres,
    apellidos,
    cedula,
    nacimiento,
    celular,
    telfijo,
    direccion,
    eps,
    departamento,
    municipio,
    email,
    password,
  } = req.body;

  userSchema.create(
    {
      foto,
      nombres,
      apellidos,
      cedula,
      nacimiento,
      celular,
      telfijo,
      direccion,
      eps,
      departamento,
      municipio,
      email,
      password: bcrypt.hashSync(password, 10),
    },
    (error, data) => {
      if (error) {
        return next(error);
      } else {
        // Genera el token de autenticación
        let token = jwt.sign({ id: data._id }, "secretkey", {
          expiresIn: "24h",
        });
        console.log("token que envia")
        console.log(token)
        res.header("auth-token", token).json({
          ok: true,
          id: data._id,
          token,
        });
      }
    }
  );
});

router.route("/:id").get(verifyToken, (req, res, next) => {
  userSchema.findById(req.params.id, (error, data) => {
    if (error) {
      return next(error);
    } else {
      res.json(data);
    }
  });
});

router.route("/update/:id").put(verifyToken, (req, res, next) => {
  console.log("Desde la ruta")
  console.log(req.id)
  userSchema.findByIdAndUpdate(
    req.params.id,
    { $set: req.body },
    (error, data) => {
      if (error) {
        return next(error);
      } else {
        res.json(data);
        console.log("user updated successfully !");
      }
    }
  );
});


function verifyToken(req, res, next) {
  const token = req.header("auth-token");
  console.log("token que llega")
  console.log(token)
  if (!token) return res.status(401).json({ error: "Acceso denegado" });
  try {
    const verified = jwt.verify(token, "secretkey");
    console.log("Id verificado")
    console.log(verified)
    req.id = verified
    //req.user = verified;
    next(); // continuamos
  } catch (error) {
    res.status(400).json({ error: "token no es válido" });
  }
}

module.exports = router;
