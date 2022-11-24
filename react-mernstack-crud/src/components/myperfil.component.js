
import React, { Component } from "react";
import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';


import {
  Form,
  Col,
  Row,
  Button,
  Image,
  
} from "react-bootstrap";
import { Link } from "react-router-dom";
import axios from "axios";
export default class Search extends Component {
  constructor(props) {
    super(props);
    this.state = {
      id: "",
      disabled: true,
        user: [],
    };
    this.getNombre = this.getNombre.bind(this);
    this.getApellido = this.getApellido.bind(this);
    this.getCedula = this.getCedula.bind(this);
    this.getNacimiento = this.getNacimiento.bind(this);
    this.getCelular = this.getCelular.bind(this);
    this.getTelfijo = this.getTelfijo.bind(this);
    this.getDireccion = this.getDireccion.bind(this);
    this.getEps = this.getEps.bind(this);
    this.getDepartamento = this.getDepartamento.bind(this);
    this.getMunicipio = this.getMunicipio.bind(this);
    this.getEmail = this.getEmail.bind(this);
  }
  getNombre = (e) => {
    let nombres = e.target.value;
    const user = { ...this.state.user };
    user.nombres = nombres;
    this.setState({ user });
  };
  getApellido = (e) => {
    let apellidos = e.target.value;
    const user = { ...this.state.user };
    user.apellidos = apellidos;
    this.setState({ user });
  };
  getCedula = (e) => {
    let cedula = e.target.value;
    const user = { ...this.state.user };
    user.cedula = cedula;
    this.setState({ user });
  };
  getNacimiento = (e) => {
    let nacimiento = e.target.value;
    const user = { ...this.state.user };
    user.nacimiento = nacimiento;
    this.setState({ user });
  };
  getCelular = (e) => {
    let celular = e.target.value;
    const user = { ...this.state.user };
    user.celular = celular;
    this.setState({ user });
  };
  getTelfijo = (e) => {
    let telfijo = e.target.value;
    const user = { ...this.state.user };
    user.telfijo = telfijo;
    this.setState({ user });
  };
  getDireccion = (e) => {
    let direccion = e.target.value;
    const user = { ...this.state.user };
    user.direccion = direccion;
    this.setState({ user });
  };
  getEps = (e) => {
    let eps = e.target.value;
    const user = { ...this.state.user };
    user.eps = eps;
    this.setState({ user });
  };
  getDepartamento = (e) => {
    let departamento = e.target.value;
    const user = { ...this.state.user };
    user.departamento = departamento;
    this.setState({ user });
  };
  getMunicipio = (e) => {
    let municipio = e.target.value;
    const user = { ...this.state.user };
    user.municipio = municipio;
    this.setState({ user });
  };
  getEmail = (e) => {
    let email = e.target.value;
    const user = { ...this.state.user };
    user.email = email;
    this.setState({ user });
  };
  componentDidMount() {
    const self = this;
    const token = window.localStorage.getItem("token");
    console.log("Componen " , token)
    console.log("id actual. ", self.props.location.state.id)
    axios
      .get("http://localhost:4000/users/" + self.props.location.state.id, {
        headers: {
          "Content-Type": "application/json",
          "auth-token": token,
        },
      })
      .then((res) => {
        self.setState({ user: res.data });
      })
      .catch((error) => {
        console.log(error);
      });
  }
  handleGameClik() {
    this.setState({ disabled: !this.state.disabled });
  }
  handleActualizar = (e) => {
    console.log("Prueba")
    const self = this;
    e.preventDefault();
    const  token = window.localStorage.getItem("token");
    console.log(token);
    const config = {
      headers: { "auth-token": `${token}` },
  
    };
    const userObject = {
      foto: self.state.user.foto,
      nombres: self.state.user.nombres,
      apellidos: self.state.user.apellidos,
      cedula: self.state.user.cedula,
      nacimiento: self.state.user.nacimiento,
      celular: self.state.user.celular,
      telfijo: self.state.user.telfijo,
      direccion: self.state.user.direccion,
      eps: self.state.user.eps,
      departamento: self.state.user.departamento,
      municipio: self.state.user.municipio,
      email: self.state.user.email,
    };
    axios
      .put(
        `http://localhost:4000/users/update/` + self.state.user._id,
        userObject,
        config
      )
      .then(function (res) {
        window.location.reload();
      });
  };

  render() {
    return (
      <div class="container my-5 d-flex justify-content-center bg-light form-wrapper rounded-4 " >
        
      <Form
       
        disabled={this.state.disabled ? "disabled" : ""} className="d-flex justify-content-center  bg-light form-wrapper"
      >
        <Col md={12} >
          <Row style={{ display: "flow-root" }} className="mx-5" >
            <fieldset disabled={true ? this.state.disabled : false}>
              <Row className="mt-5">
                <h1 className="text-center text-uppercase font-weight-bold h5 text-dark my-3">
                  MI PERFIL
                </h1>
                <Col md={6}>
                  <Image
                    src={this.state.user.foto}
                    className="text-center text-uppercase border border-dark h-40 w-100"
                  ></Image>
                </Col>
                <Col md={12}>
                  <Form.Group
                    controlId="nombres"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Nombres</Form.Label>
                    <Form.Control
                      placeholder="Ingresa tus nombres"
                      required
                      value={this.state.user.nombres || ""}
                      onChange={this.getNombre}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="apellidos"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Apellidos</Form.Label>
                    <Form.Control
                      placeholder="Ingresa tus apellidos"
                      required
                      value={this.state.user.apellidos || ""}
                      onChange={this.getApellido}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="cedula"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Número de cédula</Form.Label>
                    <Form.Control
                      type="number"
                      min="1"
                      max="9999999999"
                      placeholder="Ingresa tu número de cédula"
                      required
                      value={this.state.user.cedula || ""}
                      onChange={this.getCedula}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="nacimiento"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Fecha de nacimiento</Form.Label>
                    <Form.Control
                      type="date"
                      required
                      value={this.state.user.nacimiento || ""}
                      onChange={this.getNacimiento}
                    />
                  </Form.Group>
                </Col>
              </Row>
              <Row>
                <Col md={12}>
                  <Form.Group
                    controlId="celular"
                    className="my-3 h5 text-dark m-auto"
                  >
                    <Form.Label>Celular</Form.Label>
                    <Form.Control
                      type="number"
                      min="1"
                      max="9999999999"
                      placeholder="Ingresa tu número de teléfono celular"
                      required
                      value={this.state.user.celular || ""}
                      onChange={this.getCelular}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="eps"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>EPS</Form.Label>
                    <Form.Control
                      placeholder="Escribe el nombre de tu EPS"
                      required
                      value={this.state.user.eps || ""}
                      onChange={this.getEps}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="departamento"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Departamento de residencia</Form.Label>
                    <Form.Control
                      placeholder="Ingresa tus departamento de residencia"
                      required
                      value={this.state.user.departamento || ""}
                      onChange={this.getDepartamento}
                    />
                  </Form.Group>
                </Col>
                <Col md={12} >
                  <Form.Group
                    controlId="email"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Email</Form.Label>
                    <Form.Control
                      type="email"
                      placeholder="Ingresa un correo electrónico"
                      required
                      value={this.state.user.email || ""}
                      onChange={this.getEmail}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="direccion"
                    className="my-3  h5 text-dark m-auto"
                  >
                    <Form.Label>Dirección de residencia</Form.Label>
                    <Form.Control
                      placeholder="Ingresa tus dirección de residencia"
                      value={this.state.user.direccion || ""}
                      onChange={this.getDireccion}
                    />
                  </Form.Group>
                  <Form.Group
                    controlId="municipio"
                    className="my-3 h5 text-dark m-auto"
                  >
                    <Form.Label>Municipio de residencia</Form.Label>
                    <Form.Control
                      placeholder="Ingresa tus municipio de residencia"
                      required
                      value={this.state.user.municipio || ""}
                      onChange={this.getMunicipio}
                    />
                  </Form.Group>
                </Col>
              </Row>
            </fieldset>
            <Form.Group className="w-50 float-start">
              <Button
                type="button"
                className="btn btn-success btn-block mt-4 w-100 m-auto"
                onClick={this.handleGameClik.bind(this)}
              >
                <span className="h6 text-white ">Editar datos</span>
              </Button>
            </Form.Group>
            <Form.Group className="w-50 float-end">
              <Button
                type="button"
                className="btn btn-success w-100 btn-block m-auto"
                hidden={true ? this.state.disabled : false}
                onClick={this.handleActualizar.bind(this)}
              >
                <span className="h6 text-white">Actualizar</span>
              </Button>
            </Form.Group>
        
          </Row>
          <Row>
                    
            <Link
              type="button"
              className="w-25 btn btn-secondary text-center mx-5  my-5"
              to="/"
            >
              <span className="h5 text-white">Ingresar</span>
            </Link>
          </Row>
        </Col>
     </Form>
      <div className="Apps d-flex justify-content-center aline-100 bg-light form-wrapper">
        <Col md={12}>
          <Row className="mt-5">
            <h1 className="text-center text-uppercase font-weight-bold h5 text-dark my-3">
              Señor Agricultor Usted puede aqui
            </h1>
            <Button
              type="button"
              className="btn btn-success h3 btn-block mt-4 w-75 m-auto"
              size="lg"
              block="block" 
               href="/create-product"
              >
              Crear Producto
          
            </Button>

            <Button
              type="button"
              className="btn btn-success h5 btn-block mt-4 w-75 m-auto"
              size="lg"
              block="block" 
               href="/product-list"
              >
               Listar Producto
          
            </Button>

          </Row>
          <Accordion className="mt-5 my-5">
      <Accordion.Item eventKey="0">
        <Accordion.Header>FRUTAS</Accordion.Header>
        <Accordion.Body>

        <Card style={{ width: '18rem' }} className="d-flex justify-content-center  aline-100 bg-light w-100">
      <Card.Img variant="top" src="https://www.spanish.cl/learn/fruit-in-spanish-frutas.jpg" />
      <Card.Body>
        <Card.Title>Frutas</Card.Title>
        <Card.Text className="h7">
        
        Presentan un alto contenido de hidratos de carbono, frecuentemente como azúcares mono y
                        disacáridos (glucosa, fructosa y sacarosa) que le confieren dulzor a las frutas. Cuanto más
                        maduras son, mayor concentración de azúcares tienen.
                        Proporcionan un importante aporte vitamínico (vitaminas A, C, B1, B2, B6, ácido fólico) y
                        mineral (potasio, hierro, calcio, magnesio, sílice, zinc, sulfatos, fosfatos, cloruros).
                        Aportan fibra, principalmente celulosa y pectinas.
                        La mayoría tienen un alto contenido de agua que oscila entre un 80 y 95 por ciento.
                        Poseen antioxidantes, flavonoides, terpenos, selenio, compuestos fenólicos y sustancias
                        fitoquímicas.
        
        </Card.Text>
      </Card.Body>
    </Card>
          
       
        </Accordion.Body>
      </Accordion.Item>
      <Accordion.Item eventKey="1">
        <Accordion.Header>VERDURAS</Accordion.Header>
        <Accordion.Body>
        <Card style={{ width: '18rem' }} className="d-flex justify-content-center  aline-100 bg-light w-100 ">
      <Card.Img variant="top" src="https://www.spanish.cl/learn/vegetables-in-spanish-verduras.jpg" />
      <Card.Body>
        <Card.Title>Verduras</Card.Title>
        <Card.Text lassName="h7">
        Las verduras son un tesoro gastronómico muy saludable. Representan un
                        conglomerado de nutrientes: fibra dietética, vitaminas (ácido fólico,
                        provitamina A, vitamina E), minerales y oligoelementos (potasio, magnesio,
                        hierro, calcio…) y aportan una gran variedad de sustancias bioactivas, entre
                        ellas los antioxidantes. La Organización Mundial de la Salud (OMS) da cuenta
                        de que el bajo consumo de frutas y hortalizas tiene una relación directa con
                        más de 2,7 millones de muertes al año en todo el mundo, entre ellas el 30%
                        son cardiopatías isquémicas, el 20% corresponden a cánceres gastrointestinales
                        y el 10% a enfermedades cerebrovasculares. Además, algunas verduras
                        destacan incluso, sobre otras por su particular contenido en determinados nutrientes
                        y sustancias bioactivas, por lo que su ingesta es más recomendable durante determinadas
                        situaciones. Las hay más idóneas en caso de padecer anemia o dolencias musculares; especialmente
                        indicadas para mantener la salud de los ojos e incluso, para la mineralización de los huesos.
        
        </Card.Text>
      </Card.Body>
    </Card>

       
        </Accordion.Body>
      </Accordion.Item>
    </Accordion>
 
</Col>

</div>
  
        
      </div>
    );
  }
}
