import React, { Component } from "react";
import { Col, Container, Form, Button } from "react-bootstrap";
import { Redirect } from "react-router";
import axios from "axios";
import { Link } from "react-router-dom";

class LoginForm extends Component {
  constructor(props) {
    super(props);
    this.state = {
      id: "",
      email: "",
      password: "",
      redirect: false,
    };

    this.handleSubmit = this.handleSubmit.bind(this);
  }

  getEmail = (e) => {
    let email = e.target.value;
    this.setState({
      email: email,
    });
  };

  getPassword = (e) => {
    let password = e.target.value;
    this.setState({
      password: password,
    });
  };

  handleSubmit = (e) => {
    const self = this;
    e.preventDefault();
    const userObject = {
      email: self.state.email,
      password: self.state.password,
    };

    axios
      .post("http://localhost:4000/users/login", userObject)
      .then(function (res) {
        if (res.data.ok) {
          self.setState({
            id: res.data.id,
            redirect: true,
          });
          const token = res.data.token;
          window.localStorage.setItem("token", token);
        }
      })
      .catch((error) => alert(error));
  };

  render() {
    const { redirect } = this.state;
    if (redirect) {
      return (
        <Redirect to={{ pathname: "/profile", state: { id: this.state.id } }} />
      );
    }
    return (
      <div class=" my-5 d-flex justify-content-center aline-100  form-wrapper rounded-4" >
      
      <Col md={6} xs="auto" className="align-items-center">
        <Form className="w-100 m-auto my-5 mt-2" onSubmit={this.handleSubmit}>
          <h3 className="text-center text-uppercase font-weight-bold h3 text-dark">
            login
          </h3>
          <Form.Group className="my-3 h5 text-dark">
            <Form.Label>Correo</Form.Label>
            <Form.Control
              onChange={this.getEmail}
              name="email"
              type="email"
              placeholder="&#128273;Ingresa tu correo"
              required
            />
          </Form.Group>
          <Form.Group className="my-3 h5 text-dark">
            <Form.Label>Contraseña</Form.Label>
            <Form.Control
              name="password"
              onChange={this.getPassword}
              type="password"
              placeholder="&#128274;Ingresa tu contraseña"
              required
            />
          </Form.Group>
          <Form.Group className="my-3 h7 text-dark">
            <Form.Check label="Recuerdarme" />
          </Form.Group>
          <Form.Group className="my-3">
            <Button type="submit" className="btn btn-primary btn-block h3">
              <span className="h5 text-white">Ingresar</span>
            </Button>
          </Form.Group>
          <Form.Group className="my-3">
            <Link
              type="button"
              className="btn btn-info w-50 btn-block h4"
              to="/signup"
            >
              <span className="h5 text-white  btn-block w-50 m-auto">Registrarse</span>
            </Link>
            <Link
              className="forgot-password text-right h5 mt-3 float-end"
              to="/signup"
            >
              ¿Olvidaste tu contraseña?
            </Link>
          </Form.Group>
        </Form>
      </Col>
      
        
      </div>
    );
  }
}



class Login extends Component {
  render() {
    return (
      <Container>
        <LoginForm></LoginForm>
      </Container>
    );
  }
}

export default Login;
