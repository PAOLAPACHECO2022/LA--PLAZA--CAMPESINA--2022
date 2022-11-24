//import "./App.css";
import React from "react";
import Navbar from "react-bootstrap/Navbar";
import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import "bootstrap/dist/css/bootstrap.min.css";
import "./App.css";
import {  CDBBtn, CDBIcon, CDBBox} from 'cdbreact';
import { Form, Button} from "react-bootstrap";
import { Dropdown} from 'react-bootstrap';
import { Link } from "react-router-dom";

import "bootstrap/dist/css/bootstrap.css";



import { BrowserRouter as Router, Switch, Route } from "react-router-dom";


import CreateProduct from "./components/create-product.component";
import EditProduct  from "./components/edit-product.component";
import ProductList from "./components/product-list.component";
//import Home from "./components/home";
//import LoginForm from "./compone/nts/LoginForm.component";
//import SignUp from "./components/login/register/RegisterForm.component";


import "bootstrap/dist/css/bootstrap.css";
import Home from "./components/home";
import Login from "./components/login/LoginForm.component";
import Register from "./components/login/register/RegisterForm.component";
import Profile from "./components/myperfil.component";



function App() {
  return (
    <Router>
    <div className="App">
    <header className="App-header">
            <Navbar bg="black" variant="dark">
            <Container>
    
    <Navbar.Brand>        
    
    <a href="/" className="d-flex align-items-center p-0 text-dark">
      <Link to={"/create-product"} className="nav-link">
          <img
          alt=""
          src="/laplaza.gif"
          width="100"
          height="100"
          className="d-inline-block align-top"
        />{' '}            
          
      </Link>
        <span className="ml-3 h5 font-weight-bold">LA PLAZA CAMPESINA</span>
      </a>
      </Navbar.Brand>

      <Form.Group className="w-50 h7 px-20">

      <Button 
            className="bg-black  mt-2 w-25"
          
            >
             <a href="/home">Home</a>
      </Button>
      <Button 
            className="bg-black  mt-2 w-25 "
           
            >
             <a href="/">Login</a>
      </Button>
      <Button
            className=" mt-2 w-25 bg-black "
        
            >
             <a href="/signup">Register</a>
      </Button>
            
      </Form.Group>
      
                            <Dropdown.Header>
                            <CDBBtn className="mx-3 p-2 rounded-3">
                            <img
          alt=""
          src="https://i.pinimg.com/originals/a8/77/bd/a877bd50186346533f3d389fb59d2ca1.jpg"
          width="30"
          height="30"
          className="bg-warning form-wrapper rounded-4"
        />{' '}
        
        <Dropdown.Item href="/ " className="20">Cerrar sesión</Dropdown.Item>
    </CDBBtn> </Dropdown.Header>
                         
                        

      
    </Container>
            </Navbar>
          </header>
          <Container>
          <Row>
            <Col md={12}>
              <Switch>
                <Route exact path="/" component={Login} />
                <Route path="/signup" component={Register} />
                <Route path="/profile" component={Profile} />
                <Route  // Se dirige a cada una de las rutas y precisa cual es cada una basada en las propiedades(switch) 
                    exact
                    path="/home"
                    component={(props) => < Home {...props} />}
                  />
               <Route  // Se dirige a cada una de las rutas y precisa cual es cada una basada en las propiedades(switch) 
                    exact
                    path="/create-product"
                    component={(props) => <CreateProduct {...props} />}
                  />
                    <Route
                    exact
                    path="/edit-product/:id"
                    component={(props) => <EditProduct {...props} />}
                  />
                  <Route
                    exact
                    path="/product-list"
                    component={(props) => <ProductList {...props} />}
                  />
               
              
              </Switch>
              <br></br>
              <br></br>
            </Col>
          </Row>
          </Container>
  
  
  <footer className="footer bg-black">
    
  <CDBBox display="flex" flex="column" className="mx-auto py-5" style={{ width: '90%' }}>
  <CDBBox display="flex" justifyContent="between" className="flex-wrap">
    <CDBBox>
      <a href="/" className="d-flex align-items-center p-0 text-dark">
      <Link to={"/create-product"} className="nav-link">
          <img
          alt=""
          src="/laplaza.gif"
          width="100"
          height="100"
          className="d-inline-block align-top"
        />{' '}            
          
      </Link>
        <span className="ml-3 h5 font-weight-bold">LA PLAZA CAMPESINA</span>
      </a>
      <p className="my-3" style={{ width: '250px' }}>
        Frutas, Verduras y más...
      </p>
    </CDBBox>
    <CDBBox>
      <p className="h5 mb-4" style={{ fontWeight: '600' }}>
      Contactenos
      </p>
      <CDBBox flex="column" display="flex" style={{ cursor: 'pointer', padding: '0' }}>
      <p>(+57) 3209887626</p>
          <p>laplaza.cm@gmail.com </p>
      </CDBBox>
    </CDBBox>
    <CDBBox>
      <p className="h5 mb-4" style={{ fontWeight: '600' }}>
      Funciones
      </p>
      <CDBBox display="flex" flex="column" style={{ cursor: 'pointer', padding: '0' }}>
      <ul className="list-unstyled">
              <li><a href="/home">Home</a></li>
              <li><a href="/">Login</a></li>
              <li><a href="/signup">register</a></li>
             
          </ul>
      </CDBBox>
    </CDBBox>
    <CDBBox>
      <p className="h5 mb-3" style={{ fontWeight: '600' }}>
        Products
      </p>
      <CDBBox display="flex" flex="column" style={{ cursor: 'pointer', padding: '0' }}>
      <a href="/" className=" text-dark">
    
    <img
          alt=""
          src="https://i.pinimg.com/originals/28/30/84/283084d7c1d7c52ca6a67aa75624817d.jpg" 
          width="50"
          height="50"
          className="bg-warning form-wrapper rounded-4 my-3"
        />
        <span className="ml-4 h7 mb-0 font-weight-black">Frutas y Verduras- Alimentos perecederos</span>
    </a>
    
    </CDBBox>
    <CDBBox display="flex" >
    <a href="/" className="d-flex  p-0 text-dark">
    <img
          alt=""
          src="https://i.pinimg.com/originals/a8/77/bd/a877bd50186346533f3d389fb59d2ca1.jpg"
          width="50"
          height="50"
          className="bg-warning form-wrapper rounded-4"
        />{' '}
        <span className="ml-4 h7 mb-0 font-weight-black"> Alimentos no perecederos- Arroz, Frijol y más...</span>
    </a>
      </CDBBox>
    </CDBBox>
  </CDBBox>
  <CDBBox
    display="flex"
    justifyContent="center"
    style={{ width: '100%' }}
    className="mx-auto mt-4"
  >
    <CDBBtn flat color="dark" className="p-2">
      <CDBIcon fab icon="facebook-f" />
    </CDBBtn>
    <CDBBtn flat color="dark" className="mx-3 p-2">
      <CDBIcon fab icon="twitter" />
    </CDBBtn>
    <CDBBtn flat color="dark" className="p-2">
      <CDBIcon fab icon="instagram" />
    </CDBBtn>
  </CDBBox>
  <small className="text-center mt-5">&copy; Devwares, 2022. All rights reserved.</small>
</CDBBox>

</footer>
</div>
</Router>  

 

  );
}

export default App;





