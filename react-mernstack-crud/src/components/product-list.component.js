import React, { Component } from "react";
import axios from "axios";
import Table from "react-bootstrap/Table";
import ProductTableRow from "./ProductTableRow";
import { Button  
} from "react-bootstrap";

export default class ProductList extends Component {
  constructor(props) {
    super(props);
    this.state = {
    products: [],
    };
  }
// se ejecuta lo que esta adentro , se renderiza
  componentDidMount() {
    axios
      .get("http://localhost:4000/products/")
      .then((res) => {
        this.setState({
        products: res.data,
        });
      })
      .catch((error) => {
        console.log(error);
      });
  }

  DataTable() {
    return this.state.products.map((res, i) => {
      return <ProductTableRow obj={res} key={i} />;
    });
  }

  render() {
    return (   
        <Table striped bordered hover  className="my-5 mt-4">
           
  
 
  
          <thead class="bg-warning form-wrapper rounded-4">
            <tr>
              <th>Nombre</th>
              <th>Descripción</th>
              <th>Precio</th>
              <th>Cantidad</th>
              <th>Opciones</th>
            </tr>
          </thead>
          <tbody>{this.DataTable()}</tbody>

          <Button
    type="button"
    className="btn btn-success h5 align-center my-5 mt-4 w-50 m-auto" 
     href="/create-product"
    >
    Crear nuevo Producto

  </Button>
        </Table>
        
      
    );
  }
}
