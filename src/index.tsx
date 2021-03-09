import React from 'react';
import {render} from 'react-dom';
import reportWebVitals from './reportWebVitals';
import { Home, CreateDrone, Drones, UpdateDrone, Login } from './components';
import 'bootstrap/dist/css/bootstrap.min.css';
import {Button, Navbar, Nav} from 'react-bootstrap';
import logo from './assets/img/Coding-Drones-Logo.png';
import './styles.css';
import { FirebaseAppProvider, AuthCheck } from 'reactfire';
import 'firebase/auth';
import { firebaseConfig } from './firebaseConfig';

// Imports From React-Router-Dom
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Link
}
from 'react-router-dom';


render(
  <React.StrictMode>
    <FirebaseAppProvider firebaseConfig={firebaseConfig}>
    <Router>
      <Navbar bg="dark" variant="dark">
        <Navbar.Brand>
          <img
            alt="Coding Drone Members"
            src={logo}
            width="30"
            height="30"
            className="d-inline-block align-top"
          />{' '}
          <Link to= "/">Coding Drones Members Area</Link>                {/*This is how you do comments in React */}
        </Navbar.Brand>
        {/*Nav Items to the right */}
        <Nav className="move-nav" activeKey='/'>

          <Nav.Item>
            <Nav.Link>
              <Link to='/'>Home </Link>
            </Nav.Link>
          </Nav.Item>

          {/* Auth Check for Authed User */}
          <AuthCheck fallback = {
            <Nav.Item>
              <Nav.Link>
                <Link to = "/login">Login Here</Link>
              </Nav.Link>
            </Nav.Item>
          }>

          <Nav.Item>
            <Nav.Link>
              <Link to='/drones'>Display Your Drones </Link>
            </Nav.Link>
          </Nav.Item>

          <Nav.Item>
            <Nav.Link>
              <Link to = "/login">Logout</Link>
            </Nav.Link>
          </Nav.Item>

          </AuthCheck>
          {/* End of Auth Check*/}

        </Nav>



      </Navbar>

      <Switch>
        <Route exact path="/">
          <Home title="Coding Drones" age={31}  />
        </Route>
        <Route path="/create">
          <CreateDrone />
        </Route>
        <Route path="/drones">
          <Drones />
        </Route>
        <Route path = '/update'>
          <UpdateDrone />
        </Route>
        <Route path="/login">
          <Login />
        </Route>
      </Switch>

    </Router>
    </FirebaseAppProvider>
  </React.StrictMode>,
  document.getElementById('root')
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
