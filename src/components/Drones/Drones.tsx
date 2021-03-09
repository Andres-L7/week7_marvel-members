import React, {useEffect, useState } from 'react';
import { useGetData } from '../../custom-hooks';
import { Jumbotron, Button, Container, Card, Col, Row } from 'react-bootstrap';
import drone from '../../assets/img/drone.svg';

import { useHistory } from 'react-router-dom';
import { server_calls } from '../../api';

export const Drones = () => {

    const history:any = useHistory();

    {/* Creating history route function -- routeChange */}
    const routeChange = (id?:string, path?:string) => {
        history.push({
            pathname: path,
            state: { drone_id: id}
        })
    }

    let { droneData, getData} = useGetData();
    console.log(droneData)

    const handleDeleteDrone = (id:any) => {
        server_calls.delete(id);
        getData()
    }


    return (
        <Container>
            <Row>
                <Col>
                    <Jumbotron>
                        <h1>Hello Drones</h1>
                        <p>Here are your current collection of drones!</p>
                        <Button onClick= { () => routeChange('','create')}>Create New Drone</Button>
                    </Jumbotron>
                </Col>
            </Row>

            {/* Row to display Data*/}
            <Row>
                <Col>
                    <div>
                        {droneData.map( (item:any) => (
                            <div key = {item.id} >
                                <Card style={{ width: '18rem'}} >
                                    <Card.Img variant="top" src={drone} />
                                    <Card.Body>
                                        <Card.Title>
                                            { item.name }
                                        </Card.Title>
                                        <Card.Text>
                                            { item.model }
                                        </Card.Text>
                                        <Card.Text>
                                            { item.price }
                                        </Card.Text>

                                        <Button variant="danger" onClick = { () => handleDeleteDrone(item.id)}>Delete</Button>
                                        <Button variant="primary" onClick = { () => routeChange(item.id, 'update')}>Update</Button>
                                    </Card.Body>
                                </Card>
                            </div>
                        ))}
                    </div>
                </Col>
            </Row>
        </Container>
    )
}