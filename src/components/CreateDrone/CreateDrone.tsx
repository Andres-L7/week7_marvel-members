import React from 'react';
import { useForm } from 'react-hook-form';
import { server_calls } from '../../api';
import { Jumbotron, Container, Col, Row } from "react-bootstrap";

type Inputs = {
    name: string,
    model: string,
    price: number
}

export const CreateDrone = () => {

    {/* Creating a deconstructed value for useForm Hook */}
    const { register, handleSubmit} = useForm<Inputs>();

    const onSubmit = (data:any) => {
        console.log(data)
        server_calls.create(data)
    }

    return (
        <Container>
            <h1>Create Your New Drone</h1>
            <form onSubmit = {handleSubmit(onSubmit)}>
                <label htmlFor="name">Drone Name</label>
                <input type="text" name="name" id="name" placeholder="Add Drone Name" ref={ register }/>

                <label htmlFor="model">Drone Model</label>
                <input type="text" name="model" id="model" placeholder="Add Drone Model" ref={ register }/>

                <label htmlFor="price">Drone Price</label>
                <input type="text" name="price" id="price" placeholder="Add Drone Price" ref={ register }/>

                <button type="submit" className="button-styles">Submit Drone</button>
            </form>
        </Container>
    )
}