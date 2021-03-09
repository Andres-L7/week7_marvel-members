import React from 'react';
import { useForm } from 'react-hook-form';
import { useLocation } from 'react-router-dom';
import { server_calls } from '../../api';
import { Container } from 'react-bootstrap';
import '../../styles.css';

type Inputs = {
    name: string,
    model: string,
    price: number
}

export const UpdateDrone = () => {

    {/* Set up communication of state via the router location */}
    const location:any = useLocation();
    const { register,handleSubmit } = useForm();
    const onSubmit = (data:any) => {
        console.log(data, location)
        server_calls.update(location.state.drone_id,data)
    }

    return (
        <Container>
            <h1>Update Your Drone</h1>
            <form onSubmit = {handleSubmit(onSubmit)}>
                <label htmlFor="name">Drone Name</label>
                <input type="text" name="name" id="name" placeholder="Update Drone Name" ref={ register }/>

                <label htmlFor="model">Drone Model</label>
                <input type="text" name="model" id="model" placeholder="Update Drone Model" ref={ register }/>

                <label htmlFor="price">Drone Price</label>
                <input type="text" name="price" id="price" placeholder="Update Drone Price" ref={ register }/>

                <button type="submit" className="button-styles">Submit </button>
            </form>
        </Container>
    )
}