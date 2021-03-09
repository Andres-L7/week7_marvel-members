import React from 'react';
import firebase from 'firebase/app';
import { useAuth, AuthCheck } from 'reactfire';
import 'firebase/auth';
import { Jumbotron, Button, Container} from 'react-bootstrap';

export const Login = () => {

    const auth = useAuth();

    const sign_in = async () => {
        await auth.signInWithPopup(new firebase.auth.GoogleAuthProvider());
    };

    const sign_out = async () => {
        await auth.signOut();
    }

    return (
        <Container>
            <Jumbotron>
                <h1>Login/Logout Here</h1>
                <AuthCheck fallback = {
                    <Button onClick = {sign_in}>
                        Sign In
                    </Button>
                }>
                    <Button onClick = {sign_out}> Sign Out</Button>
                </AuthCheck>
            </Jumbotron>
        </Container>
    )


}