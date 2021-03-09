import React, {useState, useEffect} from 'react';
import { server_calls } from '../api';

export function useGetData() {
    const [droneData, setData] = useState<any>([]);

    async function handleDataFetch(){
        const result = await server_calls.get();
        setData(result)
    }

    // Introducing the useEffect Hook to add our data to state
    useEffect( () => {
        handleDataFetch();
    }, [])

    return {droneData, getData:handleDataFetch}
}