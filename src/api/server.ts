const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvd25lciI6ImY3OTgyZTYwZTYzYzk2YTI5OGQzYzE0NzE2Zjc0YTMwNDYxN2FkMDBhZTZjODFmOCIsImFjY2Vzc190aW1lIjoiXCIyMDIxLTAyLTE2IDIxOjE1OjI1LjUyNTM0MlwiIn0.8mdht4N8_3flCcH2KvlxSDyqYPCX6wlk_86gWseqhvs'  // TODO: Add API-Access-Key
const heroku_token ='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvd25lciI6IjEzNzc0YmU2NDA1OGFmMDdiMDQzNjY1MTFkMDFlYjYzMzljZWM1Yjc3NjNlNzZmMSIsImFjY2Vzc190aW1lIjoiXCIyMDIxLTAyLTE4IDE3OjQ4OjQxLjk1MzQ3MlwiIn0.EC3zC-CBZZar8a1cwJ1eDnZLvMpZ4xzJbYZxBCiQrTo'

export const server_calls = {
    get: async () => {
        const response = await fetch(`https://drone-collections-api-al7.herokuapp.com/drones`,{
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': `Bearer ${heroku_token}`
            }
        });

        if(!response.ok){
            throw new Error('Failed to fetch data from server')
        }

        return await response.json()
    },
    delete: async (id:string) => {
        const response = await fetch(`https://drone-collections-api-al7.herokuapp.com/drones/${id}`,{
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': `Bearer ${heroku_token}`
            }
        });

        if(!response.ok){
            throw new Error('Failed to Delete data from server')
        }

        return await response.json()
    },
    update: async (id:string, data:any = {}) => {
        const response = await fetch(`https://drone-collections-api-al7.herokuapp.com/drones/${id}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': `Bearer ${heroku_token}`
            },
            body: JSON.stringify(data)
        });
        if(!response.ok){
            throw new Error('Failed to update data from server')
        }

        return await response.json()
    },
    create: async (data:any = {}) => {
        const response = await fetch(`https://drone-collections-api-al7.herokuapp.com/drones`,{
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': `Bearer ${heroku_token}`
            },
            body: JSON.stringify(data)
        });
        if (!response.ok){
            throw new Error('Failed to Create new data on server')
        }

        return await response.json()
    }
}

/*
data = 
{
    name: 'DJI MAVIC 20',
    model: 'DJI Mavic 20 2021,
    price: 2000 
}

JSON.stringify(data) == {
    "name": "DJI Mavic 20",
    "model": "DJI Mavic 20 2021",
    "price": 2000
}

*/