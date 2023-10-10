export const backend = "/api/v1"

export async function login(username, password) {
    var response = await fetch(backend + "/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            "username": username,
            "password": password
        })
    }).then(async (response) => { return await response.json() })

    return response
}

export async function register(username, password) {
    var response = await fetch(backend + "/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            "username": username,
            "password": password
        })
    })
    return response
}