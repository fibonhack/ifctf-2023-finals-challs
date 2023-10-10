import { backend } from "./auth";

export async function getProfileProperties() {
    var response = await fetch(backend + "/profile/properties", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        }
    })
    return response
}
export async function getProfileName() {
    var response = await fetch(backend + "/profile/me", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        }
    })
    return response
}

export async function createProperty(key, value) {
    var response = await fetch(backend + "/profile/properties", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        },
        body: JSON.stringify({
            "key": key,
            "value": value
        })
    })
    return response
}

export async function deletePropertyById(id) {
    var response = await fetch(backend + "/profile/properties/"+id, {
        method: "DELETE",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        }
    })
    return response
}

export async function getPosts() {
    var response = await fetch(backend + "/posts", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        }
    })
    return response
}

export async function createPost(content) {
    var response = await fetch(backend + "/posts", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        },
        body: JSON.stringify({
            "content": content,
        })
    })
    return response
}

export async function deleteProfilePost(id) {
    var response = await fetch(backend + "/posts/"+id, {
        method: "DELETE",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + localStorage.getItem("token")
        }
    })
    return response
}